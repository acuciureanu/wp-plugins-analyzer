use std::collections::HashMap;
use tree_sitter::{Query, QueryCursor, Tree};

pub type OperationResult = (HashMap<String, Vec<String>>, Vec<(String, String)>);

pub trait Operation {
    fn name(&self) -> &str;

    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            &self.functions_checks(),
            &self.args_checks(),
            &self.exclude_args_checks(),
            |func_name, args| self.format_log_message(func_name, args),
            |tree, source_code, handler| self.check_nonce_in_handler(tree, source_code, handler),
        )
    }

    fn functions_checks(&self) -> Vec<&'static str>;
    fn args_checks(&self) -> Vec<&'static str>;

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec![]
    }

    fn format_log_message(&self, func_name: &str, args: Vec<String>) -> String {
        let has_excluded_args = args.iter().any(|arg| {
            self.exclude_args_checks()
                .iter()
                .any(|&check| arg.contains(check))
        });
        if has_excluded_args {
            format!(
                "Function: {} | Arguments: {} | No obvious {} vulnerability detected, but verify if proper security checks are in place.",
                func_name,
                args.join(", "),
                self.name()
            )
        } else {
            format!(
                "Function: {} | Arguments: {} | Potential {} vulnerability: Missing Nonce Verification",
                func_name,
                args.join(", "),
                self.name()
            )
        }
    }

    fn check_nonce_in_handler(&self, tree: &Tree, source_code: &str, handler: &str) -> bool {
        let handler_name = handler.split(',').nth(1).unwrap_or("").trim();
        let query_str = format!(
            r#"
            (function_definition
              name: (name) @function-name (#eq? @function-name "{}")
              body: (compound_statement) @body)
            "#,
            handler_name
        );

        let query = match Query::new(&tree.language(), &query_str) {
            Ok(query) => query,
            Err(e) => {
                eprintln!("Failed to create query: {:?}", e);
                return false;
            }
        };

        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&query, tree.root_node(), source_code.as_bytes());

        for m in matches {
            for capture in m.captures {
                if capture.index as u32 == query.capture_index_for_name("body").unwrap() {
                    let body_node = capture.node;
                    if self.contains_nonce_check(source_code, body_node) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn contains_nonce_check(&self, source_code: &str, body_node: tree_sitter::Node) -> bool {
        let body_text = body_node.utf8_text(source_code.as_bytes()).unwrap_or("");
        self.exclude_args_checks()
            .iter()
            .any(|check| body_text.contains(check))
    }
}

pub fn check_for_function_calls<H, F>(
    tree: &Tree,
    source_code: &str,
    function_names: &[&str],
    arg_checks: &[&str],
    exclusion_arg_checks: &[&str],
    log_message: H,
    check_nonce: F,
) -> OperationResult
where
    H: Fn(&str, Vec<String>) -> String,
    F: Fn(&Tree, &str, &str) -> bool,
{
    let mut functions_to_check = HashMap::new();
    let mut log = Vec::new();

    let query_str = r#"
    (function_call_expression
      function: (name) @function-name
      arguments: (arguments) @arguments
    )
    "#;

    let query = match Query::new(&tree.language(), query_str) {
        Ok(query) => query,
        Err(e) => {
            eprintln!("Failed to create query: {:?}", e);
            return (functions_to_check, log);
        }
    };

    let mut cursor = QueryCursor::new();
    let matches = cursor.matches(&query, tree.root_node(), source_code.as_bytes());

    for m in matches {
        let mut function_name = None;
        let mut arguments = Vec::new();
        let mut has_dangerous_input = false;

        for capture in m.captures {
            let node = capture.node;
            let capture_name = &query.capture_names()[capture.index as usize];

            match *capture_name {
                "function-name" => {
                    function_name = node.utf8_text(source_code.as_bytes()).ok();
                }
                "arguments" => {
                    for i in 0..node.named_child_count() {
                        if let Some(arg) = node.named_child(i) {
                            if let Ok(arg_text) = arg.utf8_text(source_code.as_bytes()) {
                                if arg_checks.iter().any(|&check| arg_text.contains(check)) {
                                    has_dangerous_input = true;
                                }
                                arguments.push(arg_text.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some(function_name) = function_name {
            let function_name = function_name.to_string();
            let contains_exclusion = exclusion_arg_checks
                .iter()
                .any(|&check| source_code.contains(check));
            if function_names.contains(&function_name.as_str())
                && has_dangerous_input
                && !arguments.is_empty()
                && !contains_exclusion
            {
                let handler_function_name = arguments.iter().find(|arg| arg.starts_with("["));
                if let Some(handler) = handler_function_name {
                    if !check_nonce(tree, source_code, handler) {
                        functions_to_check.insert(function_name.clone(), arguments.clone());
                        log.push((
                            function_name.clone(),
                            log_message(&function_name, arguments),
                        ));
                    }
                } else {
                    functions_to_check.insert(function_name.clone(), arguments.clone());
                    log.push((
                        function_name.clone(),
                        log_message(&function_name, arguments),
                    ));
                }
            }
        }
    }

    (functions_to_check, log)
}
