use std::collections::HashMap;
use tree_sitter::{Node, Query, QueryCursor, Tree};

/// Result type for an operation, containing a map of functions to check
/// and a log of function details.
pub type OperationResult = (HashMap<String, Vec<String>>, Vec<(String, String, String)>);

/// Trait representing an operation to be performed on the source code.
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
        format!("Function: {}\nArguments: {:?}", func_name, args)
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

        query_and_check(tree, source_code, &query_str, |body_node| {
            self.contains_nonce_check(source_code, body_node)
        })
    }

    fn contains_nonce_check(&self, source_code: &str, body_node: Node) -> bool {
        let body_text = body_node.utf8_text(source_code.as_bytes()).unwrap_or("");
        self.exclude_args_checks().iter().any(|check| body_text.contains(check))
    }
}

/// Executes a query and checks if any node matches a given condition.
fn query_and_check<F>(tree: &Tree, source_code: &str, query_str: &str, check: F) -> bool
where
    F: Fn(Node) -> bool,
{
    let query = match Query::new(&tree.language(), query_str) {
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
            if capture.index == query.capture_index_for_name("body").unwrap() {
                if check(capture.node) {
                    return true;
                }
            }
        }
    }

    false
}

/// Checks for function calls in the source code and collects relevant information.
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
        let (function_name, arguments) = parse_function_call(&query, m, source_code, arg_checks);

        if let Some(function_name) = function_name {
            if function_names.contains(&function_name.as_str())
                && !arguments.is_empty()
                && !contains_exclusion(source_code, exclusion_arg_checks)
            {
                let handler_function_name = arguments.iter().find(|arg| arg.starts_with("["));
                if let Some(handler) = handler_function_name {
                    if !check_nonce(tree, source_code, handler) {
                        add_to_results(&mut functions_to_check, &mut log, function_name, &arguments, handler, &log_message);
                    }
                } else {
                    add_to_results(&mut functions_to_check, &mut log, function_name, &arguments, "", &log_message);
                }
            }
        }
    }

    (functions_to_check, log)
}

/// Adds function details to the results and log.
fn add_to_results<H>(
    functions_to_check: &mut HashMap<String, Vec<String>>,
    log: &mut Vec<(String, String, String)>,
    function_name: String,
    arguments: &Vec<String>,
    handler: &str,
    log_message: &H,
) where
    H: Fn(&str, Vec<String>) -> String,
{
    functions_to_check.insert(function_name.clone(), arguments.clone());
    log.push((
        function_name.clone(),
        handler.to_string(),
        log_message(&function_name, arguments.clone()),
    ));
}

/// Parses a function call from a query match.
fn parse_function_call(
    query: &Query,
    m: tree_sitter::QueryMatch,
    source_code: &str,
    arg_checks: &[&str],
) -> (Option<String>, Vec<String>) {
    let mut function_name = None;
    let mut arguments = Vec::new();

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
                                arguments.push(arg_text.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    (function_name.map(String::from), arguments)
}

/// Checks if any exclusion arguments are present in the source code.
fn contains_exclusion(source_code: &str, exclusion_arg_checks: &[&str]) -> bool {
    exclusion_arg_checks.iter().any(|&check| source_code.contains(check))
}