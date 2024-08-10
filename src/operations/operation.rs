use std::collections::HashMap;
use tree_sitter::{Query, QueryCursor, Tree};

pub type OperationResult = (HashMap<String, Vec<String>>, Vec<(String, String, String)>);
pub type LogMessageFormatter<'a> = dyn Fn(&str, Vec<String>) -> String + 'a;
type NonceChecker<'a> = dyn Fn(&Tree, &str, &str) -> bool + 'a;

pub struct FunctionCallParams<'a, H, F>
where
    H: Fn(&str, Vec<String>) -> String,
    F: Fn(&Tree, &str, &str) -> bool,
{
    pub tree: &'a Tree,
    pub source_code: &'a str,
    pub function_names: &'a [&'a str],
    pub arg_checks: &'a [&'a str],
    pub exclusion_arg_checks: &'a [&'a str],
    pub log_message: H,
    pub check_nonce: F,
    pub hooks_checks: &'a [&'a str],
}

pub trait Operation {
    fn name(&self) -> &str;

    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        let params = FunctionCallParams {
            tree,
            source_code,
            function_names: &self.functions_checks(),
            arg_checks: &self.args_checks(),
            exclusion_arg_checks: &self.exclude_args_checks(),
            log_message: self.format_log_message(),
            check_nonce: self.check_nonce_in_handler(),
            hooks_checks: &self.hooks_checks(),
        };
        check_for_function_calls(params)
    }

    fn functions_checks(&self) -> Vec<&'static str>;
    fn args_checks(&self) -> Vec<&'static str>;
    fn exclude_args_checks(&self) -> Vec<&'static str> { vec![] }
    fn hooks_checks(&self) -> Vec<&'static str> { vec!["wp_ajax_", "admin_post_"] }

    fn format_log_message(&self) -> Box<LogMessageFormatter> {
        Box::new(|func_name, args| format!("Function: {} | Arguments: {:?}", func_name, args))
    }

    fn check_nonce_in_handler(&self) -> Box<NonceChecker> {
        Box::new(move |_tree, _source_code, _handler| false)
    }
}

pub fn check_for_function_calls<H, F>(params: FunctionCallParams<H, F>) -> OperationResult
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

    let query = Query::new(&params.tree.language(), query_str).expect("Failed to create query");

    let mut cursor = QueryCursor::new();
    let matches = cursor.matches(&query, params.tree.root_node(), params.source_code.as_bytes());

    for m in matches {
        let (function_name, arguments) = parse_function_call(&query, m, params.source_code, params.arg_checks);

        if let Some(function_name) = function_name {
            if (params.function_names.contains(&function_name.as_str()) || function_name == "add_action")
                && !arguments.is_empty()
                && !contains_exclusion(&arguments, params.exclusion_arg_checks)
            {
                if function_name == "add_action" && arguments.len() > 1 {
                    let hook = &arguments[0];
                    if params.hooks_checks.iter().any(|&h| hook.contains(h)) {
                        add_to_results(
                            &mut functions_to_check,
                            &mut log,
                            function_name.clone(),
                            &arguments,
                            "",
                            &params.log_message,
                        );
                    }
                } else {
                    let handler_function_name = arguments.iter().find(|arg| arg.starts_with('['));
                    if let Some(handler) = handler_function_name {
                        if !(params.check_nonce)(params.tree, params.source_code, handler) {
                            add_to_results(
                                &mut functions_to_check,
                                &mut log,
                                function_name.clone(),
                                &arguments,
                                handler,
                                &params.log_message,
                            );
                        }
                    } else {
                        add_to_results(
                            &mut functions_to_check,
                            &mut log,
                            function_name.clone(),
                            &arguments,
                            "",
                            &params.log_message,
                        );
                    }
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
    arguments: &[String],
    handler: &str,
    log_message: &H,
) where
    H: Fn(&str, Vec<String>) -> String,
{
    functions_to_check.insert(function_name.clone(), arguments.to_vec());
    log.push((
        function_name.clone(),
        handler.to_string(),
        log_message(&function_name, arguments.to_vec()),
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

        if capture_name == &"function-name" {
            if let Ok(text) = node.utf8_text(source_code.as_bytes()) {
                function_name = Some(text.to_string());
            }
        } else if capture_name == &"arguments" {
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
    }

    (function_name, arguments)
}

/// Checks if any exclusion arguments are present in the arguments list.
fn contains_exclusion(arguments: &[String], exclusion_arg_checks: &[&str]) -> bool {
    exclusion_arg_checks
        .iter()
        .any(|&check| arguments.iter().any(|arg| arg.contains(check)))
}