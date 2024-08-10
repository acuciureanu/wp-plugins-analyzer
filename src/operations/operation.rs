use std::collections::HashMap;
use tree_sitter::{Node, Query, QueryCursor, Tree};
use regex::Regex;

/// Result type for an operation, containing a map of functions to check
/// and a log of function details.
pub type OperationResult = (HashMap<String, Vec<String>>, Vec<(String, String, String)>);

/// Type alias for a function that formats log messages.
pub type LogMessageFormatter<'a> = dyn Fn(&str, Vec<String>) -> String + 'a;

/// Type alias for a function that checks nonces in a handler.
type NonceChecker<'a> = dyn Fn(&Tree, &str, &str) -> bool + 'a;

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
            self.format_log_message(),
            self.check_nonce_in_handler(),
        )
    }

    fn functions_checks(&self) -> Vec<&'static str>;
    fn args_checks(&self) -> Vec<&'static str>;

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec![]
    }

    fn format_log_message(&self) -> Box<LogMessageFormatter> {
        Box::new(|func_name, args| format!("Function: {}\nArguments: {:?}", func_name, args))
    }

    fn check_nonce_in_handler(&self) -> Box<NonceChecker> {
        Box::new(move |tree, source_code, handler| {
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
                let body_text = body_node.utf8_text(source_code.as_bytes()).unwrap_or("");
                self.exclude_args_checks().iter().any(|check| body_text.contains(check))
            })
        })
    }
}

/// Executes a query and checks if any node matches a given condition.
fn query_and_check<F>(tree: &Tree, source_code: &str, query_str: &str, check: F) -> bool
where
    F: Fn(Node) -> bool,
{
    let query = Query::new(&tree.language(), query_str);
    if query.is_err() {
        eprintln!("Failed to create query: {:?}", query.err());
        return false;
    }
    let query = query.unwrap();

    let mut cursor = QueryCursor::new();
    cursor
        .matches(&query, tree.root_node(), source_code.as_bytes())
        .any(|m| m.captures.iter().any(|capture| {
            capture.index == query.capture_index_for_name("body").unwrap() && check(capture.node)
        }))
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

    let query = Query::new(&tree.language(), query_str);
    if query.is_err() {
        eprintln!("Failed to create query: {:?}", query.err());
        return (functions_to_check, log);
    }
    let query = query.unwrap();

    let mut cursor = QueryCursor::new();
    let matches = cursor.matches(&query, tree.root_node(), source_code.as_bytes());

    matches.for_each(|m| {
        let (function_name, arguments) = parse_function_call(&query, m, source_code, arg_checks);

        if let Some(function_name) = function_name {
            if function_names.contains(&function_name.as_str())
                && !arguments.is_empty()
                && !contains_exclusion(source_code, exclusion_arg_checks)
            {
                let handler_function_name = arguments.iter().find(|arg| arg.starts_with('['));
                if let Some(handler) = handler_function_name {
                    if !check_nonce(tree, source_code, handler) {
                        add_to_results(
                            &mut functions_to_check,
                            &mut log,
                            function_name,
                            &arguments,
                            handler,
                            &log_message,
                        );
                    }
                } else {
                    add_to_results(
                        &mut functions_to_check,
                        &mut log,
                        function_name,
                        &arguments,
                        "",
                        &log_message,
                    );
                }
            }
        }
    });

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

        match *capture_name {
            "function-name" => {
                function_name = node.utf8_text(source_code.as_bytes()).ok().map(String::from);
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

    (function_name, arguments)
}

/// Checks if any exclusion arguments are present in the source code.
fn contains_exclusion(source_code: &str, exclusion_arg_checks: &[&str]) -> bool {
    exclusion_arg_checks.iter().any(|&check| source_code.contains(check))
}

fn capture_add_actions(tree: &Tree, hooks: &[&str], source_code: &str) -> OperationResult {
    let query_str = r#"
    (function_call_expression
      function: (name) @function-name
      arguments: (arguments) @arguments
      (#eq? @function-name "add_action")
    )
    "#;

    let query = Query::new(&tree.language(), query_str).unwrap();
    let mut cursor = QueryCursor::new();
    let matches = cursor.matches(&query, tree.root_node(), source_code.as_bytes());

    let mut functions_to_check = HashMap::new();
    let mut log = Vec::new();
    let re_hooks = Regex::new(&format!("^({})", hooks.join("|"))).unwrap();

    for m in matches {
        let func_name_node = m.nodes_for_capture_index(0).next().unwrap();
        let args_node = m.nodes_for_capture_index(1).next().unwrap();
        let add_action_text = format!(
            "{} {}",
            func_name_node.utf8_text(source_code.as_bytes()).unwrap(),
            args_node.utf8_text(source_code.as_bytes()).unwrap()
        );

        let argument_nodes: Vec<_> = args_node.named_children(&mut args_node.walk()).collect();
        if argument_nodes.len() < 2 {
            log.push((
                func_name_node.utf8_text(source_code.as_bytes()).unwrap().to_string(),
                args_node.utf8_text(source_code.as_bytes()).unwrap().to_string(),
                String::from("Insufficient arguments")
            ));
            continue;
        }

        let (hook_node, callback_node) = (&argument_nodes[0], &argument_nodes[1]);
        let hook = extract_hook_name(hook_node, source_code.as_bytes(), &re_hooks);
        if hook.is_none() {
            log.push((
                func_name_node.utf8_text(source_code.as_bytes()).unwrap().to_string(),
                args_node.utf8_text(source_code.as_bytes()).unwrap().to_string(),
                String::from("Invalid hook")
            ));
            continue;
        }
        let hook = hook.unwrap();

        if let Some(callback) = extract_callback_name(callback_node, source_code.as_bytes()) {
            functions_to_check.insert(callback, vec![hook, add_action_text]);
        } else {
            log.push((
                func_name_node.utf8_text(source_code.as_bytes()).unwrap().to_string(),
                args_node.utf8_text(source_code.as_bytes()).unwrap().to_string(),
                String::from("Invalid callback")
            ));
        }
    }

    (functions_to_check, log)
}

fn extract_hook_name(node: &Node, source_code: &[u8], re_hooks: &Regex) -> Option<String> {
    match node.kind() {
        "string" | "encapsed_string" => {
            let hook_text = node.utf8_text(source_code).ok()?;
            if re_hooks.is_match(hook_text) {
                Some(hook_text.to_string())
            } else {
                None
            }
        }
        "binary_expression" => {
            let mut be: Node = *node;
            loop {
                let child = be.named_child(0)?;
                if child.kind() != "binary_expression" {
                    be = child;
                    break;
                }
                be = child;
            }
            if be.kind() == "string" || be.kind() == "encapsed_string" {
                let hook_text = be.utf8_text(source_code).ok()?;
                if re_hooks.is_match(hook_text) {
                    Some(hook_text.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}




fn extract_callback_name(node: &Node, source_code: &[u8]) -> Option<String> {
    if node.named_child_count() == 1 {
        let child = node.named_child(0).unwrap();
        if child.kind() == "string" || child.kind() == "encapsed_string" {
            return Some(child.utf8_text(source_code).unwrap().to_string());
        } else if child.kind() == "array_creation_expression" {
            let elements: Vec<_> = child
                .named_children(&mut child.walk())
                .filter(|n| n.kind() == "array_element_initializer")
                .collect();
            if let Some(last) = elements.last() {
                if last.named_child(0).unwrap().kind() == "string"
                    || last.named_child(0).unwrap().kind() == "encapsed_string"
                {
                    let func = last.named_child(0).unwrap().utf8_text(source_code).unwrap();
                    return Some(func.split("::").last().unwrap().to_string());
                }
            }
        }
    }
    None
}
