use std::collections::HashMap;
use tree_sitter::{Query, QueryCursor, Tree};

use super::operation::OperationResult;

/**
Checks for function calls in the given source code that match the specified query.

This function takes a syntax tree, source code, query string, function check closure,
argument check closure, and log message closure as input. It searches for function calls
in the source code that match the query and satisfy the function check and argument check
conditions. For each matching function call, it adds the function name and arguments to
a HashMap and logs a message using the log message closure.

# Arguments

* `tree` - The syntax tree of the source code.
* `source_code` - The source code as a string.
* `query_str` - The query string used for searching.
* `function_check` - A closure that takes a function name as input and returns a boolean
                     indicating whether the function should be checked.
* `arg_check` - A closure that takes an argument as input and returns a boolean indicating
                whether the argument is considered dangerous.
* `log_message` - A closure that takes a function name and a vector of arguments as input
                  and returns a log message as a string.

# Returns

A tuple containing a HashMap of functions to check and a vector of log messages.
*/
pub fn check_for_function_calls<F, G, H>(
    tree: &Tree,
    source_code: &str,
    query_str: &str,
    function_check: F,
    arg_check: G,
    log_message: H,
) -> OperationResult
where
    F: Fn(&str) -> bool,
    G: Fn(&str) -> bool,
    H: Fn(&str, Vec<String>) -> String,
{
    let mut functions_to_check = HashMap::new();
    let mut log = Vec::new();

    // Represents the query used for searching.
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
                                if arg_check(arg_text) {
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
            if function_check(&function_name) && has_dangerous_input && !arguments.is_empty() {
                functions_to_check.insert(function_name.clone(), arguments.clone());
                log.push((
                    function_name.clone(),
                    log_message(&function_name, arguments),
                ));
            }
        }
    }

    (functions_to_check, log)
}
