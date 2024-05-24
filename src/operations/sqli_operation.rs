use crate::operations::operation::Operation;
use std::collections::HashMap;
use tree_sitter::{Query, QueryCursor, Tree};

use super::operation::OperationResult;

pub struct SqlInjectionOperation;

impl Operation for SqlInjectionOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_sql_injection(tree, source_code)
    }

    fn name(&self) -> &str {
        "SqlInjectionOperation"
    }
}

fn check_sql_injection(tree: &Tree, source_code: &str) -> OperationResult {
    let mut functions_to_check = HashMap::new();
    let mut log = Vec::new();

    let query = match Query::new(
        &tree.language(),
        r#"
        (function_call_expression
          function: (name) @function-name
          arguments: (arguments) @arguments
          (#match? @function-name "(query|get_results|get_row|get_var|prepare|execute)")
        )
        "#,
    ) {
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
                                if is_dangerous_input(arg_text) {
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
            if has_dangerous_input && !arguments.is_empty() {
                functions_to_check.insert(function_name.clone(), arguments.clone());
                log.push((function_name.clone(), arguments.join(", ")));
            } else if !arguments.is_empty() {
                log.push((function_name.clone(), arguments.join(", ")));
            }
        }
    }

    (functions_to_check, log)
}

fn is_dangerous_input(argument: &str) -> bool {
    argument.contains("$_GET")
        || argument.contains("$_POST")
        || argument.contains("$_REQUEST")
        || argument.contains("$_SERVER")
        || argument.contains("$_COOKIE")
        || argument.contains("$_FILES")
        || argument.contains("concat")
        || argument.contains("join")
        || argument.contains("interpolate")
}
