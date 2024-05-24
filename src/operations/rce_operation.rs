use crate::operations::operation::Operation;
use std::collections::HashMap;
use tree_sitter::{Query, QueryCursor, Tree};

use super::operation::OperationResult;

pub struct RemoteCodeExecutionOperation;

impl Operation for RemoteCodeExecutionOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_rce(tree, source_code)
    }

    fn name(&self) -> &str {
        "RemoteCodeExecutionOperation"
    }
}

fn check_for_rce(tree: &Tree, source_code: &str) -> OperationResult {
    let mut functions_to_check = HashMap::new();
    let mut log = Vec::new();

    let query = match Query::new(
        &tree.language(),
        r#"
        (function_call_expression 
          function: (name) @function-name
          arguments: (arguments) @arguments
          (#match? @function-name "(exec|shell_exec|system|passthru|proc_open|eval|call_user_func|call_user_func_array)")
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
            if !arguments.is_empty() {
                functions_to_check.insert(function_name.clone(), arguments.clone());
                log.push((function_name.clone(), arguments.join(", ")));
            } else {
                log.push((function_name.clone(), "No arguments found".to_string()));
            }
        }
    }

    (functions_to_check, log)
}
