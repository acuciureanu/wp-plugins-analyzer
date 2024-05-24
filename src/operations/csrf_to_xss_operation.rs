use crate::operations::operation::{Operation, OperationResult};
use std::collections::HashMap;
use tree_sitter::{Query, QueryCursor, Tree};

pub struct CsrfToXssOperation;

impl Operation for CsrfToXssOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_csrf_to_xss(tree, source_code)
    }

    fn name(&self) -> &str {
        "CsrfToXssOperation"
    }
}

fn check_for_csrf_to_xss(tree: &Tree, source_code: &str) -> OperationResult {
    let mut functions_to_check = HashMap::new();
    let mut log = Vec::new();

    let query = match Query::new(
        &tree.language(),
        r#"
        (function_call_expression
          function: (name) @function-name
          arguments: (arguments) @arguments
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
            if arguments.iter().any(|arg| arg.contains("$_POST")) && !arguments.iter().any(|arg| arg.contains("check_admin_referer")) {
                let log_message = format!(
                    "Function: {} | Arguments: {} | Potential CSRF to Stored XSS vulnerability",
                    function_name, arguments.join(", ")
                );
                functions_to_check.insert(function_name.clone(), arguments.clone());
                log.push((function_name.clone(), log_message));
            }
        }
    }

    (functions_to_check, log)
}
