use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct ServerSideRequestForgeryOperation;

impl Operation for ServerSideRequestForgeryOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            r#"
            (function_call_expression
              function: (name) @function-name
              arguments: (arguments) @arguments
            )
            "#,
            |func_name| {
                func_name == "wp_remote_get"
                    || func_name == "wp_remote_post"
                    || func_name == "file_get_contents"
                    || func_name == "fopen"
                    || func_name == "curl_exec"
            },
            |arg| arg.contains("$_GET") || arg.contains("$_POST") || arg.contains("$_REQUEST"),
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential Server-Side Request Forgery vulnerability",
                    func_name,
                    args.join(", ")
                )
            },
        )
    }

    fn name(&self) -> &str {
        "ServerSideRequestForgeryOperation"
    }
}
