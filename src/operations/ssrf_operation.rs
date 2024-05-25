use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct ServerSideRequestForgeryOperation;

impl Operation for ServerSideRequestForgeryOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            &[
                "wp_remote_get",
                "wp_remote_post",
                "file_get_contents",
                "fopen",
                "curl_exec",
            ],
            &["$_GET", "$_POST", "$_REQUEST"],
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
