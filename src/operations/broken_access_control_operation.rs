use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct BrokenAccessControlOperation;

impl Operation for BrokenAccessControlOperation {
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
                func_name == "add_action"
                    || func_name == "update_option"
                    || func_name == "register_rest_route"
            },
            |arg| {
                arg.contains("current_user_can")
                    || arg.contains("wp_verify_nonce")
                    || arg.contains("check_admin_referer")
                    || arg.contains("check_ajax_referer")
            },
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential Broken Access Control vulnerability",
                    func_name,
                    args.join(", ")
                )
            },
        )
    }

    fn name(&self) -> &str {
        "BrokenAccessControlOperation"
    }
}
