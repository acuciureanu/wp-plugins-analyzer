use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct BrokenAccessControlOperation;

impl Operation for BrokenAccessControlOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            &[
                "add_action",
                "update_option",
                "register_rest_route",
            ],
            &[
                "current_user_can",
                "wp_verify_nonce",
                "check_admin_referer",
                "check_ajax_referer",
            ],
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
