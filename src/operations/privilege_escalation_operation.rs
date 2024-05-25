use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct PrivilegeEscalationOperation;

impl Operation for PrivilegeEscalationOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            &["current_user_can", "user_can", "wp_get_current_user"],
            &["$_GET", "$_POST"],
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential Privilege Escalation vulnerability",
                    func_name,
                    args.join(", ")
                )
            },
        )
    }

    fn name(&self) -> &str {
        "PrivilegeEscalationOperation"
    }
}
