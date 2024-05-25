use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct PrivilegeEscalationOperation;

impl Operation for PrivilegeEscalationOperation {
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
                func_name == "current_user_can"
                    || func_name == "user_can"
                    || func_name == "wp_get_current_user"
            },
            |arg| arg.contains("$_GET") || arg.contains("$_POST"),
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
