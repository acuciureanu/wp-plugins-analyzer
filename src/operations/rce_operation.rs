use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct RemoteCodeExecutionOperation;

impl Operation for RemoteCodeExecutionOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            &[
                "exec",
                "shell_exec",
                "system",
                "passthru",
                "proc_open",
                "eval",
                "call_user_func",
                "call_user_func_array",
            ],
            &["$_GET", "$_POST", "$_REQUEST"],
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential Remote Code Execution vulnerability",
                    func_name,
                    args.join(", ")
                )
            },
        )
    }

    fn name(&self) -> &str {
        "RemoteCodeExecutionOperation"
    }
}
