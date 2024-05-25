use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct RemoteCodeExecutionOperation;

impl Operation for RemoteCodeExecutionOperation {
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
                func_name == "exec"
                    || func_name == "shell_exec"
                    || func_name == "system"
                    || func_name == "passthru"
                    || func_name == "proc_open"
                    || func_name == "eval"
                    || func_name == "call_user_func"
                    || func_name == "call_user_func_array"
            },
            |arg| arg.contains("$_GET") || arg.contains("$_POST") || arg.contains("$_REQUEST"),
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
