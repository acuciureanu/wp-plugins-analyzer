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
                matches!(
                    func_name,
                    "exec"
                        | "shell_exec"
                        | "system"
                        | "passthru"
                        | "proc_open"
                        | "eval"
                        | "call_user_func"
                        | "call_user_func_array"
                        | "create_function"
                )
            },
            |arg| arg.contains("$_GET") || arg.contains("$_POST"),
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential RCE vulnerability",
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
