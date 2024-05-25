use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct LocalFileInclusionOperation;

impl Operation for LocalFileInclusionOperation {
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
                    "include" | "include_once" | "require" | "require_once"
                )
            },
            |arg| arg.contains("$_GET") || arg.contains("$_POST") || arg.contains("urldecode"),
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential LFI vulnerability",
                    func_name,
                    args.join(", ")
                )
            },
        )
    }

    fn name(&self) -> &str {
        "LocalFileInclusionOperation"
    }
}
