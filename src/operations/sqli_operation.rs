use crate::operations::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct SqlInjectionOperation;

impl Operation for SqlInjectionOperation {
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
                    "query" | "get_results" | "get_row" | "get_var" | "prepare" | "execute"
                )
            },
            |arg| arg.contains("$_GET") || arg.contains("$_POST") || arg.contains("concat"),
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential SQLi vulnerability",
                    func_name,
                    args.join(", ")
                )
            },
        )
    }

    fn name(&self) -> &str {
        "SqlInjectionOperation"
    }
}
