use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct SqlInjectionOperation;

impl Operation for SqlInjectionOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            &[
                "query",
                "get_results",
                "get_row",
                "get_var",
                "prepare",
                "execute",
            ],
            &["$_GET", "$_POST", "$_REQUEST"],
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential SQL Injection vulnerability",
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
