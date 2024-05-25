use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct PhpObjectInjectionOperation;

impl Operation for PhpObjectInjectionOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            &["unserialize"],
            &["$_GET", "$_POST", "$_REQUEST"],
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential PHP Object Injection vulnerability",
                    func_name,
                    args.join(", ")
                )
            },
        )
    }

    fn name(&self) -> &str {
        "PhpObjectInjectionOperation"
    }
}
