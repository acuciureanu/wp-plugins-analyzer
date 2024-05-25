use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

use super::common::check_for_function_calls;

pub struct CsrfToXssOperation;

impl Operation for CsrfToXssOperation {
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
            |func_name| func_name == "isset",
            |arg| {
                arg.contains("$_POST") && !arg.contains("check_admin_referer") && 
                (arg.contains("add_action") || arg.contains("admin_action"))
            },
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential CSRF to Stored XSS vulnerability",
                    func_name,
                    args.join(", ")
                )
            },
        )
    }

    fn name(&self) -> &str {
        "CsrfToXssOperation"
    }
}
