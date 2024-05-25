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
            |func_name| func_name == "wp_update_post" || func_name == "update_option",
            |arg| arg.contains("$_POST") && !arg.contains("wp_nonce_field"),
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
