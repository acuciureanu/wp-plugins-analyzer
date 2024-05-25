use super::common::check_for_function_calls;
use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

pub struct CsrfOperation;

impl Operation for CsrfOperation {
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
            |func_name| func_name == "add_action",
            |arg| arg.contains("init") || arg.contains("admin_init") || arg.contains("wp_ajax_"),
            |func_name, args| {
                let mut logs = vec![];
                for arg in &args {
                    if arg.contains("init") || arg.contains("admin_init") || arg.contains("wp_ajax_") {
                        if !source_code.contains("wp_verify_nonce")
                            && !source_code.contains("check_admin_referer")
                            && !source_code.contains("check_ajax_referer")
                        {
                            logs.push(format!(
                                "Function: {} | Arguments: {} | Potential CSRF Vulnerability: Missing Nonce Verification",
                                func_name,
                                args.join(", ")
                            ));
                        }
                    }
                }
                if logs.is_empty() {
                    logs.push(format!(
                        "Function: {} | Arguments: {} | No obvious CSRF vulnerability detected, but verify if proper security checks are in place.",
                        func_name,
                        args.join(", ")
                    ));
                }
                logs.join("\n")
            },
        )
    }

    fn name(&self) -> &str {
        "CSRFOperation"
    }
}
