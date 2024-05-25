use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;
use super::common::check_for_function_calls;

pub struct CSRFProtectionOperation;

impl Operation for CSRFProtectionOperation {
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
                func_name == "add_action"
            },
            |arg| arg.contains("init") || arg.contains("admin_init") || arg.contains("wp_ajax_"),
            |func_name, args| {
                let mut logs = vec![];
                for arg in &args {
                    if arg.contains("init") || arg.contains("admin_init") || arg.contains("wp_ajax_") {
                        logs.push(format!(
                            "Function: {} | Arguments: {} | Potential CSRF Vulnerability",
                            func_name,
                            args.join(", ")
                        ));
                    }
                }
                logs.join("\n")
            },
        )
    }

    fn name(&self) -> &str {
        "CSRFOperation"
    }
}
