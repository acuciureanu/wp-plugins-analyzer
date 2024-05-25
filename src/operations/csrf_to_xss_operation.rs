use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

use super::common::check_for_function_calls;

pub struct CsrfToXssOperation;

impl Operation for CsrfToXssOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            &["wp_update_post", "update_option", "add_post_meta", "update_post_meta"],
            &["$_POST"],
            |func_name, args| {
                let mut logs = vec![];
                let has_nonce_check = source_code.contains("wp_nonce_field")
                    || source_code.contains("check_admin_referer")
                    || source_code.contains("check_ajax_referer");

                if !has_nonce_check {
                    logs.push(format!(
                        "Function: {} | Arguments: {} | Potential CSRF to Stored XSS vulnerability: Missing Nonce Verification",
                        func_name,
                        args.join(", ")
                    ));
                } else {
                    logs.push(format!(
                        "Function: {} | Arguments: {} | No obvious CSRF to Stored XSS vulnerability detected, but verify if proper security checks are in place.",
                        func_name,
                        args.join(", ")
                    ));
                }

                logs.join("\n")
            },
        )
    }

    fn name(&self) -> &str {
        "CsrfToXssOperation"
    }
}
