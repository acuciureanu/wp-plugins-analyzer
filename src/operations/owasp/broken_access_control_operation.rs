use crate::operations::operation::{Operation, NonceChecker};
use std::collections::HashMap;
use tree_sitter::Tree;

pub struct OWASPBrokenAccessControlOperation;

impl Operation for OWASPBrokenAccessControlOperation {
    fn name(&self) -> &str {
        "OWASP Broken Access Control Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["add_action", "add_filter", "register_rest_route"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["wp_ajax_nopriv_", "rest_api_init"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["current_user_can", "check_admin_referer", "wp_verify_nonce"]
    }

    fn format_log_message(&self) -> Box<super::super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "High: Potential Broken Access Control vulnerability in '{}' with arguments: {:?}. Implement proper authorization checks with current_user_can() and nonce verification.",
                func_name, args
            )
        })
    }

    fn apply(&self, tree: &Tree, source_code: &str) -> (HashMap<String, Vec<String>>, Vec<(String, String, String)>) {
        // Call the default implementation from the Operation trait
        let params = super::super::operation::FunctionCallParams {
            tree,
            source_code,
            function_names: &self.functions_checks(),
            arg_checks: &self.args_checks(),
            exclusion_arg_checks: &self.exclude_args_checks(),
            log_message: self.format_log_message(),
            check_nonce: self.check_nonce_in_handler(),
            hooks_checks: &self.hooks_checks(),
        };
        
        let (functions, mut log) = super::super::operation::check_for_function_calls(params);
        
        // Additional check for missing capability checks in admin pages
        if source_code.contains("admin_menu") && !source_code.contains("current_user_can") {
            log.push((
                "admin_menu".to_string(),
                "".to_string(),
                "High: Admin page without capability checks detected. Always verify user capabilities with current_user_can() before performing privileged operations.".to_string(),
            ));
        }
        
        (functions, log)
    }
    
    fn hooks_checks(&self) -> Vec<&'static str> { std::vec!["wp_ajax_", "admin_post_"] }
    
    fn check_nonce_in_handler(&self) -> Box<NonceChecker<'_>> {
        Box::new(move |_tree, _source_code, _handler| false)
    }
}