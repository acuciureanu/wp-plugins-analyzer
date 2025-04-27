use crate::operations::operation::Operation;
use std::collections::HashMap;
use tree_sitter::Tree;

pub struct InsecureDesignOperation;

impl Operation for InsecureDesignOperation {
    fn name(&self) -> &str {
        "Insecure Design Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["file_get_contents", "fopen", "include", "require", "require_once", "include_once"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST", "$_FILES", "upload"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["sanitize_file_name", "wp_handle_upload"]
    }

    fn format_log_message(&self) -> Box<super::super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Medium: Potential Insecure Design issue in function '{}' with arguments: {:?}. Implement proper input validation, file type checking, and use WordPress's built-in file handling functions.",
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
        
        // Check for hardcoded credentials
        if source_code.contains("username") && source_code.contains("password") {
            log.push((
                "credentials".to_string(),
                "".to_string(),
                "High: Potential hardcoded credentials detected. Store credentials securely using WordPress options API or environment variables.".to_string(),
            ));
        }
        
        // Check for direct database queries without wpdb
        if source_code.contains("mysqli_") || source_code.contains("mysql_") {
            log.push((
                "direct_db".to_string(),
                "".to_string(),
                "Medium: Direct database access detected. Use WordPress $wpdb object for database operations to ensure compatibility and security.".to_string(),
            ));
        }
        
        // Check for eval usage
        if source_code.contains("eval(") {
            log.push((
                "eval".to_string(),
                "".to_string(),
                "Critical: Use of eval() detected. Avoid using eval() as it can lead to code injection vulnerabilities.".to_string(),
            ));
        }
        
        (functions, log)
    }
}