use crate::operations::operation::Operation;
use std::collections::HashMap;
use tree_sitter::Tree;

pub struct SecurityMisconfigOperation;

impl Operation for SecurityMisconfigOperation {
    fn name(&self) -> &str {
        "Security Misconfiguration Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["ini_set", "error_reporting", "define"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["WP_DEBUG", "display_errors", "error_reporting"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec![]
    }

    fn format_log_message(&self) -> Box<super::super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Low: Potential Security Misconfiguration in function '{}' with arguments: {:?}. Ensure debug settings are disabled in production environments.",
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
        
        // Check for directory listing prevention
        if !source_code.contains("index.php") && !source_code.contains("Options -Indexes") {
            log.push((
                "directory_listing".to_string(),
                "".to_string(),
                "Low: No directory listing prevention detected. Add empty index.php files to all directories or use .htaccess with 'Options -Indexes'.".to_string(),
            ));
        }
        
        // Check for file permissions settings
        if source_code.contains("chmod") {
            log.push((
                "chmod".to_string(),
                "".to_string(),
                "Medium: File permission modification detected. Ensure secure file permissions (0644 for files, 0755 for directories).".to_string(),
            ));
        }
        
        // Check for version information disclosure
        if source_code.contains("wp_get_theme()->get('Version')") || 
           source_code.contains("wp_get_theme()->Version") {
            log.push((
                "version_disclosure".to_string(),
                "".to_string(),
                "Low: Theme version disclosure detected. Consider hiding version information to prevent targeted attacks.".to_string(),
            ));
        }
        
        (functions, log)
    }
}