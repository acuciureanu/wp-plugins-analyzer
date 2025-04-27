use crate::operations::operation::Operation;
use std::collections::HashMap;
use tree_sitter::Tree;

pub struct CryptoFailuresOperation;

impl Operation for CryptoFailuresOperation {
    fn name(&self) -> &str {
        "Cryptographic Failures Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["md5", "sha1", "base64_encode", "base64_decode", "crypt"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["password", "secret", "key", "token", "hash"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["wp_hash_password", "wp_check_password"]
    }

    fn format_log_message(&self) -> Box<super::super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Critical: Potential Cryptographic Failure detected in function '{}' with sensitive data: {:?}. Use WordPress password functions or modern cryptographic algorithms like PBKDF2, bcrypt, or Argon2.",
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
        
        // Additional check for hardcoded credentials
        if source_code.contains("define") && 
           (source_code.contains("DB_PASSWORD") || 
            source_code.contains("AUTH_KEY") || 
            source_code.contains("SECURE_AUTH_KEY")) {
            log.push((
                "define".to_string(),
                "".to_string(),
                "Critical: Hardcoded credentials or keys detected. Store sensitive data in environment variables or use WordPress's wp-config.php with proper file permissions.".to_string(),
            ));
        }
        
        // Check for unencrypted data transmission
        if source_code.contains("http://") && !source_code.contains("https://") {
            log.push((
                "http://".to_string(),
                "".to_string(),
                "Medium: Unencrypted HTTP communication detected. Use HTTPS for all data transmission to prevent eavesdropping.".to_string(),
            ));
        }
        
        (functions, log)
    }
}