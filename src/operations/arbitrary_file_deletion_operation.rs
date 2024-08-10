use super::operation::Operation;

pub struct ArbitraryFileDeletionOperation;

impl Operation for ArbitraryFileDeletionOperation {
    fn name(&self) -> &str {
        "Arbitrary File Deletion Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            "unlink",
            "wp_delete_file",
            "wp_delete_file_from_directory",
            "WP_Filesystem_Direct::delete",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST", "$_FILES"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["sanitize_file_name", "wp_verify_nonce", "current_user_can", "wp_validate_file"]
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Potential arbitrary file deletion: Function '{}' with user input: {:?}. Ensure proper file path validation and user permissions are checked.",
                func_name, args
            )
        })
    }
}