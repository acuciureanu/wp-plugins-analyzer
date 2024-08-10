use super::operation::Operation;

pub struct ArbitraryFileReadOperation;

impl Operation for ArbitraryFileReadOperation {
    fn name(&self) -> &str {
        "Arbitrary File Read Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            "file_get_contents",
            "readfile",
            "fopen",
            "WP_Filesystem_Direct::get_contents",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["sanitize_file_name", "wp_verify_nonce", "current_user_can", "wp_validate_file"]
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Potential arbitrary file read: Function '{}' with user input: {:?}. Verify file path validation and user permissions.",
                func_name, args
            )
        })
    }
}