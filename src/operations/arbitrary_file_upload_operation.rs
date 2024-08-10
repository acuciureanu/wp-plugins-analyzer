use super::operation::Operation;

pub struct ArbitraryFileUploadOperation;

impl Operation for ArbitraryFileUploadOperation {
    fn name(&self) -> &str {
        "Arbitrary File Upload Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            "move_uploaded_file",
            "wp_handle_upload",
            "WP_Filesystem_Direct::put_contents",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_FILES"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["wp_verify_nonce", "current_user_can", "wp_check_filetype_and_ext"]
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Potential arbitrary file upload: Function '{}' handling uploaded file: {:?}. Ensure proper file type validation and user permissions.",
                func_name, args
            )
        })
    }
}