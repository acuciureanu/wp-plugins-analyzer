use super::operation::Operation;

pub struct LocalFileInclusionOperation;

impl Operation for LocalFileInclusionOperation {
    fn name(&self) -> &str {
        "Local File Inclusion Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["include", "include_once", "require", "require_once"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["sanitize_file_name", "wp_validate_path", "realpath"]
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Potential local file inclusion: Function '{}' with user input: {:?}. Ensure strict file path validation.",
                func_name, args
            )
        })
    }
}