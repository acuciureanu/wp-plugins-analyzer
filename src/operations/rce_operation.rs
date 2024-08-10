use super::operation::Operation;

pub struct RemoteCodeExecutionOperation;

impl Operation for RemoteCodeExecutionOperation {
    fn name(&self) -> &str {
        "Remote Code Execution Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["eval", "create_function", "assert", "system", "exec", "shell_exec", "passthru", "popen"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["sanitize_text_field", "escapeshellarg", "escapeshellcmd"]
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Critical: Potential remote code execution: Function '{}' with user input: {:?}. Avoid using these functions with user input.",
                func_name, args
            )
        })
    }
}