use super::operation::Operation;

pub struct ServerSideRequestForgeryOperation;

impl Operation for ServerSideRequestForgeryOperation {
    fn name(&self) -> &str {
        "Server Side Request Forgery Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["wp_remote_get", "wp_remote_post", "wp_safe_remote_get", "wp_safe_remote_post"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["esc_url_raw", "wp_http_validate_url"]
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Potential SSRF vulnerability: Function '{}' with user input: {:?}. Implement strict URL validation and whitelisting.",
                func_name, args
            )
        })
    }
}