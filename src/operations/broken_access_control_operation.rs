use super::operation::Operation;

pub struct BrokenAccessControlOperation;

impl Operation for BrokenAccessControlOperation {
    fn name(&self) -> &str {
        "Broken Access Control Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["add_action", "register_rest_route"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["wp_ajax_", "admin_post_", "rest_api_init"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["current_user_can", "wp_verify_nonce", "check_admin_referer", "check_ajax_referer"]
    }

    fn hooks_checks(&self) -> Vec<&'static str> {
        vec!["wp_ajax_", "admin_post_", "rest_api_init"]
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            match func_name {
                "add_action" => format!(
                    "Potential broken access control: Hook '{}' registered. Verify proper capability checks in the callback function.",
                    args[0]
                ),
                "register_rest_route" => "Potential broken access control: REST API route registered. Ensure proper permission_callback is implemented.".to_string(),
                _ => format!(
                    "Potential broken access control: Function '{}' called. Verify proper capability checks.",
                    func_name
                )
            }
        })
    }
}