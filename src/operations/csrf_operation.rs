use super::operation::Operation;

pub struct CsrfOperation;

impl Operation for CsrfOperation {
    fn name(&self) -> &str {
        "CSRF Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["add_action"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["admin_post_", "wp_ajax_"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["wp_verify_nonce", "check_admin_referer", "check_ajax_referer"]
    }

    fn hooks_checks(&self) -> Vec<&'static str> {
        vec!["admin_post_", "wp_ajax_"]
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            if func_name == "add_action" {
                format!(
                    "Potential CSRF vulnerability: Hook '{}' registered. Ensure proper nonce verification in the callback function.",
                    args[0]
                )
            } else {
                format!(
                    "Potential CSRF vulnerability: Function '{}' called. Ensure proper nonce verification.",
                    func_name
                )
            }
        })
    }
}