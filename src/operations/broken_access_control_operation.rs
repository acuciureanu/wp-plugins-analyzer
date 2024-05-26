use super::operation::Operation;

pub struct BrokenAccessControlOperation;

impl Operation for BrokenAccessControlOperation {
    fn name(&self) -> &str {
        "Broken Access Control Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            "add_action",
            "update_option",
            "register_rest_route",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec![
            "current_user_can",
            "wp_verify_nonce",
            "check_admin_referer",
            "check_ajax_referer",
        ]
    }
}
