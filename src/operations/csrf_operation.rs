use crate::operations::operation::Operation;

pub struct CsrfOperation;

impl Operation for CsrfOperation {
    fn name(&self) -> &str {
        "CSRF Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["add_action"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["init", "admin_init", "wp_ajax_"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec![
            "wp_verify_nonce",
            "check_admin_referer",
            "check_ajax_referer",
        ]
    }
}
