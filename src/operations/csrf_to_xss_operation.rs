use crate::operations::operation::Operation;

pub struct CsrfToXssOperation;

impl Operation for CsrfToXssOperation {
    fn name(&self) -> &str {
        "CSRF To XSS Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            "wp_update_post",
            "update_option",
            "add_post_meta",
            "update_post_meta",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_POST"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec![
            "wp_nonce_field",
            "check_admin_referer",
            "check_ajax_referer",
        ]
    }
}
