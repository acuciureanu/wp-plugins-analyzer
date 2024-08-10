use crate::operations::operation::{Operation, LogMessageFormatter};

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
            "wp_insert_post",
            "wp_update_user",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_POST", "$_GET", "$_REQUEST"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec![
            "wp_nonce_field",
            "check_admin_referer",
            "check_ajax_referer",
            "wp_kses",
            "wp_kses_post",
            "esc_html",
            "esc_attr",
        ]
    }

    fn format_log_message(&self) -> Box<LogMessageFormatter> {
        Box::new(move |func_name, args| {
            let has_exclusion_check = args.iter().any(|arg| {
                self.exclude_args_checks()
                    .iter()
                    .any(|&check| arg.contains(check))
            });

            if has_exclusion_check {
                format!(
                    "Function: {} | Arguments: {} | No obvious {} vulnerability detected.",
                    func_name,
                    args.join(", "),
                    self.name()
                )
            } else {
                format!(
                    "Function: {} | Arguments: {} | Potential {} vulnerability: Missing CSRF protection or output escaping",
                    func_name,
                    args.join(", "),
                    self.name()
                )
            }
        })
    }
}