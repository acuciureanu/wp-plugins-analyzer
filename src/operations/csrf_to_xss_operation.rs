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

    fn format_log_message(&self, func_name: &str, args: Vec<String>) -> String {
        let has_exclusion_check = args.iter().any(|arg| {
            self.exclude_args_checks()
                .iter()
                .any(|&check| arg.contains(check))
        });

        match has_exclusion_check {
            true => format!(
                "Function: {} | Arguments: {} | No obvious CSRF to Stored XSS vulnerability detected, but verify if proper security checks are in place.",
                func_name,
                args.join(", ")
            ),
            false => format!(
                "Function: {} | Arguments: {} | Potential CSRF to Stored XSS vulnerability: Missing Nonce Verification",
                func_name,
                args.join(", ")
            ),
        }
    }
}
