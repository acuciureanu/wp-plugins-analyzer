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

    fn format_log_message(&self, func_name: &str, args: Vec<String>) -> String {
        let has_exclusion_check = args.iter().any(|arg| {
            self.exclude_args_checks()
                .iter()
                .any(|&check| arg.contains(check))
        });

        match has_exclusion_check {
            true => {
                format!(
                    "Function: {} | Arguments: {} | No obvious {} vulnerability detected, but verify if proper security checks are in place.",
                    func_name,
                    args.join(", "),
                    self.name()
                )
            }
            false => {
                format!(
                        "Function: {} | Arguments: {} | Potential {} vulnerability: Missing Nonce Verification",
                        func_name,
                        args.join(", "),
                        self.name()
                    )
            }
        }
    }
}
