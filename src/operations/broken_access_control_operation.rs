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
            "check_if_update",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec![
            "wp_verify_nonce",
            "check_admin_referer",
            "check_ajax_referer",
            "sanitize_text_field",
        ]
    }

    fn format_log_message(&self, func_name: &str, args: Vec<String>) -> String {
        let body = args.join(" ");  // Concatenate args to simulate a function body for missing checks

        let missing_checks = vec![
            ("current_user_can", "Permission Check"),
            ("wp_verify_nonce", "Nonce Verification"),
            ("check_admin_referer", "Admin Referer Check"),
            ("check_ajax_referer", "AJAX Referer Check"),
        ];

        let missing_checks: Vec<&str> = missing_checks
            .iter()
            .filter(|(check, _)| !body.contains(check))
            .map(|(_, desc)| *desc)
            .collect();

        if missing_checks.is_empty() {
            format!(
                "Function: {} | Arguments: {} | No obvious {} vulnerability detected, but verify if proper security checks are in place.",
                func_name,
                args.join(", "),
                self.name()
            )
        } else {
            format!(
                "Function: {} | Arguments: {} | Potential {} vulnerability: Missing {}",
                func_name,
                args.join(", "),
                self.name(),
                missing_checks.join(", ")
            )
        }
    }
}
