use crate::operations::operation::{Operation, LogMessageFormatter};

pub struct MissingCapabilityCheckOperation;

impl Operation for MissingCapabilityCheckOperation {
    fn name(&self) -> &str {
        "Missing Capability Check Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            "add_action", "add_filter",
            "register_rest_route",
            "add_menu_page", "add_submenu_page",
            "add_management_page", "add_options_page",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["wp_ajax_", "admin_post_", "rest_api_init", "admin_menu"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["current_user_can", "is_super_admin", "map_meta_cap"]
    }

    fn format_log_message(&self) -> Box<LogMessageFormatter> {
        Box::new(move |func_name, args| {
            let has_capability_check = args.iter().any(|arg| {
                self.exclude_args_checks()
                    .iter()
                    .any(|&check| arg.contains(check))
            });

            if has_capability_check {
                format!(
                    "Function: {} | Arguments: {} | No {} vulnerability detected.",
                    func_name,
                    args.join(", "),
                    self.name()
                )
            } else {
                format!(
                    "Function: {} | Arguments: {} | Potential {} vulnerability: Missing capability check",
                    func_name,
                    args.join(", "),
                    self.name()
                )
            }
        })
    }
}