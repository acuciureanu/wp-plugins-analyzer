use crate::operations::operation::Operation;

pub struct MissingCapabilityCheckOperation;

impl Operation for MissingCapabilityCheckOperation {
    fn name(&self) -> &str {
        "Missing Capability Check Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["add_action"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["wp_ajax_", "admin_post_"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["current_user_can"]
    }
}
