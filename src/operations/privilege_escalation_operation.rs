use super::operation::Operation;

pub struct PrivilegeEscalationOperation;

impl Operation for PrivilegeEscalationOperation {
    fn name(&self) -> &str {
        "Privilege Escalation Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["current_user_can", "user_can", "wp_get_current_user"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST"]
    }
}
