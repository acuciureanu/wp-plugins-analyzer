use super::operation::Operation;

pub struct PrivilegeEscalationOperation;

impl Operation for PrivilegeEscalationOperation {
    fn name(&self) -> &str {
        "Privilege Escalation Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            "wp_update_user",
            "wp_insert_user",
            "add_role",
            "set_role",
            "add_cap",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["current_user_can", "wp_verify_nonce", "check_admin_referer"]
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Potential privilege escalation: Function '{}' with user input: {:?}. Verify strict capability checks and input validation.",
                func_name, args
            )
        })
    }
}