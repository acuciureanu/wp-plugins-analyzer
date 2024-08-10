use super::operation::Operation;

pub struct SqlInjectionOperation;

impl Operation for SqlInjectionOperation {
    fn name(&self) -> &str {
        "SQL Injection Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["$wpdb->query", "$wpdb->get_results", "$wpdb->get_row", "$wpdb->get_var"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["$wpdb->prepare", "esc_sql", "intval", "absint"]
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Potential SQL injection: Function '{}' with user input: {:?}. Use prepared statements or proper escaping.",
                func_name, args
            )
        })
    }
}