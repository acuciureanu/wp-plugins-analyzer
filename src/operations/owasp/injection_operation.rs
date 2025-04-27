use crate::operations::operation::Operation;

pub struct InjectionOperation;

impl Operation for InjectionOperation {
    fn name(&self) -> &str {
        "Injection Vulnerability Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            // SQL Injection
            "$wpdb->query", "$wpdb->get_results", "$wpdb->get_row", "$wpdb->get_var",
            // XSS
            "echo", "print", "printf", "wp_die"
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec![
            "esc_sql", "prepare", 
            "esc_html", "esc_attr", "esc_url", "esc_js", "wp_kses", "sanitize_"
        ]
    }

    fn format_log_message(&self) -> Box<super::super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Critical: Potential Injection vulnerability detected in function '{}' with user input: {:?}. Use prepared statements for SQL queries and output escaping functions for user data.",
                func_name, args
            )
        })
    }
}