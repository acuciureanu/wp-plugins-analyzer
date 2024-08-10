use super::operation::Operation;

pub struct PhpObjectInjectionOperation;

impl Operation for PhpObjectInjectionOperation {
    fn name(&self) -> &str {
        "PHP Object Injection Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["unserialize", "maybe_unserialize"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["wp_unslash", "sanitize_text_field"]
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(move |func_name, args| {
            format!(
                "Potential PHP object injection: Function '{}' with user input: {:?}. Use safe deserialization methods.",
                func_name, args
            )
        })
    }
}