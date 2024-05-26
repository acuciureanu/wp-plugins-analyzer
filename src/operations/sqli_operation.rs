use super::operation::Operation;

pub struct SqlInjectionOperation;

impl Operation for SqlInjectionOperation {
    fn name(&self) -> &str {
        "SQL Injection Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            "query",
            "get_results",
            "get_row",
            "get_var",
            "prepare",
            "execute",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST"]
    }
}
