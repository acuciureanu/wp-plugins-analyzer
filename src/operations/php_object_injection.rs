use crate::operations::operation::Operation;

pub struct PhpObjectInjectionOperation;

impl Operation for PhpObjectInjectionOperation {
    fn name(&self) -> &str {
        "Php Object Injection Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["unserialize"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST"]
    }
}
