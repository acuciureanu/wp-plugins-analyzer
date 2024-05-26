use crate::operations::operation::Operation;

pub struct LocalFileInclusionOperation;

impl Operation for LocalFileInclusionOperation {
    fn name(&self) -> &str {
        "Local File Inclusion Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["include", "include_once", "require", "require_once"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST", "urldecode"]
    }
}
