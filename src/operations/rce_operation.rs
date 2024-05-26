use super::operation::Operation;

pub struct RemoteCodeExecutionOperation;

impl Operation for RemoteCodeExecutionOperation {
    fn name(&self) -> &str {
        "Remote Code Execution Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            "exec",
            "shell_exec",
            "system",
            "passthru",
            "proc_open",
            "eval",
            "call_user_func",
            "call_user_func_array",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST"]
    }
}
