use super::operation::Operation;

pub struct ServerSideRequestForgeryOperation;

impl Operation for ServerSideRequestForgeryOperation {
    fn name(&self) -> &str {
        "Server Side Request Forgery Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            "wp_remote_get",
            "wp_remote_post",
            "file_get_contents",
            "fopen",
            "curl_exec",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST"]
    }
}
