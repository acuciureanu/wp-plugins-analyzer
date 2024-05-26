use crate::operations::operation::Operation;

pub struct ArbitraryFileDeletionOperation;

impl Operation for ArbitraryFileDeletionOperation {
    fn name(&self) -> &str {
        "Arbitrary File Deletion Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
            "unlink",
            "rmdir",
            "wp_delete_file",
            "wp_delete_file_from_directory",
            "WP_Filesystem_Direct::delete",
            "WP_Filesystem_Direct::rmdir",
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST", "json_decode"]
    }
}
