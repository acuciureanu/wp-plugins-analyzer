use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

use super::common::check_for_function_calls;

pub struct ArbitraryFileDeletionOperation;

impl Operation for ArbitraryFileDeletionOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            &[
                "unlink",
                "rmdir",
                "wp_delete_file",
                "wp_delete_file_from_directory",
                "WP_Filesystem_Direct::delete",
                "WP_Filesystem_Direct::rmdir",
            ],
            &[
                "$_GET",
                "$_POST",
                "$_REQUEST",
                "json_decode",
            ],
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential Arbitrary File Deletion vulnerability",
                    func_name,
                    args.join(", ")
                )
            },
        )
    }

    fn name(&self) -> &str {
        "ArbitraryFileDeletionOperation"
    }
}
