use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

use super::common::check_for_function_calls;

pub struct ArbitraryFileDeletionOperation;

impl Operation for ArbitraryFileDeletionOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            r#"
            (function_call_expression
              function: (name) @function-name
              arguments: (arguments) @arguments
            )
            "#,
            |func_name| {
                func_name == "unlink"
                    || func_name == "rmdir"
                    || func_name == "wp_delete_file"
                    || func_name == "wp_delete_file_from_directory"
                    || func_name == "WP_Filesystem_Direct::delete"
                    || func_name == "WP_Filesystem_Direct::rmdir"
            },
            |arg| {
                arg.contains("$_GET")
                    || arg.contains("$_POST")
                    || arg.contains("$_REQUEST")
                    || arg.contains("json_decode")
            },
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
