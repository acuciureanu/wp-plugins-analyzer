use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

use super::common::check_for_function_calls;

pub struct ArbitraryFileReadOperation;

impl Operation for ArbitraryFileReadOperation {
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
                func_name == "file_get_contents"
                    || func_name == "fopen"
                    || func_name == "readfile"
                    || func_name == "fread"
                    || func_name == "file"
                    || func_name == "fgets"
                    || func_name == "fgetcsv"
                    || func_name == "fgetss"
                    || func_name == "curl_exec"
                    || func_name == "WP_Filesystem_Direct::get_contents"
                    || func_name == "WP_Filesystem_Direct::get_contents_array"
            },
            |arg| arg.contains("$_GET") || arg.contains("$_POST") || arg.contains("$_REQUEST"),
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential Arbitrary File Read vulnerability",
                    func_name,
                    args.join(", ")
                )
            },
        )
    }

    fn name(&self) -> &str {
        "ArbitraryFileReadOperation"
    }
}
