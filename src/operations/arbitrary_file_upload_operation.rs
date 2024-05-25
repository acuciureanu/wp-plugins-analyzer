use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

use super::common::check_for_function_calls;

pub struct ArbitraryFileUploadOperation;

impl Operation for ArbitraryFileUploadOperation {
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
                func_name == "move_uploaded_file" ||
                func_name == "file_put_contents" ||
                func_name == "fwrite" ||
                func_name == "fputs" ||
                func_name == "copy" ||
                func_name == "fputcsv" ||
                func_name == "rename" ||
                func_name == "WP_Filesystem_Direct::put_contents" ||
                func_name == "WP_Filesystem_Direct::move" ||
                func_name == "WP_Filesystem_Direct::copy" ||
                func_name == "ZipArchive::extractTo" ||
                func_name == "PharData::extractTo" ||
                func_name == "unzip_file"
            },
            |arg| arg.contains("$_FILES") || arg.contains("get_file_params"),
            |func_name, args| {
                format!(
                    "Function: {} | Arguments: {} | Potential Arbitrary File Upload vulnerability",
                    func_name,
                    args.join(", ")
                )
            },
        )
    }

    fn name(&self) -> &str {
        "ArbitraryFileUploadOperation"
    }
}
