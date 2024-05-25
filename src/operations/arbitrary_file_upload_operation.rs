use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

use super::common::check_for_function_calls;

pub struct ArbitraryFileUploadOperation;

impl Operation for ArbitraryFileUploadOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            &[
                "move_uploaded_file",
                "file_put_contents",
                "fwrite",
                "fputs",
                "copy",
                "fputcsv",
                "rename",
                "WP_Filesystem_Direct::put_contents",
                "WP_Filesystem_Direct::move",
                "WP_Filesystem_Direct::copy",
                "ZipArchive::extractTo",
                "PharData::extractTo",
                "unzip_file",
            ],
            &[
                "$_FILES",
                "get_file_params",
            ],
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
