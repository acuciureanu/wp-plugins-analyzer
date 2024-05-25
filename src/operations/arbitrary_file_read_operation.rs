use crate::operations::operation::{Operation, OperationResult};
use tree_sitter::Tree;

use super::common::check_for_function_calls;

pub struct ArbitraryFileReadOperation;

impl Operation for ArbitraryFileReadOperation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        check_for_function_calls(
            tree,
            source_code,
            &[
                "file_get_contents",
                "fopen",
                "readfile",
                "fread",
                "file",
                "fgets",
                "fgetcsv",
                "fgetss",
                "curl_exec",
                "WP_Filesystem_Direct::get_contents",
                "WP_Filesystem_Direct::get_contents_array",
            ],
            &[
                "$_GET",
                "$_POST",
                "$_REQUEST",
            ],
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
