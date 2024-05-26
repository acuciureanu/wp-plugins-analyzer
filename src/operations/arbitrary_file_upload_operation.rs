use crate::operations::operation::Operation;

pub struct ArbitraryFileUploadOperation;

impl Operation for ArbitraryFileUploadOperation {
    fn name(&self) -> &str {
        "Arbitrary File Upload Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
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
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_FILES", "get_file_params"]
    }
}
