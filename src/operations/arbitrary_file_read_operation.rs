use super::operation::Operation;

pub struct ArbitraryFileReadOperation;

impl Operation for ArbitraryFileReadOperation {
    fn name(&self) -> &str {
        "Arbitrary File Read Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec![
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
        ]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec![
            "$_GET",
            "$_POST",
            "$_REQUEST",
        ]
    }
}