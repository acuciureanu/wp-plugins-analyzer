use super::operation::{compile_results, filter_function_calls, is_access_control_function, parse_function_calls, parse_tree, Operation, OperationResult};

struct BrokenAccessControlCheck;

impl Operation for BrokenAccessControlCheck {
    fn name(&self) -> String {
        "Broken Access Control Check".to_string()
    }

    fn apply(&self, source_code: &str) -> OperationResult {
        let tree = parse_tree(source_code);
        let function_calls = parse_function_calls(&tree, source_code);
        let filtered_calls = filter_function_calls(&function_calls, &is_access_control_function);
        compile_results(&filtered_calls, source_code)
    }

    fn description(&self) -> String {
        "Identifies potential broken access control vulnerabilities by examining function calls and their arguments in WordPress plugins or themes.".to_string()
    }
}