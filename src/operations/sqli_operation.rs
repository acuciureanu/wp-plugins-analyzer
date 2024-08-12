use std::collections::HashMap;
use tree_sitter::{Node, Tree};
use super::operation::{Operation, OperationResult};

pub struct SqlInjectionOperation;

impl SqlInjectionOperation {
    fn check_input_sanitization(&self, tree: &Tree, arg: &str, source_code: &[u8]) -> bool {
        let cursor = tree.root_node().walk();

        while let Some(node) = cursor.node().next_sibling() {
            if let Some(variable_name) = self.extract_assigned_variable(&node, arg, source_code) {
                return self.find_sanitization_call(&tree.root_node(), &variable_name, source_code);
            }
        }

        false
    }

    fn extract_assigned_variable(&self, node: &Node, arg: &str, source_code: &[u8]) -> Option<String> {
        if node.kind() == "assignment" {
            let right_child = node.child_by_field_name("right")?;
            if right_child.utf8_text(source_code).ok()?.contains(arg) {
                return node.child_by_field_name("left")
                    .and_then(|n| n.utf8_text(source_code).ok())
                    .map(String::from);
            }
        }
        None
    }

    fn find_sanitization_call(&self, root_node: &Node, variable_name: &str, source_code: &[u8]) -> bool {
        let cursor = root_node.walk();

        while let Some(node) = cursor.node().next_sibling() {
            if self.is_sanitization_function(&node, variable_name, source_code) {
                return true;
            }
        }

        false
    }

    fn is_sanitization_function(&self, node: &Node, variable_name: &str, source_code: &[u8]) -> bool {
        const SANITIZING_FUNCTIONS: [&str; 7] = [
            "esc_sql", "intval", "absint", "sanitize_text_field",
            "esc_attr", "esc_html", "esc_js",
        ];

        node.utf8_text(source_code)
            .map(|text| SANITIZING_FUNCTIONS.iter().any(|&func| 
                text.contains(func) && text.contains(variable_name)))
            .unwrap_or(false)
    }
}

impl Operation for SqlInjectionOperation {
    fn name(&self) -> &str {
        "SQL Injection Operation"
    }

    fn functions_checks(&self) -> Vec<&'static str> {
        vec!["$wpdb->query", "$wpdb->get_results", "$wpdb->get_row", "$wpdb->get_var"]
    }

    fn args_checks(&self) -> Vec<&'static str> {
        vec!["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES", "$_ENV"]
    }

    fn exclude_args_checks(&self) -> Vec<&'static str> {
        vec!["$wpdb->prepare", "esc_sql", "intval", "absint", 
             "sanitize_text_field", "esc_attr", "esc_html", "esc_js"]
    }

    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult {
        let mut vulnerabilities = Vec::new();
        let source_code_bytes = source_code.as_bytes();
        let log_formatter = self.format_log_message();

        for func in self.functions_checks() {
            for arg in self.args_checks() {
                if source_code.contains(func) && source_code.contains(arg) 
                   && !self.check_input_sanitization(tree, arg, source_code_bytes) {
                    let log_message = log_formatter(func, vec![arg.to_string()]);
                    vulnerabilities.push((func.to_string(), arg.to_string(), log_message));
                }
            }
        }

        (HashMap::new(), vulnerabilities)
    }

    fn format_log_message(&self) -> Box<super::operation::LogMessageFormatter> {
        Box::new(|func_name, args| {
            format!(
                "Potential SQL injection: Function '{}' with user input: {:?}. Use prepared statements or proper escaping.",
                func_name, args
            )
        })
    }
}