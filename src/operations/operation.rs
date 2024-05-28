use tree_sitter::{Language, Parser, Query, QueryCursor, Tree};

// Assuming tree_sitter_php is linked as an external function.
extern "C" {
    fn tree_sitter_php() -> Language;
}

pub trait Operation {
    fn name(&self) -> String;
    fn apply(&self, source_code: &str) -> OperationResult;
    fn description(&self) -> String;
}

pub type OperationResult = Vec<Vulnerability>;

#[derive(Debug)]
pub struct Vulnerability {
    pub description: String,
    pub severity: Severity,
    pub location: Option<String>, // Updated to store location details
}

#[derive(Debug, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

pub fn filter_function_calls(
    calls: &[(String, Vec<String>)],
    filter: &dyn Fn(&str, &[String]) -> bool,
) -> Vec<(String, Vec<String>)> {
    calls
        .iter()
        .filter(|(name, args)| filter(name, args))
        .cloned()
        .collect()
}

pub fn parse_tree(source_code: &str) -> Tree {
    let mut parser = Parser::new();
    let language = unsafe { tree_sitter_php() };
    parser
        .set_language(&language)
        .expect("Error setting language");
    parser
        .parse(source_code, None)
        .expect("Error parsing source code")
}

pub fn parse_function_calls(tree: &Tree, source_code: &str) -> Vec<(String, Vec<String>)> {
    let query_str = r#"
        (function_call_expression
            function: (identifier) @function-name
            arguments: (argument_list) @arguments
        )
    "#;
    let query = Query::new(&tree.language(), query_str).expect("Failed to compile query");
    let mut cursor = QueryCursor::new();
    let mut function_calls = Vec::new();

    for match_ in cursor.matches(&query, tree.root_node(), source_code.as_bytes()) {
        let function_name = match_
            .captures
            .iter()
            .find(|&c| c.node.to_string().as_str() == "function-name")
            .map(|c| {
                c.node
                    .utf8_text(source_code.as_bytes())
                    .unwrap()
                    .to_string()
            })
            .unwrap_or_default();
        let arguments = match_
            .captures
            .iter()
            .filter(|&c| c.node.to_string().as_str() == "arguments")
            .map(|c| {
                c.node
                    .utf8_text(source_code.as_bytes())
                    .unwrap()
                    .to_string()
            })
            .collect::<Vec<String>>();
        function_calls.push((function_name, arguments));
    }

    function_calls
}

pub fn is_access_control_function(name: &str, args: &[String]) -> bool {
    name == "current_user_can" || args.iter().any(|arg| arg.contains("cap_"))
}

pub fn compile_results(calls: &[(String, Vec<String>)], source_code: &str) -> OperationResult {
    calls
        .iter()
        .map(|(name, args)| {
            Vulnerability {
                description: format!(
                    "Potential broken access control in function: {} with args {:?}",
                    name, args
                ),
                severity: Severity::High,
                location: Some(format!("Detail about location in source: {}", source_code)),
            }
        })
        .collect()
}
