use std::collections::HashMap;
use tree_sitter::Tree;

pub type OperationResult = (HashMap<String, Vec<String>>, Vec<(String, String)>);

pub trait Operation {
    fn apply(&self, tree: &Tree, source_code: &str) -> OperationResult;
    fn name(&self) -> &str;
}
