use operations::operation::Operation;
use operations::rce_operation::RemoteCodeExecutionOperation;
use operations::sqli_operation::SqlInjectionOperation;
use reqwest::Error;
use serde_json::Value;
use std::borrow::Cow;
use std::io::{Cursor, Read};
use tree_sitter::Parser;
use zip::ZipArchive;

mod operations {
    pub mod operation;
    pub mod rce_operation;
    pub mod sqli_operation;
}

async fn get_plugin_info(url: &str) -> Result<(), Error> {
    let plugins = fetch_plugins(url).await?;
    if plugins.is_empty() {
        eprintln!("No plugins found");
        return Ok(());
    }

    for plugin in plugins {
        process_plugin(&plugin).await?;
    }

    Ok(())
}

async fn fetch_plugins(url: &str) -> Result<Vec<Value>, Error> {
    let response = reqwest::get(url).await?;
    let response_body: Value = response.json().await?;

    if let Some(plugins) = response_body["plugins"].as_array() {
        Ok(plugins.clone())
    } else {
        eprintln!("Invalid response format: expected 'plugins' to be an array");
        Ok(vec![])
    }
}

async fn process_plugin(plugin: &Value) -> Result<(), Error> {
    if let Some(download_link) = plugin["download_link"].as_str() {
        let data = download_plugin(download_link).await?;
        let reader = Cursor::new(data);
        let operations: Vec<Box<dyn Operation>> = vec![
            Box::new(RemoteCodeExecutionOperation),
            Box::new(SqlInjectionOperation),
        ];
        process_archive(reader, &operations)?;
    } else {
        eprintln!("Download link not found for plugin: {:?}", plugin);
    }

    Ok(())
}

async fn download_plugin(download_link: &str) -> Result<Vec<u8>, Error> {
    let data_response = reqwest::get(download_link).await?;
    let data = data_response.bytes().await?;
    println!("Download finished for plugin: {}", download_link);
    Ok(data.to_vec())
}

fn process_archive(
    reader: Cursor<Vec<u8>>,
    operations: &[Box<dyn Operation>],
) -> Result<(), Error> {
    let mut archive = match ZipArchive::new(reader) {
        Ok(archive) => archive,
        Err(e) => {
            eprintln!("Failed to read ZIP archive: {:?}", e);
            return Ok(());
        }
    };

    for i in 0..archive.len() {
        let mut file = match archive.by_index(i) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Failed to access file at index {}: {:?}", i, e);
                continue;
            }
        };

        if file.is_file() && file.name().ends_with(".php") {
            process_file(&mut file, operations)?;
        }
    }

    Ok(())
}

fn process_file(
    file: &mut zip::read::ZipFile,
    operations: &[Box<dyn Operation>],
) -> Result<(), Error> {
    let file_name = file.name().to_string();
    if file_name.ends_with(".php") {
        let mut buffer = Vec::new();
        if let Err(e) = file.read_to_end(&mut buffer) {
            eprintln!("Failed to read PHP file {}: {:?}", file_name, e);
            return Ok(());
        }

        let source_code = String::from_utf8_lossy(&buffer);
        let source_code_bytes: Cow<[u8]> = Cow::Borrowed(source_code.as_bytes());
        let mut parser = initialize_parser();
        let tree = parser.parse(source_code_bytes, None).unwrap();

        for operation in operations {
            let (_, log) = operation.apply(&tree, &source_code);
            for (func_name, args) in &log {
                println!(
                    "File: {} | Operation: {} | Function name: {} | Args: {}",
                    file_name,
                    operation.name(),
                    func_name,
                    args
                );
            }
        }
    }

    Ok(())
}

fn initialize_parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::language_php())
        .expect("Error loading PHP grammar");
    parser
}

#[tokio::main]
async fn main() {
    let stack_size = 16 * 1024 * 1024; // 16 MB
    let builder = std::thread::Builder::new().stack_size(stack_size);
    builder
        .spawn(move || {
            let url = "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins";
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(get_plugin_info(url)).unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}
