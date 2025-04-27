use wp_plugins_analyzer::api::client::{fetch_all_plugins, load_snapshot, save_snapshot};
use wp_plugins_analyzer::models::plugin::Plugin;
use wp_plugins_analyzer::operations::operation::Operation;
use wp_plugins_analyzer::operations::owasp::{
    InjectionOperation,
    OWASPBrokenAccessControlOperation,
    CryptoFailuresOperation,
    InsecureDesignOperation,
    SecurityMisconfigOperation,
};
use reqwest::Error;
use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;
use tokio::task::spawn_blocking;
use tree_sitter::Parser;
use wp_plugins_analyzer::utils::comparator::compare_snapshots;
use zip::ZipArchive;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 OWASP Top 5 WordPress Plugin Security Analyzer");
    println!("=================================================");
    println!("Analyzing plugins for the following vulnerabilities:");
    println!("1. Injection (SQL Injection, XSS)");
    println!("2. Broken Access Control");
    println!("3. Cryptographic Failures");
    println!("4. Insecure Design");
    println!("5. Security Misconfiguration");
    println!("=================================================\n");

    let new_data = fetch_all_plugins().await?;

    if Path::new("snapshot.json").exists() {
        let old_data = load_snapshot()?;
        compare_snapshots(&new_data, &old_data);
    } else {
        println!("No snapshot found. Creating a new one.");
    }

    save_snapshot(&new_data)?;

    let mut total_plugins = 0;
    let mut plugins_with_vulnerabilities = 0;
    let mut total_vulnerabilities = 0;

    for plugin in new_data.plugins {
        total_plugins += 1;
        let result = process_plugin(&plugin).await;
        match result {
            Ok(vulnerability_count) => {
                if vulnerability_count > 0 {
                    plugins_with_vulnerabilities += 1;
                    total_vulnerabilities += vulnerability_count;
                }
            }
            Err(e) => {
                eprintln!("Error processing plugin {}: {:?}", plugin.name, e);
            }
        }
    }

    println!("\n=================================================");
    println!("Analysis Summary:");
    println!("Total plugins analyzed: {}", total_plugins);
    println!("Plugins with vulnerabilities: {}", plugins_with_vulnerabilities);
    println!("Total vulnerabilities found: {}", total_vulnerabilities);
    println!("=================================================");

    Ok(())
}

async fn process_plugin(plugin: &Plugin) -> Result<usize, Error> {
    let mut vulnerability_count = 0;
    
    if let Some(download_link) = &plugin.download_link {
        println!("Analyzing plugin: {} ({})", plugin.name, plugin.version);
        
        let data = download_plugin(download_link).await?;
        let reader = Cursor::new(data);
        
        // Create OWASP operations
        let operations: Vec<Arc<dyn Operation + Send + Sync>> = vec![
            Arc::new(InjectionOperation),
            Arc::new(OWASPBrokenAccessControlOperation),
            Arc::new(CryptoFailuresOperation),
            Arc::new(InsecureDesignOperation),
            Arc::new(SecurityMisconfigOperation),
        ];
        
        vulnerability_count = process_archive(reader, &operations, &plugin.name).await?;
    } else {
        eprintln!("Download link not found for plugin: {:?}", plugin);
    }

    Ok(vulnerability_count)
}

async fn download_plugin(download_link: &str) -> Result<Vec<u8>, Error> {
    let data_response = reqwest::get(download_link).await?;
    let data = data_response.bytes().await?;
    Ok(data.to_vec())
}

async fn process_archive(
    reader: Cursor<Vec<u8>>,
    operations: &[Arc<dyn Operation + Send + Sync>],
    plugin_name: &str,
) -> Result<usize, Error> {
    let mut archive = match ZipArchive::new(reader) {
        Ok(archive) => archive,
        Err(e) => {
            eprintln!("Failed to read ZIP archive for {}: {:?}", plugin_name, e);
            return Ok(0);
        }
    };

    let mut vulnerability_count = 0;

    for i in 0..archive.len() {
        let file = match archive.by_index(i) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Failed to access file at index {} for {}: {:?}", i, plugin_name, e);
                continue;
            }
        };

        if file.is_file() && file.name().ends_with(".php") {
            let count = process_file(file, operations, plugin_name).await?;
            vulnerability_count += count;
        }
    }

    Ok(vulnerability_count)
}

async fn process_file(
    mut file: zip::read::ZipFile<'_, std::io::Cursor<Vec<u8>>>,
    operations: &[Arc<dyn Operation + Send + Sync>],
    plugin_name: &str,
) -> Result<usize, Error> {
    let file_name = file.name().to_string();
    let mut vulnerability_count = 0;
    
    if file_name.ends_with(".php") {
        let mut buffer = Vec::new();
        if let Err(e) = file.read_to_end(&mut buffer) {
            eprintln!("Failed to read PHP file {} in {}: {:?}", file_name, plugin_name, e);
            return Ok(0);
        }

        let source_code = Arc::new(String::from_utf8_lossy(&buffer).to_string());
        let source_code_bytes: Cow<[u8]> = Cow::Borrowed(source_code.as_bytes());
        let mut parser = initialize_parser();
        let tree = Arc::new(parser.parse(source_code_bytes, None).unwrap());

        let mut handles = vec![];

        for operation in operations {
            let tree_clone = Arc::clone(&tree);
            let source_code_clone = Arc::clone(&source_code);
            let operation = Arc::clone(operation);
            let operation_name = operation.name().to_string();

            let handle = spawn_blocking(move || {
                let (_, log) = operation.apply(&tree_clone, &source_code_clone);
                (operation_name, log)
            });

            handles.push(handle);
        }

        let mut unique_results = HashSet::new();

        for handle in handles {
            match handle.await {
                Ok(result) => {
                    let (operation_name, log) = result;
                    for (_, _, log_message) in log {
                        let formatted_message = format!(
                            "Plugin: {} | File: {} | Operation: {} | {}",
                            plugin_name, file_name, operation_name, log_message
                        );
                        if !log_message.is_empty()
                            && unique_results.insert(formatted_message.clone())
                        {
                            println!("{}", formatted_message);
                            vulnerability_count += 1;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error occurred while awaiting handle: {:?}", e);
                }
            }
        }
    }

    Ok(vulnerability_count)
}

fn initialize_parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::language_php())
        .expect("Error loading PHP grammar");
    parser
}