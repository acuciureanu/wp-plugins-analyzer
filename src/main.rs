use api::client::{fetch_all_plugins, load_snapshot, save_snapshot};
use models::plugin::Plugin;
use operations::arbitrary_file_deletion_operation::ArbitraryFileDeletionOperation;
use operations::arbitrary_file_read_operation::ArbitraryFileReadOperation;
use operations::arbitrary_file_upload_operation::ArbitraryFileUploadOperation;
use operations::broken_access_control_operation::BrokenAccessControlOperation;
use operations::csrf_to_xss_operation::CsrfToXssOperation;
use operations::lfi_operation::LocalFileInclusionOperation;
use operations::operation::Operation;
use operations::php_object_injection::PhpObjectInjectionOperation;
use operations::privilege_escalation_operation::PrivilegeEscalationOperation;
use operations::rce_operation::RemoteCodeExecutionOperation;
use operations::sqli_operation::SqlInjectionOperation;
use operations::ssrf_operation::ServerSideRequestForgeryOperation;
use reqwest::Error;
use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;
use tokio::task::spawn_blocking;
use tree_sitter::Parser;
use utils::comparator::compare_snapshots;
use zip::ZipArchive;

mod api {
    pub mod client;
}

mod models {
    pub mod plugin;
}

mod utils {
    pub mod comparator;
}

mod operations {
    pub mod arbitrary_file_deletion_operation;
    pub mod arbitrary_file_read_operation;
    pub mod arbitrary_file_upload_operation;
    pub mod broken_access_control_operation;
    pub mod csrf_to_xss_operation;
    pub mod lfi_operation;
    pub mod operation;
    pub mod php_object_injection;
    pub mod privilege_escalation_operation;
    pub mod rce_operation;
    pub mod sqli_operation;
    pub mod ssrf_operation;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let new_data = fetch_all_plugins().await?;

    if Path::new("snapshot.json").exists() {
        let old_data = load_snapshot()?;
        compare_snapshots(&new_data, &old_data);
    } else {
        println!("No snapshot found. Creating a new one.");
    }

    save_snapshot(&new_data)?;

    for plugin in new_data.plugins {
        process_plugin(&plugin).await?;
    }

    Ok(())
}

async fn process_plugin(plugin: &Plugin) -> Result<(), Error> {
    if let Some(download_link) = &plugin.download_link {
        let data = download_plugin(download_link).await?;
        let reader = Cursor::new(data);
        let operations: Vec<Arc<dyn Operation + Send + Sync>> = vec![
            Arc::new(ArbitraryFileDeletionOperation),
            Arc::new(ArbitraryFileReadOperation),
            Arc::new(ArbitraryFileUploadOperation),
            Arc::new(BrokenAccessControlOperation),
            Arc::new(CsrfToXssOperation),
            Arc::new(LocalFileInclusionOperation),
            Arc::new(PhpObjectInjectionOperation),
            Arc::new(PrivilegeEscalationOperation),
            Arc::new(RemoteCodeExecutionOperation),
            Arc::new(SqlInjectionOperation),
            Arc::new(ServerSideRequestForgeryOperation),
        ];
        process_archive(reader, &operations).await?;
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

async fn process_archive(
    reader: Cursor<Vec<u8>>,
    operations: &[Arc<dyn Operation + Send + Sync>],
) -> Result<(), Error> {
    let mut archive = match ZipArchive::new(reader) {
        Ok(archive) => archive,
        Err(e) => {
            eprintln!("Failed to read ZIP archive: {:?}", e);
            return Ok(());
        }
    };

    for i in 0..archive.len() {
        let file = match archive.by_index(i) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Failed to access file at index {}: {:?}", i, e);
                continue;
            }
        };

        if file.is_file() && file.name().ends_with(".php") {
            process_file(file, operations).await?;
        }
    }

    Ok(())
}

async fn process_file(
    mut file: zip::read::ZipFile<'_>,
    operations: &[Arc<dyn Operation + Send + Sync>],
) -> Result<(), Error> {
    let file_name = file.name().to_string();
    if file_name.ends_with(".php") {
        let mut buffer = Vec::new();
        if let Err(e) = file.read_to_end(&mut buffer) {
            eprintln!("Failed to read PHP file {}: {:?}", file_name, e);
            return Ok(());
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
                            "File: {} | Operation: {} | {}",
                            file_name, operation_name, log_message
                        );
                        if !log_message.is_empty()
                            && unique_results.insert(formatted_message.clone())
                        {
                            println!("{}", formatted_message);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error occurred while awaiting handle: {:?}", e);
                }
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
