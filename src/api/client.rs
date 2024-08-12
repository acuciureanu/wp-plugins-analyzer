use crate::models::plugin::{Info, PluginDataResponse};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::{Client, Error as ReqwestError};
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

const API_URL: &str = "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins";
const SNAPSHOT_FILE: &str = "snapshot.json";
const PER_PAGE: u32 = 250;
const MAX_RETRIES: u32 = 5;
const INITIAL_RETRY_DELAY: u64 = 1000; // milliseconds
const MAX_CONCURRENT_REQUESTS: usize = 10;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RATE_LIMIT: Duration = Duration::from_millis(100); // 10 requests per second

#[derive(Debug)]
pub enum FetchError {
    Network(ReqwestError),
    Api(String),
    Deserialize(String),
    Timeout,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Network(e) => write!(f, "Network error: {}", e),
            FetchError::Api(e) => write!(f, "API error: {}", e),
            FetchError::Deserialize(e) => write!(f, "Deserialization error: {}", e),
            FetchError::Timeout => write!(f, "Request timed out"),
        }
    }
}

impl std::error::Error for FetchError {}

async fn fetch_with_retry(
    client: &Client,
    url: &str,
    retries: u32,
) -> Result<PluginDataResponse, FetchError> {
    let mut current_retry = 0;
    let mut delay = INITIAL_RETRY_DELAY;

    loop {
        let start = Instant::now();
        match timeout(REQUEST_TIMEOUT, client.get(url).send()).await {
            Ok(Ok(response)) => {
                let status = response.status();
                if status.is_success() {
                    match response.json::<PluginDataResponse>().await {
                        Ok(data) => return Ok(data),
                        Err(e) => return Err(FetchError::Deserialize(e.to_string())),
                    }
                } else {
                    let error_body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unable to read error body".to_string());
                    return Err(FetchError::Api(format!("HTTP {}: {}", status, error_body)));
                }
            }
            Ok(Err(e)) if current_retry < retries => {
                println!(
                    "{}",
                    &format!("Network error (attempt {}): {:?}", current_retry + 1, e)
                );
                current_retry += 1;
                sleep(Duration::from_millis(delay)).await;
                delay *= 2; // Exponential backoff
            }
            Ok(Err(e)) => return Err(FetchError::Network(e)),
            Err(_) => return Err(FetchError::Timeout),
        }
        println!("Request took {:?}", start.elapsed());
    }
}

async fn fetch_plugin_data(
    client: &Client,
    page: u32,
    semaphore: Arc<Semaphore>,
) -> Result<PluginDataResponse, FetchError> {
    let _permit = semaphore.acquire().await.unwrap();
    let url = format!("{}&page={}&per_page={}", API_URL, page, PER_PAGE);
    let result = fetch_with_retry(client, &url, MAX_RETRIES).await;
    sleep(RATE_LIMIT).await; // Respect rate limit
    result
}

pub async fn fetch_all_plugins() -> Result<PluginDataResponse, FetchError> {
    let client = Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(FetchError::Network)?;

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));

    let first_page_response = fetch_plugin_data(&client, 1, semaphore.clone()).await?;
    let total_pages = first_page_response.info.pages;
    let mut all_plugins = first_page_response.plugins;

    let mut fetches = FuturesUnordered::new();
    for page in 2..=total_pages {
        let client_clone = client.clone();
        let semaphore_clone = semaphore.clone();
        fetches.push(tokio::spawn(async move {
            fetch_plugin_data(&client_clone, page, semaphore_clone).await
        }));
    }

    while let Some(result) = fetches.next().await {
        match result {
            Ok(Ok(response)) => {
                all_plugins.extend(response.plugins);
                println!(
                    "{}",
                    &format!("Successfully fetched page {}", response.info.page)
                );
            }
            Ok(Err(e)) => {
                println!("{}", &format!("Error fetching plugin data: {}", e));
            }
            Err(e) => {
                println!("{}", &format!("Task error: {}", e));
            }
        }
    }

    Ok(PluginDataResponse {
        info: Info {
            page: 1,
            pages: total_pages,
            results: all_plugins.len() as u32,
        },
        plugins: all_plugins,
    })
}

pub fn save_snapshot(snapshot: &PluginDataResponse) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot_json = serde_json::to_string_pretty(snapshot)?;
    fs::write(SNAPSHOT_FILE, snapshot_json)?;
    Ok(())
}

pub fn load_snapshot() -> Result<PluginDataResponse, Box<dyn std::error::Error>> {
    let snapshot_json = fs::read_to_string(SNAPSHOT_FILE)?;
    let snapshot: PluginDataResponse = serde_json::from_str(&snapshot_json)?;
    Ok(snapshot)
}
