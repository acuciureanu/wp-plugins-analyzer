use crate::models::plugin::{Info, PluginDataResponse};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Error;
use std::fs;

const API_URL: &str = "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins";
const SNAPSHOT_FILE: &str = "snapshot.json";
const PER_PAGE: u32 = 250;

pub async fn fetch_plugin_data(page: u32) -> Result<PluginDataResponse, Error> {
    let url = format!("{}&page={}&per_page={}", API_URL, page, PER_PAGE);
    let response = reqwest::get(&url).await?;
    let api_response: PluginDataResponse = response.json().await?;
    Ok(api_response)
}

pub async fn fetch_all_plugins() -> Result<PluginDataResponse, Error> {
    let first_page_response = fetch_plugin_data(1).await?;
    let total_pages = first_page_response.info.pages;
    let mut all_plugins = first_page_response.plugins;

    let mut fetches = FuturesUnordered::new();
    for page in 2..=total_pages {
        fetches.push(fetch_plugin_data(page));
    }

    while let Some(result) = fetches.next().await {
        match result {
            Ok(response) => {
                all_plugins.extend(response.plugins);
            }
            Err(e) => {
                eprintln!("Error fetching plugin data: {:?}", e);
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
