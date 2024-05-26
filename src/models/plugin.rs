use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginDataResponse {
    pub info: Info,
    pub plugins: Vec<Plugin>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Info {
    pub page: u32,
    pub pages: u32,
    pub results: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Plugin {
    pub name: String,
    pub slug: String,
    pub version: String,
    pub download_link: Option<String>,
}
