use crate::models::plugin::PluginDataResponse;

pub fn compare_snapshots(new_data: &PluginDataResponse, old_data: &PluginDataResponse) {
    let old_plugins: std::collections::HashMap<_, _> = old_data
        .plugins
        .iter()
        .map(|plugin| (plugin.slug.clone(), plugin))
        .collect();

    for plugin in &new_data.plugins {
        match old_plugins.get(&plugin.slug) {
            Some(old_plugin) => {
                if old_plugin.version != plugin.version {
                    println!(
                        "Plugin {} has a new version: {} -> {}",
                        plugin.name, old_plugin.version, plugin.version
                    );
                }
            }
            None => {
                println!("New plugin found: {}", plugin.name);
            }
        }
    }
}
