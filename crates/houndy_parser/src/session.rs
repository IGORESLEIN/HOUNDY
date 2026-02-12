use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Session {
    pub user: String,
    pub computer: String,
    pub weight: u32, // Confidence score for prediction
}

pub struct SessionPredictor;

impl SessionPredictor {
    pub fn predict_high_traffic_hosts(computers: &[String]) -> Vec<String> {
        // Heuristic: Identify Domain Controllers, Exchange, File Servers
        // Return list of likely targets for NetSessionEnum
        computers.iter()
            .filter(|c| c.contains("DC") || c.contains("FILE"))
            .cloned()
            .collect()
    }
}
