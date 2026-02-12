use reqwest::Client;
use anyhow::Result;
use log::info;

pub struct AdwsClient {
    client: Client,
    url: String,
}

impl AdwsClient {
    pub fn new(dc_host: &str) -> Result<Self> {
        let url = format!("https://{}:9389/ActiveDirectoryWebServices/Windows/Resource", dc_host);
        
        // In a real tool, we would handle custom TLS config (ignoring cert errors internally or using pinned)
        let client = Client::builder()
            .danger_accept_invalid_certs(true) 
            .build()?;
            
        Ok(AdwsClient { client, url })
    }

    pub async fn send_soap_request(&self, body: &str) -> Result<String> {
        info!("Sending SOAP request to ADWS...");
        let resp = self.client.post(&self.url)
            .header("Content-Type", "application/soap+xml; charset=utf-8")
            .body(body.to_string())
            .send()
            .await?;
            
        let text = resp.text().await?;
        Ok(text)
    }
}
