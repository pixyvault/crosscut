pub(crate) struct ZoneEditor {
    domain: String,
    zone_name: String,
    zone_id: String,
    cloudflare_dns_api_token: String,
}

impl ZoneEditor {
    pub(crate) fn new(domain: &str, cloudflare_dns_api_token: &str) -> anyhow::Result<Self> {
        let mut response = ureq::get("https://api.cloudflare.com/client/v4/zones/")
            .header(
                "Authorization",
                format!("Bearer {cloudflare_dns_api_token}"),
            )
            .call()?;

        if !response.status().is_success() {
            anyhow::bail!("get /client/v4/zones: {response:?}")
        }

        let zones: serde_json::Value = response.body_mut().read_json()?;

        if !zones["success"].as_bool().expect("'success' to be boolean") {
            anyhow::bail!("in /client/v4/zones: {}", zones["errors"]);
        }

        let (zone_name, zone_id) = zones["result"]
            .as_array()
            .expect("'result' to be an array")
            .iter()
            .find_map(|zone| {
                let zone_name = zone["name"].as_str().expect("'name' to be a string");
                let zone_id = zone["id"].as_str().expect("'id' to be a string");

                println!("checking {zone_name}...");

                if zone_name == domain || domain.ends_with(&format!(".{zone_name}")) {
                    Some((zone_name.to_string(), zone_id.to_string()))
                } else {
                    None
                }
            })
            .ok_or(anyhow::anyhow!("couldn't find an appropriate zone"))?;

        println!("we're going to use the zone named {zone_name} with id {zone_id}");

        Ok(Self {
            domain: domain.to_owned(),
            zone_name,
            zone_id,
            cloudflare_dns_api_token: cloudflare_dns_api_token.to_owned(),
        })
    }

    pub(crate) fn publish_acme_proof(&self, dns_proof: &str) -> anyhow::Result<()> {
        let response = ureq::post(format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        ))
        .header(
            "Authorization",
            format!("Bearer {}", self.cloudflare_dns_api_token),
        )
        .send_json(&serde_json::json!({
            "name": format!("_acme-challenge.{}", self.domain),
            "ttl": 1,
            "type": "TXT",
            "content": dbg!(dns_proof),
        }))?;

        if !response.status().is_success() {
            anyhow::bail!(
                "post /client/v4/zones/{}/dns_records: {response:?}",
                self.zone_id
            );
        }

        Ok(())
    }
}
