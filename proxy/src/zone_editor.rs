pub(crate) struct ZoneEditor {
    domain: String,
    zone_name: String,
    zone_id: String,
    cloudflare_dns_api_token: String,
}

impl ZoneEditor {
    pub(crate) fn new(
        domain: &str,
        cloudflare_dns_api_token: &str,
    ) -> Result<Self, std::io::Error> {
        let client = reqwest::blocking::Client::new();
        let zones: serde_json::Value = client
            .request(
                reqwest::Method::GET,
                "https://api.cloudflare.com/client/v4/zones/",
            )
            .bearer_auth(cloudflare_dns_api_token)
            .send()
            .map_err(std::io::Error::other)?
            .error_for_status()
            .map_err(std::io::Error::other)?
            .json()
            .map_err(std::io::Error::other)?;

        if !zones["success"].as_bool().expect("'success' to be boolean") {
            return Err(std::io::Error::other(format!(
                "in /client/v4/zones: {}",
                zones["errors"]
            )));
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
            .ok_or(std::io::Error::other("couldn't find an appropriate zone"))?;

        println!("we're going to use the zone named {zone_name} with id {zone_id}");

        Ok(Self {
            domain: domain.to_owned(),
            zone_name,
            zone_id,
            cloudflare_dns_api_token: cloudflare_dns_api_token.to_owned(),
        })
    }
}
