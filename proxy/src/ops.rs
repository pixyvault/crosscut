mod zone_editor;

fn main() -> std::io::Result<()> {
    let domain = std::env::var("DOMAIN").map_err(std::io::Error::other)?;

    let _zone_editor = crate::zone_editor::ZoneEditor::new(
        &domain,
        &std::fs::read_to_string("/secrets/cloudflare_dns_api")?,
    )?;

    let directory = acme_client::Directory::lets_encrypt()?;
    let account = directory.account_registration().register()?;

    let authorization = account.authorization(domain)?;

    let dns_challenge = authorization.get_dns_challenge()?;

    let signature = dns_challenge.signature()?;

    // TODO add _acme-challenge.{domain} TXT -> {signature}

    dns_challenge.validate()?;

    let certificate_signer = account.certificate_signer(&[domain])?;
    let certificate = certificate_signer.sign_certificate()?;
    certificate.save_signed_certificate(format!("/secrets/{domain}.certificate.pem"))?;
    certificate.save_private_key(format!("/secrets/{domain}.certificate.key"))?;

    Ok(())
}
