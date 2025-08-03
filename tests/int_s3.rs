use anyhow::Result;
use kingfisher::s3::visit_bucket_objects;

#[tokio::test]
async fn test_visit_public_bucket() -> Result<()> {
    let mut objects = Vec::new();
    visit_bucket_objects("awsglue-datasets", Some("examples/us-legislators/all/"), None, None, |key, data| {
        objects.push((key, data));
        Ok(())
    })
    .await?;

    assert!(
        objects.iter().any(|(k, _)| k.ends_with("events.json")),
        "events.json object not found"
    );
    let creds = objects
        .iter()
        .find(|(k, _)| k.ends_with("events.json"))
        .expect("events.json object");

    let body = std::str::from_utf8(&creds.1)?;
    assert!(
        body.contains("Q4450263"),
        "expected events.json file"
    );
    Ok(())
}