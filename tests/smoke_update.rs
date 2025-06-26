use kingfisher::{cli::global::GlobalArgs, update::check_for_update};
use tokio;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn no_update_when_flag_set() {
    let args = GlobalArgs { no_update_check: true, ..Default::default() };
    assert!(check_for_update(&args, None).is_none());
}

#[tokio::test]
async fn detects_new_release() {
    let server = MockServer::start().await;

    let body = serde_json::json!({
        "tag_name": "v99.999.0",
        "created_at": "2025-01-01T00:00:00Z",
        "name": "Kingfisher 99.999.0",
        "body": "",
        "assets": [{"url": "http://example.com/bin", "name": "bin"}]
    });

    // Stub HEAD *and* GET
    for m in ["HEAD", "GET"] {
        Mock::given(method(m))
            .and(path("/repos/mongodb/kingfisher/releases/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;
    }

    // run the update checker on a blocking thread
    let msg = tokio::task::spawn_blocking({
        let uri = server.uri(); // move into closure
        let args = GlobalArgs::default();
        move || check_for_update(&args, Some(&uri))
    })
    .await
    .expect("blocking task panicked")
    .expect("update checker returned None");

    assert!(msg.contains("99.999.0"));
}
