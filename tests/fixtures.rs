use std::path::Path;

#[test]
fn every_documented_fixture_has_the_expected_event_name() {
    let fixtures = [
        "charge.success",
        "subscription.create",
        "subscription.disable",
        "subscription.not_renew",
        "invoice.create",
        "invoice.update",
        "invoice.payment_failed",
        "transfer.success",
        "transfer.failed",
        "transfer.reversed",
        "refund.pending",
        "refund.processing",
        "refund.processed",
        "refund.failed",
    ];
    for name in fixtures {
        let path = format!("tests/fixtures/{name}.json");
        let body = std::fs::read_to_string(Path::new(&path)).expect("fixture exists");
        let value: serde_json::Value = serde_json::from_str(&body).expect("fixture is JSON");
        assert_eq!(
            value.get("event").and_then(serde_json::Value::as_str),
            Some(name)
        );
    }
}

#[test]
fn app_store_connect_fixtures_cover_each_requested_event_family() {
    let fixtures = [
        (
            "app_store_connect.build_upload_state_updated",
            "buildUploadStateUpdated",
        ),
        (
            "app_store_connect.app_version_state_updated",
            "appStoreVersionAppVersionStateUpdated",
        ),
        (
            "app_store_connect.beta_feedback_crash_submission_created",
            "betaFeedbackCrashSubmissionCreated",
        ),
        (
            "app_store_connect.beta_feedback_screenshot_submission_created",
            "betaFeedbackScreenshotSubmissionCreated",
        ),
    ];
    for (name, event_type) in fixtures {
        let path = format!("tests/fixtures/{name}.json");
        let body = std::fs::read_to_string(Path::new(&path)).expect("fixture exists");
        let value: serde_json::Value = serde_json::from_str(&body).expect("fixture is JSON");
        assert_eq!(
            value
                .pointer("/data/type")
                .and_then(serde_json::Value::as_str),
            Some(event_type)
        );
        assert_eq!(
            value
                .pointer("/data/attributes/appId")
                .and_then(serde_json::Value::as_str),
            Some("123456789")
        );
    }
}
