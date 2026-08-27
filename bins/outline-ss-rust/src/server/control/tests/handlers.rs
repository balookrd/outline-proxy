use super::*;

#[test]
fn create_request_rejects_unknown_fields() {
    // Stale clients sending removed per-user path fields like `ws_path_tcp`
    // must get a deserialization error (400), not silent-ignore.
    let json = r#"
    {
        "id": "test-user",
        "password": "secret",
        "ws_path_tcp": "/x"
    }
    "#;

    let result: Result<CreateRequest, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "CreateRequest must reject unknown field 'ws_path_tcp', got {:?}",
        result
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unknown field"),
        "error message must mention unknown field: {}",
        err_msg
    );
}

#[test]
fn create_request_accepts_valid_fields() {
    let json = r#"
    {
        "id": "test-user",
        "password": "secret",
        "method": "2022-blake3-aes-256-gcm"
    }
    "#;

    let result: Result<CreateRequest, _> = serde_json::from_str(json);
    assert!(
        result.is_ok(),
        "CreateRequest must accept valid fields, got error: {:?}",
        result
    );
    let req = result.unwrap();
    assert_eq!(req.id, "test-user");
    assert_eq!(req.password, Some("secret".to_string()));
}

#[test]
fn update_request_rejects_unknown_fields() {
    // Stale clients sending removed per-user path fields must fail.
    let json = r#"
    {
        "password": "new-secret",
        "ws_path_tcp": "/x"
    }
    "#;

    let result: Result<UpdateRequest, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "UpdateRequest must reject unknown field 'ws_path_tcp', got {:?}",
        result
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unknown field"),
        "error message must mention unknown field: {}",
        err_msg
    );
}

#[test]
fn update_request_accepts_valid_fields() {
    let json = r#"
    {
        "password": "new-secret",
        "enabled": true
    }
    "#;

    let result: Result<UpdateRequest, _> = serde_json::from_str(json);
    assert!(
        result.is_ok(),
        "UpdateRequest must accept valid fields, got error: {:?}",
        result
    );
    let req = result.unwrap();
    assert!(matches!(req.password, FieldPatch::Set(_)));
    assert_eq!(req.enabled, Some(true));
}
