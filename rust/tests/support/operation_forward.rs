// SPDX-License-Identifier: Apache-2.0

/// Assert the mediated child frame is the authorized JSON object plus exactly
/// one receiver-visible operation id. Returns that id for callers that need to
/// correlate it with a signed receipt.
pub fn assert_operation_forward(actual: &str, authorized: &str) -> String {
    let mut actual_json: serde_json::Value = serde_json::from_str(actual).unwrap();
    let operation_id = actual_json
        .as_object_mut()
        .expect("forwarded request is an object")
        .remove("operation_id")
        .and_then(|value| value.as_str().map(str::to_owned))
        .expect("mediated forward carries operation_id");
    assert_eq!(operation_id.len(), 64);
    assert!(
        operation_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
        "operation_id is lowercase hex"
    );
    assert_eq!(
        actual_json,
        serde_json::from_str::<serde_json::Value>(authorized).unwrap(),
        "operation_id must be the only child-visible change"
    );
    operation_id
}
