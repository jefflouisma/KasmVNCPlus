use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use kasmvnc_oauth::jwt::{Claims, JwtValidator};

fn create_test_token(exp_offset: i64) -> String {
    let now = Utc::now().timestamp();
    let claims = Claims {
        iss: "test-issuer".to_string(),
        sub: "user123".to_string(),
        aud: vec!["test-audience".to_string()],
        exp: now + exp_offset,
        nbf: Some(now),
        iat: Some(now),
        email: Some("user@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Test User".to_string()),
        preferred_username: None,
        picture: None,
        locale: None,
        scope: "openid profile email".to_string(),
        custom: serde_json::json!({}),
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .unwrap()
}

#[test]
fn test_extract_claims_unsafe() {
    let token = create_test_token(3600);
    let claims = JwtValidator::extract_claims_unsafe(&token).unwrap();

    assert_eq!(claims.sub, "user123");
    assert_eq!(claims.email, Some("user@example.com".to_string()));
    assert_eq!(claims.iss, "test-issuer");
}
