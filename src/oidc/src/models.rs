// Copyright (C) 2025 Mike Sauh
//
// This file is part of ExposedObserve, a modified fork of OpenObserve.
//
// OpenObserve is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// Original project: https://github.com/openobserve/openobserve
//
// This file is NOT part of the original OpenObserve codebase.
// It was created independently to add OIDC authentication and claim-based authorization.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    time::Duration,
};

use actix_session::SessionExt;
use actix_web::{Error, FromRequest, dev::Payload};
use futures::future::{FutureExt, LocalBoxFuture, ready};
use openidconnect::{
    EndpointMaybeSet, EndpointNotSet, EndpointSet, ExtraTokenFields, IdToken, IdTokenClaims,
    IdTokenFields, Nonce, NonceVerifier, StandardErrorResponse, StandardTokenResponse,
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreRevocableToken,
        CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
    },
};
use serde_json::Value;

use crate::{
    client::{exchange_refresh_token, try_to_verify_token},
    config::{ORG_CAPTURE_GROUP, OidcConfig, ROLE_CAPTURE_GROUP, get_oidc_config},
    session::get_session_tokens,
};

/// User information extracted from OIDC token claims.
/// Contains the user's subject identifier, email, and organization/role memberships.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct UserInfo {
    /// The subject identifier of the authenticated user (typically unique user ID).
    pub sub: String,
    /// The user's email address.
    pub email: String,
    /// Set of organization names the user belongs to.
    pub orgs: HashSet<String>,
    /// Map of organization names to role names for the user.
    pub org_roles: HashMap<String, String>,
    /// Flag indicating if this is an internal/system user (bypasses OIDC verification).
    pub is_internal: bool,
}

impl UserInfo {
    fn internal() -> UserInfo {
        UserInfo {
            sub: "".to_owned(),
            email: "".to_owned(),
            orgs: HashSet::new(),
            org_roles: HashMap::new(),
            is_internal: true,
        }
    }

    /// Creates a UserInfo from OIDC token claims.
    ///
    /// This function extracts user information from JWT token claims, including custom claims
    /// that contain organization and role data. It handles missing or malformed claim data
    /// gracefully by providing fallback values.
    ///
    /// Organization and role extraction depends on the configured regex patterns and will
    /// return empty collections if patterns don't match or custom claims are unavailable.
    ///
    /// # Arguments
    /// * `token_claims` - The parsed OIDC token claims
    ///
    /// # Returns
    /// A UserInfo struct with extracted user data
    ///
    /// # Error Handling
    /// - Missing email in claims results in empty email string
    /// - Missing or malformed custom claims result in empty orgs/roles
    /// - Regex pattern mismatches result in no org/role extraction
    /// - Malformed claim data is logged and ignored where possible
    pub fn from_claims(token_claims: &CustomTokenClaims) -> Self {
        let custom_claims = token_claims.additional_claims();
        let is_internal = false;
        let default_email = token_claims
            .email()
            .map(|e| e.as_str().to_string())
            .unwrap_or_default();
        match &custom_claims.custom {
            Some(ext_map) => {
                let oidc_config = get_oidc_config();
                let sub = match &oidc_config.subject_claim {
                    Some(custom_sub_claim) => ext_map
                        .get(custom_sub_claim)
                        .and_then(|v| v.as_str())
                        .unwrap_or_else(|| token_claims.subject().as_str()),
                    None => token_claims.subject().as_str(),
                }
                .to_string();
                let email = match &oidc_config.email_claim {
                    Some(custom_email_claim) => ext_map
                        .get(custom_email_claim)
                        .and_then(|v| v.as_str())
                        .unwrap_or(&default_email),
                    None => &default_email,
                }
                .to_string();
                let orgs = map_claims_to_orgs(
                    &oidc_config.org_claim_pattern,
                    &oidc_config.org_claim,
                    ext_map,
                );

                let org_roles = map_claims_to_roles(&oidc_config, ext_map);
                Self {
                    sub,
                    email,
                    orgs,
                    org_roles,
                    is_internal,
                }
            }
            None => Self {
                sub: token_claims.subject().as_str().to_string(),
                email: default_email,
                orgs: HashSet::new(),
                org_roles: HashMap::new(),
                is_internal,
            },
        }
    }
}

impl FromRequest for UserInfo {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut Payload) -> Self::Future {
        if !req.get_session().contains_key("oidc") {
            // For original oo_validator
            return ready(Ok(UserInfo::internal())).boxed_local();
        }
        let session = req.get_session();
        match get_session_tokens(req) {
            None => async move { Err(actix_web::error::ErrorUnauthorized("Unauthorized Access")) }
                .boxed_local(),
            Some(tokens) => async move {
                let token = match &tokens.id_token.is_empty() {
                    true => &tokens.access_token,
                    false => &tokens.id_token,
                };
                match try_to_verify_token(&token).await {
                    Some(user_info) => Ok(user_info),
                    None => match exchange_refresh_token(tokens).await {
                        Ok((new_info, new_tokens)) => {
                            session.insert("oidc", true)?;
                            session.insert("auth_tokens", &new_tokens)?;
                            session.renew();
                            Ok(new_info)
                        }
                        Err(e) => Err(e)?,
                    },
                }
            }
            .boxed_local(),
        }
    }
}

impl Display for UserInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let orgs = serde_json::to_string(&self.orgs).unwrap_or_default();
        let str = format!(
            "Subject: {}\nEmail: {}\nOrganizations: {}\nInternal: {}",
            &self.sub, &self.email, orgs, &self.is_internal
        );
        write!(f, "{str}")
    }
}

/// Maps OIDC claims to role assignments using regex pattern matching.
///
/// This function extracts role mappings from claim data when the regex pattern contains
/// both organization and role capture groups. If no role capture group exists in the pattern,
/// it returns an empty map.
///
/// # Arguments
/// * `oidc_config` - OIDC configuration containing claim name and regex pattern
/// * `claims` - Map of claim names to JSON values
///
/// # Returns
/// A HashMap mapping organization names to their corresponding role names
///
/// # Error Handling
/// - Returns empty map if pattern doesn't contain "role" capture group
/// - Returns empty map if claim doesn't exist
/// - Returns empty map if claim data is neither string nor array
/// - Invalid role mappings (empty org/role) are filtered out
/// - Malformed claim data is safely ignored
fn map_claims_to_roles(
    oidc_config: &OidcConfig,
    claims: &HashMap<std::string::String, Value>,
) -> HashMap<String, String> {
    // Check if the regex pattern contains a "role" capture group
    if !oidc_config
        .org_claim_pattern
        .capture_names()
        .any(|name| name == Some(ROLE_CAPTURE_GROUP))
    {
        return HashMap::new();
    }

    claims
        .get(&oidc_config.org_claim)
        .map_or(HashMap::new(), |value| {
            if value.is_string() {
                map_string_claim_to_roles(value.as_str(), &oidc_config.org_claim_pattern)
            } else if value.is_array() {
                map_array_claim_to_roles(value.as_array(), &oidc_config.org_claim_pattern)
            } else {
                HashMap::new()
            }
        })
}

/// Maps OIDC claims to organization memberships using regex pattern matching.
///
/// This function extracts organization names from claim data using a configured regex pattern.
/// It safely handles missing claims, malformed data, and regex mismatches by returning
/// an empty collection when no valid organizations can be extracted.
///
/// # Arguments
/// * `re` - The compiled regex pattern for organization extraction
/// * `org_claim` - The key name of the claim containing organization data
/// * `claims` - Map of claim names to JSON values
///
/// # Returns
/// A HashSet of organization names that matched the pattern
///
/// # Error Handling
/// - Returns empty set if claim doesn't exist
/// - Returns empty set if claim data is neither string nor array
/// - Filters out organizations that don't match the regex pattern
/// - Non-string array elements are silently ignored
fn map_claims_to_orgs(
    re: &regex::Regex,
    org_claim: &String,
    claims: &HashMap<String, Value>,
) -> HashSet<String> {
    claims.get(org_claim).map_or(HashSet::new(), |value| {
        if value.is_string() {
            return map_string_claim_to_orgs(value.as_str(), re);
        }
        if value.is_array() {
            return map_array_claim_to_orgs(value.as_array(), re);
        }
        HashSet::new()
    })
}

/// Maps a JSON array claim to organization names using regex pattern matching.
///
/// This function iterates through array elements, converting each string element
/// to an organization name using the provided regex pattern.
///
/// # Arguments
/// * `array` - Optional reference to a vector of JSON values
/// * `re` - The compiled regex pattern for organization extraction
///
/// # Returns
/// A HashSet of organization names that matched the pattern
///
/// # Error Handling
/// - Returns empty set if `array` is None
/// - Non-string array elements are converted to empty string and ignored
/// - Elements not matching the regex pattern are filtered out
/// - Empty organization names after capture are excluded
fn map_array_claim_to_orgs(
    array: Option<&Vec<serde_json::Value>>,
    re: &regex::Regex,
) -> HashSet<String> {
    match array {
        Some(vec) => {
            let iter = vec
                .iter()
                .map(|item| item.as_str().unwrap_or_default())
                .map(|s| {
                    let Some(caps) = re.captures(s) else {
                        return "";
                    };
                    caps.name(ORG_CAPTURE_GROUP).map_or("", |m| m.as_str())
                })
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            return HashSet::from_iter(iter);
        }
        None => HashSet::new(),
    }
}

/// Maps a string claim to an organization name using regex pattern matching.
///
/// This function applies the regex pattern to extract organization name from
/// a single string claim value.
///
/// # Arguments
/// * `claim_string` - Optional string claim value
/// * `re` - The compiled regex pattern for organization extraction
///
/// # Returns
/// A HashSet containing the extracted organization name, or empty if no match
///
/// # Error Handling
/// - Returns empty set if `claim_string` is None
/// - Returns empty set if string doesn't match the regex pattern
/// - Returns empty set if captured organization name is empty
fn map_string_claim_to_orgs(claim_string: Option<&str>, re: &regex::Regex) -> HashSet<String> {
    match claim_string {
        Some(claim) => {
            let Some(caps) = re.captures(claim) else {
                return HashSet::new();
            };
            let org = caps.name(ORG_CAPTURE_GROUP).map_or("", |m| m.as_str());
            if !org.is_empty() {
                return HashSet::from([org.to_string()]);
            }
            HashSet::new()
        }
        None => HashSet::new(),
    }
}

/// Maps a string claim to organization-role assignment using regex pattern matching.
///
/// This function applies the regex pattern to extract both organization and role
/// from a single string claim value.
///
/// # Arguments
/// * `claim_string` - Optional string claim value
/// * `re` - The compiled regex pattern containing both org and role capture groups
///
/// # Returns
/// A HashMap with the organization-role mapping, or empty if no valid mapping found
///
/// # Error Handling
/// - Returns empty map if `claim_string` is None
/// - Returns empty map if string doesn't match the regex pattern
/// - Returns empty map if captured organization or role names are empty
fn map_string_claim_to_roles(
    claim_string: Option<&str>,
    re: &regex::Regex,
) -> HashMap<String, String> {
    match claim_string {
        Some(claim) => {
            let Some(caps) = re.captures(claim) else {
                return HashMap::new();
            };
            let org = caps
                .name(ORG_CAPTURE_GROUP)
                .map_or("", |m| m.as_str())
                .to_string();
            let role = caps
                .name(ROLE_CAPTURE_GROUP)
                .map_or("", |m| m.as_str())
                .to_string();
            if !org.is_empty() && !role.is_empty() {
                let mut map = HashMap::new();
                map.insert(org, role);
                map
            } else {
                HashMap::new()
            }
        }
        None => HashMap::new(),
    }
}

/// Maps a JSON array claim to role assignments using regex pattern matching.
///
/// This function iterates through array elements, extracting organization-role
/// mappings from each string element using the provided regex pattern.
///
/// # Arguments
/// * `array` - Optional reference to a vector of JSON values
/// * `re` - The compiled regex pattern containing both org and role capture groups
///
/// # Returns
/// A HashMap mapping organization names to their corresponding role names
///
/// # Error Handling
/// - Returns empty map if `array` is None
/// - Non-string array elements are silently ignored
/// - Elements not matching the regex pattern are ignored
/// - Invalid mappings (empty org/role) are filtered out
fn map_array_claim_to_roles(
    array: Option<&Vec<serde_json::Value>>,
    re: &regex::Regex,
) -> HashMap<String, String> {
    match array {
        Some(vec) => {
            let mut roles_map = HashMap::new();
            for item in vec {
                if let Some(s) = item.as_str() {
                    let Some(caps) = re.captures(s) else {
                        continue;
                    };
                    let org = caps
                        .name(ORG_CAPTURE_GROUP)
                        .map_or("", |m| m.as_str())
                        .to_string();
                    let role = caps
                        .name(ROLE_CAPTURE_GROUP)
                        .map_or("", |m| m.as_str())
                        .to_string();
                    if !org.is_empty() && !role.is_empty() {
                        roles_map.insert(org, role);
                    }
                }
            }
            roles_map
        }
        None => HashMap::new(),
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AuthorizationState {
    pub pkce_verifier: String,
    pub csrf_state: String,
    pub nonce: String,
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct CallbackState {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct AuthTokens {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<Duration>,
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
}

impl Display for AuthTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let access_preview = if self.access_token.len() >= 3 {
            format!("{}...", &self.access_token[0..self.access_token.len() / 3])
        } else {
            self.access_token.clone()
        };
        let refresh_preview = if self.refresh_token.len() >= 3 {
            format!(
                "{}...",
                &self.refresh_token[0..self.refresh_token.len() / 3]
            )
        } else {
            self.refresh_token.clone()
        };
        let to_str = format!(
            "access_token: {}\nrefresh_token: {}\nid_token: {}",
            access_preview, refresh_preview, &self.id_token,
        );
        write!(f, "{to_str}")
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AdfsFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token_expires_in: Option<u64>,
}

impl AdfsFields {
    pub fn refresh_token_expires_in(&self) -> Option<Duration> {
        self.refresh_token_expires_in.map(Duration::from_secs)
    }
}

impl ExtraTokenFields for AdfsFields {}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CustomClaims {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub custom: Option<HashMap<String, serde_json::Value>>,
}

impl openidconnect::AdditionalClaims for CustomClaims {}

pub type CustomTokenFields = IdTokenFields<
    CustomClaims,
    AdfsFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

pub type CustomToken = IdToken<
    CustomClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

pub type CustomTokenClaims = IdTokenClaims<CustomClaims, CoreGenderClaim>;

pub type CustomTokenResponse = StandardTokenResponse<CustomTokenFields, CoreTokenType>;

pub type CustomClient<
    HasAuthUrl = EndpointSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointMaybeSet,
    HasUserInfoUrl = EndpointMaybeSet,
> = openidconnect::Client<
    CustomClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    CustomTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

pub struct EmptyNonceVerifier;

impl NonceVerifier for EmptyNonceVerifier {
    fn verify(self, _nonce: Option<&Nonce>) -> Result<(), String> {
        Ok(())
    }
}

pub(crate) fn empty_nonce_verifier() -> impl NonceVerifier {
    EmptyNonceVerifier
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
        time::Duration,
    };

    use base64::Engine;
    use openidconnect::{IdTokenVerifier, core::CoreJsonWebKey};
    use regex::Regex;
    use serde_json::Value;

    use crate::{
        config::OidcConfig,
        models::{
            AuthTokens, CustomToken, CustomTokenClaims, UserInfo, empty_nonce_verifier,
            map_array_claim_to_orgs, map_claims_to_roles, map_string_claim_to_orgs,
        },
    };

    #[test]
    fn test_user_info_display() {
        let expected = vec![
            "Subject: citien\nEmail: citizen@foo.bar\nOrganizations: [\"foo\",\"bar\"]\nInternal: false",
            "Subject: citien\nEmail: citizen@foo.bar\nOrganizations: [\"bar\",\"foo\"]\nInternal: false",
        ];
        let user_info = UserInfo {
            sub: "citien".to_owned(),
            email: "citizen@foo.bar".to_owned(),
            orgs: HashSet::from(["foo".to_owned(), "bar".to_owned()]),
            org_roles: HashMap::new(),
            is_internal: false,
        };
        print!("{user_info}\n");
        assert!(expected.contains(&user_info.to_string().as_str()));
    }
    #[test]
    fn test_custom_token_deserialize() {
        let claims_json = r#"{
                "sub": "citizen",
                "aud": "client",
                "nbf": 1762941467,
                "azp": "client",
                "iss": "http://localhost:8080/default",
                "groups": [
                    "foo",
                    "bar"
                ],
                "exp": 9999999999,
                "iat": 1762941467,
                "jti": "c2a5bf31-29aa-41f6-b101-ae5eeb09164c",
                "tid": "default",
                "email": "citizen@foo.bar"
                }"#;
        let id_token_str = format!(
            "eyJraWQiOiJkZWZhdWx0IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.{}.aHUQihTTpVEC1jSjvbm8ikajfRoe1GunqtZw9OHnccu5mQoFVsUS4Dtt_q8m-0BLQknlVl7SxctKE6jd5cvpc1202737O7XrAKDLH94-_tQdzp6Whhk0YcIrRtMyBKrTgMr0wmv0qjZ2U9WB9jx6Soy-w8LFhAQS4rOdFcpHdbVMLRugPFUkRG47_hvj1746VzAdUTV3_Xn4qJMdCelTN1reWMZejZTrA9qJXpfsWM-8tJIDN27-_DpqcwCoBwRZ-dqAcVuBnPmLWAUfV-2pxpu5J0o0w81Zrc7zqtEn7Gr5vaNg8j6sxfpa5yq9chbTEM7si9Fm3kv1LrnflNhKYA",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(claims_json)
        );
        let id_token: CustomToken = CustomToken::from_str(id_token_str.as_str()).unwrap();
        let verifier = &IdTokenVerifier::<CoreJsonWebKey>::new_insecure_without_verification();
        let claims: &CustomTokenClaims = id_token.claims(verifier, empty_nonce_verifier()).unwrap();
        let user_info = UserInfo::from_claims(claims);
        print!("{user_info}");
        assert!(user_info.sub == "citizen");
        assert!(user_info.email == "citizen@foo.bar");
        assert!(user_info.orgs.is_empty());
        assert!(!user_info.is_internal);
    }
    #[test]
    fn test_map_string_claim_to_orgs() {
        let regex: &Regex = &Regex::new("^foo_(?<org>.*)$").unwrap();
        let orgs: HashSet<String> = map_string_claim_to_orgs(Some("foo_bar"), regex);
        let expected: HashSet<String> = HashSet::<String>::from(["bar".to_string()]);
        assert_eq!(orgs, expected);
    }

    #[test]
    fn test_map_string_claim_to_orgs_default() {
        let regex: &Regex = &Regex::new("^foo_(?<org>.*)$").unwrap();
        let orgs: HashSet<String> = map_string_claim_to_orgs(Some("baz_bar"), regex);
        assert!(orgs.is_empty());
    }
    #[test]
    fn test_map_string_claim_to_orgs_none() {
        let regex: &Regex = &Regex::new("^foo_(?<org>.*)$").unwrap();
        let orgs: HashSet<String> = map_string_claim_to_orgs(None, regex);
        assert!(orgs.is_empty());
    }
    #[test]
    fn test_map_array_claim_to_orgs() {
        let regex: &Regex = &Regex::new("^foo_(?<org>.*)$").unwrap();
        let orgs: HashSet<String> = map_array_claim_to_orgs(
            Some(&vec![
                Value::String("foo_bar".to_string()),
                Value::String("foo_baz".to_string()),
            ]),
            regex,
        );
        let expected: HashSet<String> =
            HashSet::<String>::from(["bar".to_string(), "baz".to_string()]);
        assert_eq!(orgs, expected);
    }

    #[test]
    fn test_map_array_claim_to_orgs_default() {
        let regex: &Regex = &Regex::new("^foo_(?<org>.*)$").unwrap();
        let orgs: HashSet<String> = map_array_claim_to_orgs(
            Some(&vec![
                Value::String("foo_bar".to_string()),
                Value::String("lol_kek".to_string()),
            ]),
            regex,
        );
        let expected: HashSet<String> = HashSet::<String>::from(["bar".to_string()]);
        assert_eq!(orgs, expected);
    }

    #[test]
    fn test_map_array_claim_to_roles_mixed() {
        let regex: &Regex = &Regex::new(r"^(?<org>\w+)_(?<role>\w+)$").unwrap();
        let roles: HashMap<String, String> = super::map_array_claim_to_roles(
            Some(&vec![
                Value::String("foo_admin".to_string()),
                Value::String("invalid".to_string()),
                Value::Number(serde_json::Number::from(123)), // non-string
            ]),
            regex,
        );
        let mut expected: HashMap<String, String> = HashMap::new();
        expected.insert("foo".to_string(), "admin".to_string());
        assert_eq!(roles, expected);
    }

    #[test]
    fn test_map_claims_to_roles_with_role_pattern() {
        let role_pattern = Regex::new(r"^(?<org>\w+)_(?<role>\w+)$").unwrap();
        let mut claims = HashMap::new();
        let groups = Value::Array(vec![
            Value::String("org1_admin".to_string()),
            Value::String("org2_user".to_string()),
        ]);
        claims.insert("groups".to_string(), groups);

        let config = OidcConfig::new(
            "test".to_string(),
            Some("test".to_string()),
            "https://example.com".to_string(),
            "https://example.com/callback".to_string(),
            "https://example.com/callback".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("groups".to_string()),
            Some(role_pattern),
            None,
            None,
        );

        let roles = map_claims_to_roles(&config, &claims);
        let mut expected: HashMap<String, String> = HashMap::new();
        expected.insert("org1".to_string(), "admin".to_string());
        expected.insert("org2".to_string(), "user".to_string());
        assert_eq!(roles, expected);
    }

    #[test]
    fn test_map_claims_to_roles_without_role_pattern() {
        let org_only_pattern = Regex::new(r"^(?<org>org\d+)$").unwrap();
        let mut claims = HashMap::new();
        let groups = Value::Array(vec![
            Value::String("org1".to_string()),
            Value::String("org2".to_string()),
        ]);
        claims.insert("groups".to_string(), groups);

        // Mock config that only has org pattern (no role group)
        let config = OidcConfig::new(
            "test".to_string(),
            Some("test".to_string()),
            "https://example.com".to_string(),
            "https://example.com/callback".to_string(),
            "https://example.com/callback".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("groups".to_string()),
            Some(org_only_pattern),
            None,
            None,
        );

        let roles = map_claims_to_roles(&config, &claims);
        // Should return empty map since pattern doesn't have role group
        assert!(roles.is_empty());
    }

    #[test]
    fn test_auth_tokens_display_short_tokens() {
        let tokens = AuthTokens {
            expires_in: Some(Duration::from_secs(3600)),
            access_token: "ab".to_string(),
            refresh_token: "c".to_string(),
            id_token: "token".to_string(),
        };
        let display = format!("{tokens}");
        assert!(display.contains("ab")); // full token since len=2 < 3
        assert!(display.contains("c")); // full token
        assert!(display.contains("token"));
    }

    #[test]
    fn test_auth_tokens_display_long_tokens() {
        let tokens = AuthTokens {
            expires_in: None,
            access_token: "verylongaccesstokenhere".to_string(),
            refresh_token: "verylongrefreshtokenhere".to_string(),
            id_token: "verylongidtokenhere".to_string(),
        };
        let display = format!("{tokens}");
        // Should show partial with ... since len/3 is about 6 chars
        assert!(display.contains("..."));
        assert!(display.contains("veryl"));
        assert!(!display.contains("verylongaccesstokenhere")); // full should not be shown
    }

    #[test]
    fn test_custom_email_claim() {
        use crate::config::{set_test_config, clear_test_config};

        // Create a config with custom email claim
        let config = OidcConfig::new(
            "test".to_string(),
            Some("test".to_string()),
            "https://example.com".to_string(),
            "https://example.com/callback".to_string(),
            "https://example.com/callback".to_string(),
            None, None, None, None, None, None, None, None, None, None, None, None, None,
            Some("custom_email".to_string()), // custom email claim
        );
        set_test_config(config);

        // Create JWT token with custom email claim
        let claims_json = r#"{
                "sub": "citizen",
                "aud": "client",
                "nbf": 1762941467,
                "azp": "client",
                "iss": "http://localhost:8080/default",
                "custom_email": "custom@example.com",
                "email": "standard@example.com",
                "exp": 9999999999,
                "iat": 1762941467,
                "jti": "c2a5bf31-29aa-41f6-b101-ae5eeb09164c",
                "tid": "default"
                }"#;
        let id_token_str = format!(
            "eyJraWQiOiJkZWZhdWx0IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.{}.aHUQihTTpVEC1jSjvbm8ikajfRoe1GunqtZw9OHnccu5mQoFVsUS4Dtt_q8m-0BLQknlVl7SxctKE6jd5cvpc1202737O7XrAKDLH94-_tQdzp6Whhk0YcIrRtMyBKrTgMr0wmv0qjZ2U9WB9jx6Soy-w8LFhAQS4rOdFcpHdbVMLRugPFUkRG47_hvj1746VzAdUTV3_Xn4qJMdCelTN1reWMZejZTrA9qJXpfsWM-8tJIDN27-_DpqcwCoBwRZ-dqAcVuBnPmLWAUfV-2pxpu5J0o0w81Zrc7zqtEn7Gr5vaNg8j6sxfpa5yq9chbTEM7si9Fm3kv1LrnflNhKYA",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(claims_json)
        );

        let id_token: CustomToken = CustomToken::from_str(id_token_str.as_str()).unwrap();
        let verifier = &IdTokenVerifier::<CoreJsonWebKey>::new_insecure_without_verification();
        let claims: &CustomTokenClaims = id_token.claims(verifier, empty_nonce_verifier()).unwrap();
        let user_info = UserInfo::from_claims(claims);

        // Should use custom email claim instead of standard email
        assert_eq!(user_info.email, "custom@example.com");
        assert_eq!(user_info.sub, "citizen");

        clear_test_config();
    }

    #[test]
    fn test_fallback_to_standard_email_claim() {
        use crate::config::{set_test_config, clear_test_config};

        // Create a config with custom email claim that doesn't exist
        let config = OidcConfig::new(
            "test".to_string(),
            Some("test".to_string()),
            "https://example.com".to_string(),
            "https://example.com/callback".to_string(),
            "https://example.com/callback".to_string(),
            None, None, None, None, None, None, None, None, None, None, None, None, None,
            Some("nonexistent_email".to_string()), // custom email claim that doesn't exist
        );
        set_test_config(config);

        // Create JWT token with only standard email claim
        let claims_json = r#"{
                "sub": "citizen",
                "aud": "client",
                "nbf": 1762941467,
                "azp": "client",
                "iss": "http://localhost:8080/default",
                "email": "standard@example.com",
                "exp": 9999999999,
                "iat": 1762941467,
                "jti": "c2a5bf31-29aa-41f6-b101-ae5eeb09164c",
                "tid": "default"
                }"#;
        let id_token_str = format!(
            "eyJraWQiOiJkZWZhdWx0IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.{}.aHUQihTTpVEC1jSjvbm8ikajfRoe1GunqtZw9OHnccu5mQoFVsUS4Dtt_q8m-0BLQknlVl7SxctKE6jd5cvpc1202737O7XrAKDLH94-_tQdzp6Whhk0YcIrRtMyBKrTgMr0wmv0qjZ2U9WB9jx6Soy-w8LFhAQS4rOdFcpHdbVMLRugPFUkRG47_hvj1746VzAdUTV3_Xn4qJMdCelTN1reWMZejZTrA9qJXpfsWM-8tJIDN27-_DpqcwCoBwRZ-dqAcVuBnPmLWAUfV-2pxpu5J0o0w81Zrc7zqtEn7Gr5vaNg8j6sxfpa5yq9chbTEM7si9Fm3kv1LrnflNhKYA",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(claims_json)
        );

        let id_token: CustomToken = CustomToken::from_str(id_token_str.as_str()).unwrap();
        let verifier = &IdTokenVerifier::<CoreJsonWebKey>::new_insecure_without_verification();
        let claims: &CustomTokenClaims = id_token.claims(verifier, empty_nonce_verifier()).unwrap();
        let user_info = UserInfo::from_claims(claims);

        // Should fall back to standard email claim
        assert_eq!(user_info.email, "standard@example.com");
        assert_eq!(user_info.sub, "citizen");

        clear_test_config();
    }
}
