// Copyright (C) 2026 Mike Sauh
//
// This file is part of ExposedObserve, a modified fork of OpenObserve.
//
// OpenObserve is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// Original project: https://github.com/openobserve/openobserve
//
// This file was created independently to add OIDC authentication and claim-based authorization.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    time::Duration,
};

use openidconnect::{
    AdditionalClaims, EndpointMaybeSet, EndpointNotSet, EndpointSet, ExtraTokenFields, IdToken,
    IdTokenClaims, IdTokenFields, Nonce, NonceVerifier, StandardErrorResponse,
    StandardTokenResponse,
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreRevocableToken,
        CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
    },
};
use serde_json::Value;

use crate::config::{ORG_CAPTURE_GROUP, OidcConfig, ROLE_CAPTURE_GROUP, get_oidc_config};

/// User information extracted from OIDC token claims.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct UserInfo {
    pub sub: String,
    pub email: String,
    pub orgs: HashSet<String>,
    pub org_roles: HashMap<String, String>,
    pub is_internal: bool,
}

impl UserInfo {
    pub fn internal() -> UserInfo {
        UserInfo {
            sub: String::new(),
            email: String::new(),
            orgs: HashSet::new(),
            org_roles: HashMap::new(),
            is_internal: true,
        }
    }

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
                let mut orgs = map_claims_to_orgs(
                    &oidc_config.org_claim_pattern,
                    &oidc_config.org_claim,
                    ext_map,
                );
                orgs.retain(|org| !oidc_config.org_blacklist.contains(org));

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

impl Display for UserInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let orgs = serde_json::to_string(&self.orgs).unwrap_or_default();
        let s = format!(
            "Subject: {}\nEmail: {}\nOrganizations: {}\nInternal: {}",
            self.sub, self.email, orgs, self.is_internal
        );
        write!(f, "{s}")
    }
}

/// Maps OIDC claims to role assignments using regex pattern matching.
pub(crate) fn map_claims_to_roles(
    oidc_config: &OidcConfig,
    claims: &HashMap<String, Value>,
) -> HashMap<String, String> {
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
pub(crate) fn map_claims_to_orgs(
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

fn map_array_claim_to_orgs(array: Option<&Vec<Value>>, re: &regex::Regex) -> HashSet<String> {
    match array {
        Some(vec) => HashSet::from_iter(
            vec.iter()
                .map(|item| item.as_str().unwrap_or_default())
                .map(|s| {
                    let Some(caps) = re.captures(s) else {
                        return "";
                    };
                    caps.name(ORG_CAPTURE_GROUP).map_or("", |m| m.as_str())
                })
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        ),
        None => HashSet::new(),
    }
}

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

fn map_array_claim_to_roles(
    array: Option<&Vec<Value>>,
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

/// In-flight state for an OIDC authorization request.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AuthorizationState {
    pub pkce_verifier: String,
    pub csrf_state: String,
    pub nonce: String,
}

/// Query parameters expected on the OIDC callback URL.
#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct CallbackState {
    pub code: String,
    pub state: String,
}

/// Tokens issued by the OIDC provider, stored server-side per session.
#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
pub struct AuthTokens {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<Duration>,
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
}

impl AuthTokens {
    pub fn has_refresh_token(&self) -> bool {
        !self.refresh_token.is_empty()
    }
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
            access_preview, refresh_preview, self.id_token,
        );
        write!(f, "{to_str}")
    }
}

/// ADFS extra-token fields (e.g. `refresh_token_expires_in`).
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct AdfsFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_expires_in: Option<u64>,
}

impl AdfsFields {
    pub fn refresh_token_expires_in(&self) -> Option<Duration> {
        self.refresh_token_expires_in.map(Duration::from_secs)
    }
}

impl ExtraTokenFields for AdfsFields {}

/// Custom additional-claims bag. Every extra claim that the OIDC provider
/// returns is flattened into `custom` via `#[serde(flatten)]`.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct CustomClaims {
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<HashMap<String, Value>>,
}

impl AdditionalClaims for CustomClaims {}

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

/// `NonceVerifier` that accepts any nonce. Used in tests and in cases where
/// the server does not need to verify the nonce against a stored value.
pub struct EmptyNonceVerifier;

impl NonceVerifier for EmptyNonceVerifier {
    fn verify(self, _nonce: Option<&Nonce>) -> Result<(), String> {
        Ok(())
    }
}

pub fn empty_nonce_verifier() -> impl NonceVerifier {
    EmptyNonceVerifier
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    use super::*;

    #[test]
    fn map_string_claim_to_orgs_matches() {
        let re = Regex::new("^foo_(?<org>.*)$").unwrap();
        let orgs = map_string_claim_to_orgs(Some("foo_bar"), &re);
        assert_eq!(orgs, HashSet::from(["bar".to_string()]));
    }

    #[test]
    fn map_string_claim_to_orgs_no_match() {
        let re = Regex::new("^foo_(?<org>.*)$").unwrap();
        let orgs = map_string_claim_to_orgs(Some("baz_bar"), &re);
        assert!(orgs.is_empty());
    }

    #[test]
    fn map_string_claim_to_orgs_none() {
        let re = Regex::new("^foo_(?<org>.*)$").unwrap();
        let orgs = map_string_claim_to_orgs(None, &re);
        assert!(orgs.is_empty());
    }

    #[test]
    fn map_array_claim_to_orgs_matches() {
        let re = Regex::new("^foo_(?<org>.*)$").unwrap();
        let arr = vec![
            Value::String("foo_bar".to_string()),
            Value::String("foo_baz".to_string()),
        ];
        let orgs = map_array_claim_to_orgs(Some(&arr), &re);
        assert_eq!(orgs, HashSet::from(["bar".to_string(), "baz".to_string()]));
    }

    #[test]
    fn map_string_claim_to_roles_matches() {
        let re = Regex::new(r"^(?<org>org):(?<role>\w+)$").unwrap();
        let roles = map_string_claim_to_roles(Some("org:admin"), &re);
        assert_eq!(roles.get("org").map(String::as_str), Some("admin"));
    }

    #[test]
    fn map_string_claim_to_roles_no_match() {
        let re = Regex::new(r"^(?<org>org):(?<role>\w+)$").unwrap();
        let roles = map_string_claim_to_roles(Some("plain"), &re);
        assert!(roles.is_empty());
    }

    #[test]
    fn map_array_claim_to_roles_matches() {
        let re = Regex::new(r"^(?<org>[a-z]+):(?<role>\w+)$").unwrap();
        let arr = vec![
            Value::String("org:admin".to_string()),
            Value::String("team:viewer".to_string()),
        ];
        let roles = map_array_claim_to_roles(Some(&arr), &re);
        assert_eq!(roles.get("org").map(String::as_str), Some("admin"));
        assert_eq!(roles.get("team").map(String::as_str), Some("viewer"));
    }

    #[test]
    fn user_info_internal_is_flagged() {
        let info = UserInfo::internal();
        assert!(info.is_internal);
        assert_eq!(info.sub, "");
        assert!(info.orgs.is_empty());
    }

    #[test]
    fn auth_tokens_has_refresh_token() {
        let tokens = AuthTokens {
            access_token: "a".into(),
            refresh_token: "r".into(),
            id_token: "i".into(),
            expires_in: None,
        };
        assert!(tokens.has_refresh_token());

        let empty = AuthTokens {
            access_token: "a".into(),
            refresh_token: String::new(),
            id_token: "i".into(),
            expires_in: None,
        };
        assert!(!empty.has_refresh_token());
    }

    #[test]
    fn user_info_display_does_not_panic() {
        let info = UserInfo {
            sub: "user-1".into(),
            email: "u@example.com".into(),
            orgs: HashSet::from(["a".to_string()]),
            org_roles: HashMap::new(),
            is_internal: false,
        };
        let s = format!("{info}");
        assert!(s.contains("user-1"));
        assert!(s.contains("u@example.com"));
    }

    #[test]
    fn adfs_fields_roundtrip() {
        let f = AdfsFields {
            refresh_token_expires_in: Some(120),
        };
        assert_eq!(f.refresh_token_expires_in(), Some(Duration::from_secs(120)));
    }
}
