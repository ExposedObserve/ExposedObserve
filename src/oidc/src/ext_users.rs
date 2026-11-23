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
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::str::FromStr;

use config::meta::user::{DBUser, UserOrg, UserRole};
use infra::table::organizations;

use crate::{AuthError, config::get_oidc_config, models::UserInfo};

/// Checks if a user with the given email is a member of the specified organization.
pub async fn check_user_in_org(email: &str, org_id: &str) -> Option<UserRole> {
    let orgs = db::org_users::list_orgs_by_user(email)
        .await
        .inspect_err(|e| {
            log::error!(
                "Failed to fetch organizations list by user: {}\n{}",
                email,
                e
            );
        })
        .ok()?;
    orgs.into_iter()
        .find(|org| org.org_id.eq_ignore_ascii_case(org_id))
        .map(|rec| rec.role)
}

/// Synchronizes user information from the OIDC provider into the local
/// user/org tables. Idempotent: safe to call on every login.
pub async fn sync_user_info(user_info: &UserInfo) -> Result<(), AuthError> {
    let name = user_info.sub.trim();
    let (first_name, last_name) = name.split_once(' ').unwrap_or((name, ""));
    let user_email = user_info.email.as_str();
    let db_user = db::user::get_user_by_email(user_email).await;

    let effective = apply_admin_org_elevation(user_info).await?;

    let user_orgs = match check_and_create_user_orgs(&effective).await {
        Ok(orgs) => orgs,
        Err(err) => {
            let context = format!(
                "Failed to create/check user organizations for {}",
                user_email
            );
            return Err(AuthError::internal(context, err));
        }
    };

    if db_user.is_none() {
        add_new_user(user_email, first_name, last_name, user_orgs).await
    } else {
        check_and_update_orgs_users(&effective).await
    }
}

/// Returns the user view the provisioner should act on. When the IdP claims
/// membership in the configured admin org, every existing org is granted
/// `Admin` so the reconciliation below materializes (and later revokes) the
/// elevation; otherwise the IdP's own claims are returned unchanged.
async fn apply_admin_org_elevation(user_info: &UserInfo) -> Result<UserInfo, AuthError> {
    let config = get_oidc_config();
    let Some(admin_org) = config.admin_org.as_deref() else {
        return Ok(user_info.clone());
    };
    let claimed = user_info
        .orgs
        .iter()
        .any(|org| org.eq_ignore_ascii_case(admin_org));
    if !claimed {
        return Ok(user_info.clone());
    }

    let blacklist = &config.org_blacklist;
    let all_orgs = db::organization::list(None)
        .await
        .map_err(|err| AuthError::internal("Failed to list organizations", err))?;
    let org_roles: std::collections::HashMap<String, String> = all_orgs
        .into_iter()
        .map(|org| org.identifier)
        .filter(|id| !blacklist.contains(id))
        .map(|id| (id, "admin".to_string()))
        .collect();
    let orgs: std::collections::HashSet<String> = org_roles.keys().cloned().collect();
    log::info!(
        "User {} is a member of the admin org `{}`; elevating to Admin in {} orgs",
        user_info.email,
        admin_org,
        orgs.len()
    );

    Ok(UserInfo {
        sub: user_info.sub.clone(),
        email: user_info.email.clone(),
        orgs,
        org_roles,
        is_internal: user_info.is_internal,
    })
}

/// The role an OIDC user holds in `org_id`.
///
/// A role the IdP never mentioned falls back to the configured default role
/// rather than to a hard-coded one, so `OIDC_DEFAULT_ROLE` is what actually
/// reaches the database.
///
/// A role the IdP *did* mention but that is not a known role name lands on
/// `User`, not on the default: the default may be `admin`, and the request
/// gate rejects the unknown role anyway, so the database would grant more
/// than the gate allows.
pub(crate) fn role_for_org(user_info: &UserInfo, org_id: &str) -> UserRole {
    let default_role = get_oidc_config().default_role.clone();
    match user_info.org_roles.get(org_id) {
        Some(role) if UserRole::is_valid_role(role) => {
            UserRole::from_str(role).unwrap_or(default_role)
        }
        Some(role) => {
            log::warn!(
                "OIDC role `{role}` for org `{org_id}` is not a known role; falling back to `user`"
            );
            UserRole::User
        }
        None => default_role,
    }
}

async fn check_and_update_orgs_users(user_info: &UserInfo) -> Result<(), AuthError> {
    let email = user_info.email.as_str();
    let current_orgs = match db::org_users::list_orgs_by_user(email).await {
        Ok(orgs) => orgs,
        Err(err) => {
            let context = format!("Failed to get user: {} orgs", email);
            return Err(AuthError::internal(context, err));
        }
    };

    let current_org_names: std::collections::HashSet<String> =
        current_orgs.iter().map(|o| o.org_id.clone()).collect();
    let user_orgs_to_add: std::collections::HashSet<String> = user_info
        .orgs
        .difference(&current_org_names)
        .cloned()
        .collect();

    for org in current_orgs {
        let org_name = &org.org_id;
        if !user_info.orgs.contains(org_name) {
            match db::org_users::remove(org_name, email).await {
                Ok(()) => {
                    log::info!("User: {} removed from org: {}", email, org_name);
                }
                Err(err) => {
                    let context =
                        format!("Failed to remove user: {} from org: {}", email, org_name);
                    return Err(AuthError::internal(context, err));
                }
            }
            continue;
        }

        let want = role_for_org(user_info, org_name);
        if org.role != want {
            match db::org_users::update(
                org_name,
                email,
                want.clone(),
                &org.token,
                org.rum_token.clone(),
            )
            .await
            {
                Ok(()) => {
                    log::info!(
                        "User: {} role in org: {} updated to {}",
                        email,
                        org_name,
                        want
                    );
                }
                Err(err) => {
                    let context =
                        format!("Failed to update user: {} role in org: {}", email, org_name);
                    return Err(AuthError::internal(context, err));
                }
            }
        }
    }

    for org_name in user_orgs_to_add {
        let role = role_for_org(user_info, &org_name);
        match db::org_users::add(&org_name, email, role, "", None).await {
            Ok(()) => {
                log::info!("User: {} successfully added to org: {}", email, org_name);
            }
            Err(err) => {
                let context = format!("Failed to add user: {} to org: {}", email, org_name);
                return Err(AuthError::internal(context, err));
            }
        }
    }
    Ok(())
}

async fn add_new_user(
    email: &str,
    first_name: &str,
    last_name: &str,
    user_orgs: Vec<UserOrg>,
) -> Result<(), AuthError> {
    let db_user = DBUser {
        email: email.to_string(),
        first_name: first_name.to_string(),
        last_name: last_name.to_string(),
        password: String::new(),
        salt: String::new(),
        organizations: user_orgs,
        is_external: true,
        password_ext: None,
    };
    match db::user::add(&db_user).await {
        Ok(()) => {
            log::info!("User {} added to the database", email);
            Ok(())
        }
        Err(err) => {
            let context = format!("Failed to add user: {} to the database", email);
            Err(AuthError::internal(context, err))
        }
    }
}

async fn check_and_create_user_orgs(user_info: &UserInfo) -> Result<Vec<UserOrg>, anyhow::Error> {
    let mut result = Vec::new();
    for org_id in &user_info.orgs {
        let created = ensure_org_exists(org_id).await?;
        log::debug!("Organization: {} ready (created={})", org_id, created);
        let role = role_for_org(user_info, org_id);
        result.push(UserOrg {
            name: org_id.clone(),
            org_name: org_id.clone(),
            token: String::new(),
            rum_token: None,
            role,
        });
    }
    Ok(result)
}

/// Ensure the given org_id exists in the `organizations` table. Returns
/// `true` if a new row was created, `false` if it already existed.
async fn ensure_org_exists(org_id: &str) -> Result<bool, anyhow::Error> {
    use config::meta::organization::OrganizationType;
    match organizations::get(org_id).await {
        Ok(_) => Ok(false),
        Err(get_err) => {
            organizations::add(org_id, org_id, OrganizationType::Default)
                .await
                .map_err(|add_err| {
                    let combined_err = anyhow::Error::new(add_err).context(get_err);
                    AuthError::internal("organizations::add failed", combined_err)
                })?;

            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use serial_test::serial;

    use super::*;

    /// A config whose default role is `admin`, the case that made the
    /// database and the request gate disagree.
    fn install_config_with_admin_default() {
        let cfg = crate::config::OidcConfig::new(
            "test",
            None,
            "https://example.com",
            "https://example.com/auth/sso/callback",
            "https://example.com/web/cb",
            None,
            crate::config::HttpClientConfig::default(),
            crate::config::CookieConfig::default(),
            crate::config::SessionConfig::default(),
            "groups",
            "^(?<org>[^:]+):(?<role>\\w+)$",
            "admin",
            None,
            Some("sub"),
            Some("email"),
            HashSet::new(),
        )
        .expect("config must build");
        crate::config::set_config(cfg);
    }

    fn user_with_role(role: &str) -> UserInfo {
        UserInfo {
            sub: "user-1".into(),
            email: "user-1@example.com".into(),
            orgs: HashSet::from(["acme".to_string()]),
            org_roles: HashMap::from([("acme".to_string(), role.to_string())]),
            is_internal: false,
        }
    }

    #[test]
    #[serial]
    fn an_invalid_claim_role_becomes_user_not_the_default() {
        install_config_with_admin_default();
        let user = user_with_role("wizard");
        assert_eq!(
            role_for_org(&user, "acme"),
            UserRole::User,
            "an unknown role must not inherit the configured default"
        );
    }

    #[test]
    #[serial]
    fn a_missing_role_falls_back_to_the_configured_default() {
        install_config_with_admin_default();
        let user = UserInfo {
            org_roles: HashMap::new(),
            ..user_with_role("user")
        };
        assert_eq!(
            role_for_org(&user, "acme"),
            UserRole::Admin,
            "an absent role is what the default is for"
        );
    }

    #[test]
    #[serial]
    fn a_valid_claim_role_is_kept() {
        install_config_with_admin_default();
        let user = user_with_role("viewer");
        assert_eq!(role_for_org(&user, "acme"), UserRole::Viewer);
    }

    #[test]
    #[serial]
    fn an_invalid_claim_role_is_denied_by_the_gate_and_stored_as_user() {
        // The two ends have to agree: the database must not hand out more
        // than the request gate allows.
        install_config_with_admin_default();
        let user = user_with_role("wizard");
        assert_eq!(role_for_org(&user, "acme"), UserRole::User);

        let mut parts = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/acme/streams/default")
            .body(())
            .expect("request must build")
            .into_parts()
            .0;
        let denied = crate::handlers::validate_user_info(&user, &mut parts)
            .expect_err("an unknown role must be rejected by the gate");
        assert_eq!(denied.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    #[serial]
    fn an_elevated_user_gets_admin_even_for_orgs_the_idp_never_claimed() {
        install_config_with_admin_default();
        let elevated = UserInfo {
            orgs: HashSet::from(["acme".to_string(), "other".to_string()]),
            org_roles: HashMap::from([
                ("acme".to_string(), "admin".to_string()),
                ("other".to_string(), "admin".to_string()),
            ]),
            ..user_with_role("viewer")
        };
        assert_eq!(role_for_org(&elevated, "other"), UserRole::Admin);
    }

    #[tokio::test]
    #[serial]
    async fn admin_org_disabled_leaves_the_user_view_unchanged() {
        install_config_with_admin_default();
        let user = user_with_role("viewer");
        let expected_orgs = user.orgs.clone();
        let expected_roles = user.org_roles.clone();
        let out = apply_admin_org_elevation(&user)
            .await
            .expect("no admin org configured must be a no-op");
        assert_eq!(out.orgs, expected_orgs);
        assert_eq!(out.org_roles, expected_roles);
    }
}
