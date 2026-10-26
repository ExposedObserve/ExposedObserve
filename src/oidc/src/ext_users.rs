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

use crate::{AuthError, models::UserInfo};

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

    let user_orgs = match check_and_create_user_orgs(user_info).await {
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
        check_and_update_orgs_users(user_info).await
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
        }
    }

    for org_name in user_orgs_to_add {
        let role = UserRole::from_str(
            user_info
                .org_roles
                .get(&org_name)
                .unwrap_or(&UserRole::User.to_string()),
        )
        .unwrap_or(UserRole::User);
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
        let role = match user_info.org_roles.get(org_id) {
            Some(str) => UserRole::from_str(str).unwrap_or(UserRole::User),
            None => UserRole::User,
        };
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
