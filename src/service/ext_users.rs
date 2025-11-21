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

/// Module for handling external user authentication and organization management.
///
/// This module provides functionality to check, create, and update external users
/// (typically from OIDC providers) in the system, including managing their
/// organization memberships and roles.
use std::str::FromStr;

use config::meta::user::{DBUser, UserOrg, UserRole};
use oidc::models::UserInfo;

use crate::{
    common::meta::organization::Organization,
    service::{db, organization, users},
};

/// Checks if a user with the given email is a member of the specified organization.
///
/// # Arguments
/// * `email` - The user's email address
/// * `org_id` - The organization identifier to check membership for
///
/// # Returns
/// Returns `Some(Organization)` if the user is a member, `None` otherwise.
pub async fn check_user_in_org(email: &str, org_id: &String) -> Option<Organization> {
    let orgs = organization::list_orgs_by_user(email)
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
        .find(|org| org.identifier.eq_ignore_ascii_case(org_id))
}

/// Synchronizes user information from external authentication provider (OIDC).
///
/// This function checks if the user exists in the database. If not, it creates a new user.
/// If the user exists, it updates their organization memberships based on the provided info.
///
/// # Arguments
/// * `user_info` - User information from the OIDC provider
///
/// # Returns
/// Returns `true` if the operation was successful, `false` otherwise.
pub async fn sync_user_info(user_info: &UserInfo) -> bool {
    let name = user_info.sub.trim();
    let (first_name, last_name) = name.split_once(' ').unwrap_or((name, ""));
    let user_email = user_info.email.as_str();
    let db_user = db::user::get_user_by_email(user_email).await;
    // Check and create Orgs
    let user_orgs = check_and_create_user_orgs(user_info).await.unwrap();
    if db_user.is_none() {
        // Create new user
        return add_new_user(user_email, first_name, last_name, user_orgs).await;
    } else {
        // Update user orgs
        return check_and_update_orgs_users(user_info).await;
    };
}

async fn check_and_update_orgs_users(user_info: &UserInfo) -> bool {
    let email = user_info.email.as_str();
    let current_orgs = match organization::list_orgs_by_user(email).await {
        Ok(orgs) => orgs,
        Err(err) => {
            log::error!("Failed to get user: {} orgs\n{}", email, err);
            return false;
        }
    };

    // Collect current org names for efficient lookup
    let current_org_names: std::collections::HashSet<String> = current_orgs.iter().map(|o| o.name.clone()).collect();

    // Determine orgs to add: those in user_info.orgs but not in current orgs
    let user_orgs_to_add: std::collections::HashSet<String> = user_info.orgs.difference(&current_org_names).cloned().collect();

    // Remove user from orgs they no longer belong to
    for org in current_orgs {
        let org_name = &org.name;
        if !user_info.orgs.contains(org_name) {
            match db::org_users::remove(&org.identifier, email).await {
                Ok(()) => {
                    log::info!("User: {} removed from org: {}", email, org_name);
                }
                Err(err) => {
                    log::error!(
                        "Failed to remove user: {} from org: {}\n{}",
                        email,
                        org_name,
                        err
                    );
                    return false;
                }
            }
        }
    }

    // Add user to new orgs
    for org_name in user_orgs_to_add {
        let role = UserRole::from_str(
            user_info
                .org_roles
                .get(&org_name)
                .unwrap_or(&UserRole::User.to_string()),
        )
        .unwrap();
        match db::org_users::add(&org_name, email, role, "", None).await {
            Ok(()) => {
                log::info!("User: {} successfully added to org: {}", email, &org_name);
            }
            Err(err) => {
                log::error!(
                    "Failed to add user: {} to org: {}\n{}",
                    email,
                    &org_name,
                    err
                );
                return false;
            }
        }
    }
    true
}

async fn add_new_user(
    email: &str,
    first_name: &str,
    last_name: &str,
    user_orgs: Vec<UserOrg>,
) -> bool {
    match users::create_new_user(DBUser {
        email: email.to_string(),
        first_name: first_name.to_string(),
        last_name: last_name.to_string(),
        password: "".to_owned(),
        salt: "".to_owned(),
        organizations: user_orgs,
        is_external: true,
        password_ext: None,
    })
    .await
    {
        Ok(_) => {
            log::info!("User {} added to the database", email);
            return true;
        }
        Err(e) => {
            log::error!("Failed to add user: {} to the database\n{}", email, e);
            return false;
        }
    };
}

async fn check_and_create_user_orgs(user_info: &UserInfo) -> Result<Vec<UserOrg>, anyhow::Error> {
    let mut result = Vec::new();
    for item in &user_info.orgs {
        let org_id = item.as_str();
        let org = match organization::check_and_create_org(org_id).await {
            Ok(org) => {
                log::info!("Organization: {} created successfully", org_id);
                org
            }
            Err(e) => {
                log::error!("Error creating organization: {}\n{}", org_id, e);
                return Err(e);
            }
        };
        let role = match user_info.org_roles.get(org_id) {
            Some(str) => UserRole::from_str(str).unwrap(),
            None => UserRole::User,
        };
        let user_org = UserOrg {
            name: org.name,
            token: String::new(),
            rum_token: None,
            role,
        };
        result.push(user_org);
    }
    return Ok(result);
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::LazyLock,
    };

    use config::meta::user::{UserRole, UserType};
    use infra::{
        db::{self as infra_db, ORM_CLIENT, connect_to_orm},
        table::{self as infra_table, org_users::OrgUserRecord},
    };
    use oidc::models::UserInfo;
    use rand::prelude::*;
    use tokio::sync::Mutex;

    use super::*;
    use crate::{
        common::infra::config::{ORG_USERS, USERS},
        service,
    };

    fn generate_password() -> String {
        rand::rng()
            .sample_iter(&rand::distr::Alphanumeric)
            .take(16)
            .map(char::from)
            .collect()
    }

    static TEST_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    async fn set_up() -> tokio::sync::MutexGuard<'static, ()> {
        let guard = TEST_MUTEX.lock().await;

        let _ = ORM_CLIENT.get_or_init(connect_to_orm).await;
        // clear the table here as previous tests could have written to it
        let _ = infra::table::org_users::clear().await;
        let _ = infra::table::users::clear().await;
        let _ = infra::table::organizations::clear().await;
        let _ = infra_db::create_table().await;
        let _ = infra_table::create_user_tables().await;
        // Clear global caches to ensure test isolation
        USERS.clear();
        ORG_USERS.clear();

        USERS.insert(
            "admin@zo.dev".to_string(),
            infra::table::users::UserRecord {
                email: "admin@zo.dev".to_string(),
                password: "pass#123".to_string(),
                salt: String::new(),
                first_name: "admin".to_owned(),
                last_name: "".to_owned(),
                password_ext: Some("pass#123".to_string()),
                user_type: UserType::Internal,
                is_root: false,
                created_at: 0,
                updated_at: 0,
            },
        );
        ORG_USERS.insert(
            "dummy/admin@zo.dev".to_string(),
            OrgUserRecord {
                role: UserRole::Admin,
                token: "token".to_string(),
                rum_token: Some("rum_token".to_string()),
                org_id: "dummy".to_string(),
                email: "admin@zo.dev".to_string(),
                created_at: 0,
            },
        );

        guard
    }

    #[tokio::test]
    async fn test_check_nonexistent_user_in_org() {
        let _guard = set_up().await;

        let email = "nonexistent@zo.dev";
        let get_user_by_email = db::user::get_user_by_email(email).await;
        assert!(
            get_user_by_email.is_none(),
            "User should not exist in the database"
        );
        // Test user in org
        let result = check_user_in_org(email, &"org1".to_string()).await;
        assert!(
            result.is_none(),
            "Non-existent user should not be in any org"
        );
    }
    #[tokio::test]
    async fn test_check_existent_without_orgs_user_in_org() {
        let _guard = set_up().await;

        let email = "almostexistent@zo.dev";
        db::user::add(&DBUser {
            email: email.to_string(),
            first_name: "Sam".to_string(),
            last_name: "Wheat".to_string(),
            password: generate_password(),
            salt: "".to_string(),
            organizations: vec![],
            is_external: false,
            password_ext: None,
        })
        .await.expect("Sam should be created successfully");

        let result = check_user_in_org(email, &"org1".to_string()).await;
        assert!(result.is_none(), "Sam without orgs should not be in any org");
    }

    #[tokio::test]
    async fn test_sync_user_info_new_user() {
        let _guard = set_up().await;

        let user_info = UserInfo {
            sub: "Molly Jensen".to_string(),
            email: "newuser@zo.dev".to_string(),
            orgs: HashSet::from(["org1".to_string(), "org2".to_string()]),
            org_roles: HashMap::new(),
            is_internal: false,
        };

        let result = sync_user_info(&user_info).await;
        assert!(result, "sync_user_info should succeed for Molly");

        // Verify user was created
        let db_user = db::user::get_user_by_email("newuser@zo.dev").await;
        assert!(db_user.is_some(), "Molly should exist in the database");
        let user = db_user.unwrap();
        assert_eq!(user.first_name, "Molly");
        assert_eq!(user.last_name, "Jensen");
        assert!(user.is_external, "Molly should be marked as external");
    }

    #[tokio::test]
    async fn test_sync_user_info_existing_user() {
        let _guard = set_up().await;

        let old_org = "old";
        service::organization::check_and_create_org(old_org)
            .await
            .expect("Org 'old' should be created successfully");

        let email = "existing@zo.dev";

        users::create_new_user(DBUser {
            email: email.to_string(),
            first_name: "Oda".to_string(),
            last_name: "Mae Brown".to_string(),
            password: generate_password(),
            salt: "".to_string(),
            organizations: vec![UserOrg {
                name: old_org.to_string(),
                token: String::new(),
                rum_token: None,
                role: UserRole::User,
            }],
            is_external: true,
            password_ext: None,
        })
        .await
        .expect("Oda should be created successfully");

        let new_org = "new";
        let org = organization::get_org(new_org).await;
        assert!(org.is_none(), "Org 'new' should not exist yet");

        let orgs = organization::list_orgs_by_user(email)
            .await
            .expect("Should fetch orgs successfully");

        assert!(
            orgs.iter().any(|o| o.name == old_org),
            "Oda should be in the 'old' org"
        );
        assert!(
            !orgs.iter().any(|o| o.name == new_org),
            "Oda should not be in the 'new' org yet"
        );

        let user_info = UserInfo {
            sub: "Oda Mae Brown".to_string(),
            email: "existing@zo.dev".to_string(),
            orgs: HashSet::from([new_org.to_string()]),
            org_roles: HashMap::new(),
            is_internal: false,
        };
        let result = sync_user_info(&user_info).await;
        assert!(result, "sync_user_info should succeed for existing user");

        let org = organization::get_org(new_org).await;
        assert!(org.is_some(), "Org 'new' should be created");

        let orgs = organization::list_orgs_by_user("existing@zo.dev")
            .await
            .expect("Should fetch orgs successfully");

        assert!(
            orgs.iter().any(|o| o.name == new_org),
            "Oda should now be in the 'new' org"
        );
        assert!(
            !orgs.iter().any(|o| o.name == old_org),
            "Oda should no longer be in the 'old' org"
        );
    }
}
