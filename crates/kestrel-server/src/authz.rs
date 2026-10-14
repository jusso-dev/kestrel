//! Role checks. Host-group scope is applied by repository queries and the
//! metric proxy, not by skipping the permission check.

use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    SessionUse,
    HostRead,
    HostWrite,
    GroupRead,
    GroupWrite,
    TriggerRead,
    TriggerWrite,
    ProblemRead,
    ProblemAck,
    ActionRead,
    ActionWrite,
    UserRead,
    AdminUsers,
    MediaRead,
    MediaWrite,
    DashboardRead,
    DashboardWrite,
    TemplateRead,
    TemplateWrite,
    MaintenanceRead,
    MaintenanceWrite,
    AuditRead,
    MetricsRead,
    TenantRead,
    TenantAdmin,
    MspRead,
    OtlpWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    Public,
    Agent,
    User(Permission),
}

/// `None` means every host group in the tenant. `Some` is an allow-list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub tenant_id: Uuid,
    pub groups: Option<Vec<Uuid>>,
}

pub fn role_allows(role: &str, permission: Permission) -> bool {
    let read = matches!(
        permission,
        Permission::SessionUse
            | Permission::HostRead
            | Permission::GroupRead
            | Permission::TriggerRead
            | Permission::ProblemRead
            | Permission::ActionRead
            | Permission::UserRead
            | Permission::MediaRead
            | Permission::DashboardRead
            | Permission::TemplateRead
            | Permission::MaintenanceRead
            | Permission::AuditRead
            | Permission::MetricsRead
            | Permission::TenantRead
    );
    match role {
        "owner" => true,
        "admin" => !matches!(permission, Permission::TenantAdmin),
        "operator" => {
            read || matches!(
                permission,
                Permission::ProblemAck | Permission::DashboardWrite | Permission::OtlpWrite
            )
        }
        "viewer" => read,
        _ => false,
    }
}

pub fn scope_for(tenant_id: Uuid, role: &str, host_group_id: Option<Uuid>) -> Scope {
    let groups = if matches!(role, "owner" | "admin") {
        None
    } else {
        host_group_id.map(|id| vec![id])
    };
    Scope { tenant_id, groups }
}

pub fn group_visible(scope: &Scope, host_group_id: Option<Uuid>) -> bool {
    match &scope.groups {
        None => true,
        Some(groups) => host_group_id.is_some_and(|id| groups.contains(&id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authz_viewer_cannot_write_and_operator_can_ack() {
        assert!(role_allows("viewer", Permission::HostRead));
        assert!(!role_allows("viewer", Permission::HostWrite));
        assert!(!role_allows("viewer", Permission::ProblemAck));
        assert!(!role_allows("viewer", Permission::AdminUsers));
        assert!(role_allows("operator", Permission::ProblemAck));
        assert!(!role_allows("operator", Permission::TriggerWrite));
        assert!(role_allows("admin", Permission::AdminUsers));
        assert!(!role_allows("admin", Permission::TenantAdmin));
        assert!(role_allows("owner", Permission::TenantAdmin));
        assert!(!role_allows("nope", Permission::HostRead));
    }

    #[test]
    fn authz_scope_hides_other_groups() {
        let group = Uuid::from_u128(7);
        let other = Uuid::from_u128(8);
        let scope = scope_for(Uuid::from_u128(1), "operator", Some(group));
        assert!(group_visible(&scope, Some(group)));
        assert!(!group_visible(&scope, Some(other)));
        assert!(!group_visible(&scope, None));
        let owner = scope_for(Uuid::from_u128(1), "owner", Some(group));
        assert!(owner.groups.is_none());
        assert!(group_visible(&owner, Some(other)));
    }
}
