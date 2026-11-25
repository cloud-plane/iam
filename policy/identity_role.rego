# METADATA
# description: Role scoping predicates
package common.identity_role

# A role without a domain_id (orphaned).
# For create/update: in input.target.role.
# For show/delete: in input.existing.role.
orphaned_role if {
	input.target.role.domain_id == null
}

orphaned_role if {
	input.existing.role.domain_id == null
}

global_role if {
	orphaned_role
}

# A role with a domain matching the caller's domain scope.
# For create/update: in input.target.role.
# For show/delete: in input.existing.role.
own_role if {
	input.target.role.domain_id != null
	input.credentials.domain_id == input.target.role.domain_id
}

own_role if {
	input.existing.role.domain_id != null
	input.credentials.domain_id == input.existing.role.domain_id
}

# Domain role or the global role.
own_role_or_global_role if {
	global_role
}

own_role_or_global_role if {
	own_role
}

# Roles a domain manager is allowed to delegate (mirrors the Python Keystone
# `domain_managed_target_role` rule): only manager, member and reader.
# For grant/revoke the role is in input.target.role (or input.existing.role).
domain_managed_target_role if {
	input.target.role.name in {"manager", "member", "reader"}
}

domain_managed_target_role if {
	input.existing.role.name in {"manager", "member", "reader"}
}
