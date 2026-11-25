# METADATA
# title: Show role
# description: Policy for fetching a single role
package identity.role.show

import data.common.identity_role

# Show role.
#
# The `input.existing.role` is the stored role object (Role):
#   description:  string (optional)  Role description.
#   domain_id:    string (optional)  Role domain ID.
#   id:           string            Role ID.
#   name:         string            Role name.
#
# The `input.target` is null
#
default allow := false

# METADATA
# description: "`Admin` is allowed by default"
allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "`Manager` is allowed for global roles and roles belonging to the scope domain."
allow if {
	"manager" in input.credentials.roles
	identity_role.own_role_or_global_role
}
