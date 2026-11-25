# METADATA
# description: Core identity predicates and helper rules for Keystone4 policies
package common.identity

is_system_admin if {
	"admin" in input.credentials.roles
	input.credentials.system == "all"
}
