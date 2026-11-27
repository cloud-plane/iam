# METADATA
# description: Policy for reading one OAuth2 session (refresh token family)
package identity.oauth2.session.show

# Read one refresh token family of a user. Also invoked by
# `identity/oauth2/session/list` for every family it returns, so a listed
# family is shown only to a caller that may read it.
#
# input.existing.oauth2_session.domain_id: string  Owning domain of the family.
# input.target: null.
#
# A system admin may read in any domain; a domain `manager` only in the
# domain the token is scoped to.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	input.existing.oauth2_session.domain_id == input.credentials.domain_id
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": msg} if {
	input.existing.oauth2_session.domain_id != input.credentials.domain_id
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "reading OAuth2 sessions in another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	input.existing.oauth2_session.domain_id == input.credentials.domain_id
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "reading OAuth2 sessions requires `manager` role."
}
