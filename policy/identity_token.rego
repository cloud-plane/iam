# METADATA
# description: Token ownership predicates
package common.identity_token

token_subject if {
	input.credentials.user_id == input.target.token.user.id
}

token_subject if {
	input.credentials.user_id == input.existing.token.user.id
}
