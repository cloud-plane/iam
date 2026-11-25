package test_common_identity

import data.common.identity_domain

test_own_target_single_domain if {
	identity_domain.own_target with input as {"credentials": {"domain_id": "a"}, "target": {"user": {"domain_id": "a"}}}
	identity_domain.own_target with input as {"credentials": {"domain_id": "a"}, "existing": {"project": {"domain_id": "a"}}}
	not identity_domain.foreign_target with input as {"credentials": {"domain_id": "a"}, "target": {"user": {"domain_id": "a"}}}
}

test_foreign_target_single_domain if {
	identity_domain.foreign_target with input as {"credentials": {"domain_id": "a"}, "target": {"user": {"domain_id": "b"}}}
	not identity_domain.own_target with input as {"credentials": {"domain_id": "a"}, "target": {"user": {"domain_id": "b"}}}
}

# Fail-closed: when target and existing disagree on the domain the request
# is never "own" (the former complete rule raised a conflict instead).
test_mixed_domains_are_never_own if {
	mixed := {"credentials": {"domain_id": "a"}, "target": {"user": {"domain_id": "a"}}, "existing": {"user": {"domain_id": "b"}}}
	not identity_domain.own_target with input as mixed
	identity_domain.foreign_target with input as mixed
}

test_no_domain_is_neither_own_nor_foreign if {
	not identity_domain.own_target with input as {"credentials": {"domain_id": "a"}}
	not identity_domain.foreign_target with input as {"credentials": {"domain_id": "a"}}
	not identity_domain.own_target with input as {"credentials": {"domain_id": "a"}, "target": {"user": {"domain_id": null}}}
}
