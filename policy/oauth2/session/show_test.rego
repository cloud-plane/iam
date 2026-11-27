package test_oauth2_session_show

import data.identity.oauth2.session.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"oauth2_session": {"domain_id": "foo"}}}
	show.allow with input as {"credentials": {"roles": [], "is_admin": true}, "existing": {"oauth2_session": {"domain_id": "foo"}}}
	show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_session": {"domain_id": "foo"}}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}, "existing": {"oauth2_session": {"domain_id": "foo"}}}
	not show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_session": {"domain_id": "bar"}}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"oauth2_session": {"domain_id": "foo"}}}
}
