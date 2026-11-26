package test_common_revocation

import data.common.revocation

test_fresh_without_the_flag if {
	revocation.fresh with input as {"credentials": {}}
}

test_fresh_when_false if {
	revocation.fresh with input as {"credentials": {"revocation_stale": false}}
}

test_not_fresh_when_stale if {
	not revocation.fresh with input as {"credentials": {"revocation_stale": true}}
}
