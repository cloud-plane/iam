# METADATA
# title: Revocation freshness helper
# description: >
#   Shared predicate for the policies of sensitive actions (ADR 0045 section 9).
#   A token issued by another authority is only as revoked as the revocation
#   stream from that authority is fresh. When keystone has not heard from the
#   stream within `[revoke] revocation_max_staleness` (30 seconds by default) it
#   sets `input.credentials.revocation_stale`, and every policy that imports
#   this helper denies. Reads and low-risk actions keep working during a
#   partition; the rules that gate the sensitive ones add `fresh`.
package common.revocation

# METADATA
# description: >
#   True unless keystone marked the revocation state behind the caller's token
#   as stale. A missing flag means the token is of this authority, whose
#   revocations are always current.
fresh if {
	not input.credentials.revocation_stale
}
