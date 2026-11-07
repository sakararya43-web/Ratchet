package ratchet.change

decision := {"outcome": "HOLD", "reasons": ["complete replayable context required"], "approver_groups": [], "quorum": 0} if {
 not input.complete
} else := {"outcome": "REJECT", "reasons": ["tier-0 safeguard weakening is prohibited"], "approver_groups": [], "quorum": 0} if {
 input.tier0_weakening
} else := {"outcome": "HOLD", "reasons": ["emergency access requires a fixed duration"], "approver_groups": [], "quorum": 0} if {
 input.intent.emergency
 input.intent.time_limit_seconds <= 0
} else := {"outcome": "HOLD", "reasons": ["explicit resources and permissions required for temporary access"], "approver_groups": [], "quorum": 0} if {
 input.scope.complete == false
} else := {"outcome": "HOLD", "reasons": ["role exceeds explicitly requested resources or permissions"], "approver_groups": [], "quorum": 0} if {
 input.scope.over_broad
} else := {"outcome": "ALLOW", "reasons": ["authorized verified reduction"], "approver_groups": [], "quorum": 0} if {
 input.reduction
 input.authorized_responder
 input.intent.incident_id == ""
} else := {"outcome": "REQUIRE_APPROVAL", "reasons": ["new tier-0 authority requires two independent security leads"], "approver_groups": ["role:security-lead"], "quorum": 2} if {
 input.new_tier0
} else := {"outcome": "REQUIRE_APPROVAL", "reasons": ["independent resource owner approval required"], "approver_groups": ["resource-owner"], "quorum": 1} if {
 count(input.owners) > 0
} else := {"outcome": "HOLD", "reasons": ["resource ownership context required"], "approver_groups": [], "quorum": 0}
