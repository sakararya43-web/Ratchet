package ratchet.change

decision := {"outcome": "HOLD", "reasons": ["complete replayable context required"], "approver_groups": [], "quorum": 0} if {
 not input.complete
} else := {"outcome": "REJECT", "reasons": ["tier-0 safeguard weakening is prohibited"], "approver_groups": [], "quorum": 0} if {
 input.tier0_weakening
} else := {"outcome": "HOLD", "reasons": ["temporary and emergency grant execution requires expiry orchestration"], "approver_groups": [], "quorum": 0} if {
 input.intent.emergency
} else := {"outcome": "HOLD", "reasons": ["temporary grant execution requires expiry orchestration"], "approver_groups": [], "quorum": 0} if {
 input.intent.time_limit_seconds > 0
} else := {"outcome": "ALLOW", "reasons": ["authorized verified reduction"], "approver_groups": [], "quorum": 0} if {
 input.reduction
 input.authorized_responder
} else := {"outcome": "REQUIRE_APPROVAL", "reasons": ["new tier-0 authority requires two independent security leads"], "approver_groups": ["role:security-lead"], "quorum": 2} if {
 input.new_tier0
} else := {"outcome": "REQUIRE_APPROVAL", "reasons": ["independent resource owner approval required"], "approver_groups": ["resource-owner"], "quorum": 1} if {
 count(input.owners) > 0
} else := {"outcome": "HOLD", "reasons": ["resource ownership context required"], "approver_groups": [], "quorum": 0}
