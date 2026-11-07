package ratchet.change

base := {
    "complete": true,
    "tier0_weakening": false,
    "intent": {"emergency": false, "time_limit_seconds": 3600, "incident_id": ""},
    "scope": {"complete": true, "over_broad": false},
    "reduction": false,
    "authorized_responder": false,
    "new_tier0": false,
    "owners": ["owner:alice"],
}

test_incomplete_context_precedes_even_authorized_reduction if {
    request := object.union(base, {"complete": false, "reduction": true, "authorized_responder": true})
    decision.outcome == "HOLD" with input as request
}

test_safeguard_weakening_cannot_be_approved if {
    request := object.union(base, {"tier0_weakening": true, "new_tier0": true})
    decision.outcome == "REJECT" with input as request
}

test_unbounded_emergency_is_held if {
    request := object.union(base, {"intent": {"emergency": true, "time_limit_seconds": 0, "incident_id": ""}})
    decision.outcome == "HOLD" with input as request
}

test_missing_scope_is_held if {
    request := object.union(base, {"scope": {"complete": false, "over_broad": false}})
    decision.outcome == "HOLD" with input as request
}

test_overbroad_scope_is_held if {
    request := object.union(base, {"scope": {"complete": true, "over_broad": true}})
    decision.outcome == "HOLD" with input as request
}

test_authorized_reduction_without_incident_is_allowed if {
    request := object.union(base, {"reduction": true, "authorized_responder": true})
    decision == {"outcome": "ALLOW", "reasons": ["authorized verified reduction"], "approver_groups": [], "quorum": 0} with input as request
}

test_unauthorized_reduction_still_requires_owner if {
    request := object.union(base, {"reduction": true})
    decision.outcome == "REQUIRE_APPROVAL" with input as request
    decision.quorum == 1 with input as request
}

test_incident_context_cannot_bypass_approval if {
    request := object.union(base, {"reduction": true, "authorized_responder": true, "intent": {"emergency": false, "time_limit_seconds": 3600, "incident_id": "incident:1"}})
    decision.outcome == "REQUIRE_APPROVAL" with input as request
}

test_new_tier0_requires_two_security_leads if {
    request := object.union(base, {"new_tier0": true})
    result := decision with input as request
    result.outcome == "REQUIRE_APPROVAL"
    result.quorum == 2
    result.approver_groups == ["role:security-lead"]
}

test_normal_change_requires_owner if {
    result := decision with input as base
    result.outcome == "REQUIRE_APPROVAL"
    result.quorum == 1
    result.approver_groups == ["resource-owner"]
}

test_missing_owner_is_held if {
    request := object.union(base, {"owners": []})
    decision.outcome == "HOLD" with input as request
}
