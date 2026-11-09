package ratchet.authz

test_anonymous_cannot_submit if {
    not allow with input as {"operation": "submit", "actor": "", "actor_groups": [], "owners": []}
}

test_authenticated_requester_can_submit if {
    allow with input as {"operation": "submit", "actor": "requester", "actor_groups": [], "owners": []}
}

test_requester_cannot_approve_without_owner_membership if {
    not allow with input as {"operation": "approve", "actor": "requester", "actor_groups": [], "owners": ["owner"]}
}

test_resource_owner_can_review if {
    every operation in {"approve", "reject", "hold", "more_info"} {
        allow with input as {"operation": operation, "actor": "owner", "actor_groups": [], "owners": ["owner"]}
    }
}

test_only_security_lead_can_reduce if {
    not allow with input as {"operation": "reduce", "actor": "owner", "actor_groups": [], "owners": ["owner"]}
    allow with input as {"operation": "reduce", "actor": "lead", "actor_groups": ["role:security-lead"], "owners": []}
}

test_sensitive_operations_require_security_lead if {
    every operation in {"investigate", "policy_history", "containment_plan", "audit_export", "audit_query", "checkpoint_manage", "incident_manage", "incident_view", "restore", "drift_manage", "containment_execute"} {
        not allow with input as {"operation": operation, "actor": "owner", "actor_groups": [], "owners": ["owner"]}
        allow with input as {"operation": operation, "actor": "lead", "actor_groups": ["role:security-lead"], "owners": []}
    }
}

test_unknown_operation_is_denied_even_for_lead if {
    not allow with input as {"operation": "invented-admin-operation", "actor": "lead", "actor_groups": ["role:security-lead"], "owners": []}
}

test_missing_actor_is_denied if {
    not allow with input as {"operation": "submit"}
}
