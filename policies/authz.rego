package ratchet.authz

default allow := false

allow if {
 input.operation in {"investigate", "policy_history", "containment_plan"}
 "role:security-lead" in input.actor_groups
}

allow if {
 input.operation == "reduce"
 "role:security-lead" in input.actor_groups
}

allow if {
 input.operation in {"submit", "view", "simulate"}
 input.actor != ""
}

allow if {
 input.operation in {"approve", "reject", "hold", "more_info"}
 "role:security-lead" in input.actor_groups
}

allow if {
 input.operation in {"approve", "reject", "hold", "more_info"}
 input.actor in input.owners
}
