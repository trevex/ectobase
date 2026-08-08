---
name: feedback-dont-skip-tests
description: "User (2026-08-08): don't needlessly t.Skip tests — root-cause the failure and fix the underlying code; skipping needs evidence + human sign-off."
metadata:
  node_type: memory
  type: feedback
---

**User directive (2026-08-08):** "Please don't needlessly skip tests we should analyse what is wrong and potentially fix things."

**Why:** A `t.Skip` that hides a real datapath/logic defect makes the suite lie — it reads as "covered" when it isn't. The user wants failures diagnosed and the underlying code fixed, not routed around. This reinforces [[seam-not-duplicate-for-tests]] (never keep prod code that tests don't exercise) and the general "report outcomes faithfully" posture.

**How to apply:**
- Default outcome for any test is PASS. If it fails, root-cause it (logs, state dumps, packet captures pinpointing the drop) and fix the real code — that's in scope.
- A skip is a last resort requiring: (a) concrete evidenced root cause, (b) a finding that the fix is materially out of the current effort's scope, and (c) explicit human sign-off — escalate BLOCKED with the evidence rather than self-approving a skip.
- Never weaken/loosen assertions just to go green.
- Concrete trigger: the `TestLbDistributeSmoke` LB-datapath work in the retire-bash-clab effort (see [[retire-bash-clab-datapath-to-go]]) — the plan originally allowed a documented skip fallback; per this directive that's now BLOCKED-escalation-only.
