# Distributed firewall

`flowplane`'s firewall is always-on and deny-by-default. It is enforced in the
datapath on every guest interface, in both directions, and derives entirely from
`FirewallPolicy` intent lowered by the control plane. There is no "firewall off" mode: a
packet is forwarded only when an explicit allow rule matches it.

## Deny-by-default

The datapath's evaluator, `flowplane_core::firewall::fw_classify` (`fw_classify6` for IPv6),
returns `ACCEPT` only when the rule that decides the packet is an allow. Every other outcome is
`DROP`:

- the interface has no firewall binding at all → drop;
- no rules in the packet's direction → drop;
- an unreadable inner header → drop;
- no rule matches → drop.

The drop is unconditional. This is a hard invariant of the datapath — the control plane is
responsible for materializing any "default-allow" behavior as explicit allow rules.

```mermaid
flowchart TD
    pkt["packet at interface (dir = ingress | egress)"] --> bind{"FW_BIND<br/>for ifindex?"}
    bind -->|none| drop["DROP"]
    bind -->|yes| scope{"scope for<br/>this dir?"}
    scope -->|none| drop
    scope -->|yes| hdr{"inner header<br/>readable?"}
    hdr -->|no| drop
    hdr -->|yes| class["peer address → class<br/>(longest prefix in the scope's class trie)"]
    class --> probe["policy trie, probed twice:<br/>[class, proto, port] and [any peer, proto, port]"]
    probe -->|higher-precedence entry| act["ACCEPT if that rule allows,<br/>else DROP"]
    probe -->|no entry| drop
```

A rule matches the packet's PEER — the source of an ingress packet, the destination of an egress
one — together with its protocol and destination port, or ICMP type and code. The first rule of
the interface's list that matches decides; the classifier answers exactly that in a constant
number of lookups, however many rules there are (see [The classifier](#the-classifier)).

## From FirewallPolicy to datapath

`FirewallPolicy` is a Kubernetes-native intent object with an `interfaceSelector`, an optional
`priority`, and `ingress` / `egress` rule lists. Each rule is a `{cidr, proto, port, action}`,
optionally narrowed by `endPort` (making `port`-`endPort` an inclusive range) or by `icmpType`
and `icmpCode`, and optionally ordered by its own `priority`:

```yaml
ingress:
  - { cidr: 10.0.0.0/8, proto: TCP, port: 8000, endPort: 8100, action: Allow }
  - { cidr: 10.0.0.0/8, proto: ICMP, icmpType: 8, action: Allow }              # echo request only
  - { cidr: 2001:db8::/32, proto: ICMP, icmpType: 1, icmpCode: 4, action: Deny } # ICMPv6 port unreachable
```
 The control plane compiles every policy that selects a NIC into one
first-match-wins rule list per direction, which the agent hands to the dataplane.

### Admission

The dispatch apiserver validates a `FirewallPolicy` on create and on every spec update:

- `interfaceSelector` is required and must parse (`{}` selects every interface in the
  namespace);
- `action` is `Allow` or `Deny`, `proto` is `TCP`, `UDP`, `ICMP` or empty (any);
- `port` is 0 (any) to 65535 and needs `proto` `TCP` or `UDP`; `endPort` needs a `port` and
  must not be below it;
- `icmpType` and `icmpCode` are 0 to 255, `icmpType` needs `proto` `ICMP`, and `icmpCode` needs
  `icmpType`. Both are the ICMPv6 values on an IPv6 CIDR;
- `cidr` is a CIDR with no host bits set: `10.0.0.5/24` is refused rather than read as
  either the `/24` or a typo for `/32`;
- both priorities are 0 to 65535.

`VPC.spec.defaultPolicy` must be `Allow` or `Deny` when set.

### The compiler: FirewallPolicy → CompiledNIC.Firewall

`CompileFirewall()` builds each NIC's rule lists in three steps.

1. **Order.** Every rule of every selecting policy is ranked by
   `(policy priority, rule priority, policy namespace, policy name, rule index)`, lower wins
   at each level. Priorities follow GCP: 0 to 65535, lower wins, and an unset priority is
   32768, so a policy or rule can be placed ahead of or behind every unprioritized one. With
   no priorities set, rules keep their list order within a policy and policies apply in name
   order. The ranking is total, so the compiled lists never depend on the order the apiserver
   lists policies in.
2. **Shadowing.** A rule that a higher-ranked rule fully covers can never be the first match,
   so it is dropped: its CIDR lies inside the other's, the other's proto is the same or any,
   and the other's port range contains its range (an unset port is the full range) or the
   other's ICMP type, and code, are unset or the same. Duplicates collapse the same way. Rules that only overlap partly are
   kept, since first match still decides between them. This follows Cilium's policy map
   discipline and gives the same result for any insertion order.
3. **Default posture.** The NIC's `VPC.spec.defaultPolicy` decides what happens to traffic no
   rule matches. The datapath drops it, so an open default is materialized as explicit allow
   rules, one for `0.0.0.0/0` and one for `::/0`:

    | `defaultPolicy` | Unmatched traffic | What the compiler adds |
    |---|---|---|
    | `Allow` | allowed | an allow-all pair below every rule, in both directions. A lone `Deny` rule then denies only what it matches. |
    | `Deny` | dropped, in both directions, on every interface | nothing |
    | unset | Kubernetes NetworkPolicy semantics, per direction | an allow-all pair in a direction with no rules. A direction with rules admits only what they allow, so a lone `Deny` there denies everything. |

    The VPC's `FirewallDefault` condition states which posture is in effect.

The direction that a peer CIDR describes follows k8s semantics, applied by the agent when
it lowers each `CompiledFwRule`:

- an ingress rule's CIDR is the source (who may reach us);
- an egress rule's CIDR is the destination;
- the port, or the `port`-`endPort` range, is always the destination port;
- `ICMP` means the ICMP of the CIDR's family, so it lowers to protocol 58 (ICMPv6) on an IPv6
  CIDR, and `icmpType`/`icmpCode` are matched against that family's messages.

### The rule budget and the FirewallCompiled condition

A NIC's firewall may hold 256 rules per address family, ingress and egress sharing the budget
(`FirewallRuleBudget`). Shadowed rules cost nothing; the allow-all pair a posture adds counts
like any other rule. The budget is a quota, not a datapath constant: it keeps policies far below
the dataplane's own limits (see [The classifier](#the-classifier)). The compiler enforces it.
When a NIC's rules exceed it in either family, or a rule stored before admission validation can't
be interpreted, the compiler does not guess:

- a NIC that already has a `CompiledNIC` keeps its last good rule set, since truncating
  could drop a `Deny` and emptying would cut a running workload off over an unrelated edit;
- a NIC compiling for the first time gets an empty rule set, which the datapath treats as
  deny-all.

Either way the NIC's `FirewallCompiled` condition turns `False`, with reason
`RuleBudgetExceeded` or `InvalidRule` and a message naming the family and count, or the
policy and rule. While compilation succeeds the condition is `True` and its message reports
budget use, for example `IPv4 2/256, IPv6 1/256`.

### The agent: CompiledNIC.Firewall → the dataplane

The agent is declarative. `ReconcileFirewall` computes the whole desired rule set for each
locally-attached interface and calls `ReplaceInterfaceFirewall`, a single gRPC that carries
the entire set. It holds no in-memory diff and never issues a per-rule delete; the dataplane
replaces the interface's rules wholesale, and cleanup happens through `DetachInterface`.
Failures are collected, not fatal, so the loop retries the interfaces that didn't land.

Each `CompiledFwRule` becomes one rule of the request with the proto number, destination-port
range, ICMP type and code, allow/deny bit and direction. On the wire `icmp_type` and `icmp_code`
are optional fields, since type 0 (echo reply) is a real selector; unset means any.

The dataplane replaces an interface's rules in both families or in neither: it compiles the whole
set before writing anything, and a set it refuses leaves the interface on its previous rules. An
unknown interface is `NOT_FOUND`; a rule the classifier cannot express (one that also restricts
the interface's own address, or a source port — neither can come from a `FirewallPolicy`) is
`INVALID_ARGUMENT`; a set too large for a scope is `RESOURCE_EXHAUSTED`. With the compiler
enforcing the budget, the last should not happen; it remains as a backstop.

## The classifier

The dataplane compiles each interface's rule list into two SCOPES, one per direction, each
holding both families. A scope is a pair of longest-prefix tries per family:

1. **Classes.** Every distinct peer prefix in the direction's rules becomes a class; a
   packet's peer address is classified by longest prefix. The any-peer `/0` is class 0 and never
   stored.
2. **Policy.** Each rule is expanded into every class its prefix covers, as entries keyed
   `[class, proto, port]` with the protocol and port as a maskable suffix: a port range becomes a
   handful of masked port prefixes, an ICMP rule keys its type and code in the port bytes. Each
   entry carries the rule's rank in the first-match list as its precedence. An expansion that a
   higher-ranked entry of the same class already covers is dropped, so the longest match in a
   class is always the first-match rule.

A packet probes the policy trie twice, with its class and with class 0, and the entry with the
higher precedence decides. The cost is a binding lookup, a class lookup and two probes whatever
the number of rules, so the datapath has no rule cap. Its limits are per scope: 4096 peer classes and
16384 policy entries per family, which the compiler checks before anything is written.

Scopes are content-addressed: interfaces with the same rules share one scope. Changing an
interface's rules builds the new scopes in full, then one `FW_BIND` write moves the interface to
them — both directions, both families at once — and a scope nothing references is deleted. The
bindings, scopes and epoch are pinned, so a dataplane restart keeps enforcing and re-adopts them.

A randomized differential test holds the classifier to first-match semantics: hundreds of rule
lists, each checked against the original first-match evaluator on every generated packet, in both
directions and both families.

## Connections and policy changes

The firewall is stateful. A flow's first packet meets the source interface's egress rules
and the destination interface's ingress rules; allowed, it is tracked in conntrack, and its
later packets and all of its replies ride that entry without being evaluated again. Replies
are allowed because their flow was: a guest never needs a rule for the return traffic of a
connection it opened, or of one it accepted.

A policy change reaches established connections on their next packet. The dataplane keeps a
node-wide firewall epoch and advances it whenever an interface's rules change; every
conntrack entry records the epoch it was last evaluated under. A packet that finds its flow
evaluated under an older epoch meets the current rules first, as a new flow would. If they
still allow it, the flow carries on and is re-stamped. If not, the packet is dropped and the
flow is forgotten, so its replies stop too. Replies are never re-evaluated on their own. No
conntrack sweep runs; the node's other connections each pay one extra evaluation, once.

A TCP SYN that lands on a tracked connection is a new connection reusing the port. It meets
the current rules even when no epoch has changed, so port reuse cannot inherit a verdict.

Hardware-offloaded connections (the `--offload` tier) never reach the evaluator. The offload
manager withdraws a connection whose epoch is stale, and its next packet takes the eBPF path.
For those connections a change takes effect within one reconcile interval rather than on the
next packet.

## The two-step: reachability vs. permission

Learning a route grants reachability, not firewall permission. These are two independent
gates a packet must pass:

1. Reachability: is there an overlay [route](routing-vni.md) to the destination? Routes
   are distributed by the route bus and may enter a tenant's table via VPC peering imports.
2. Permission: does an allow rule admit the packet? Allow rules come from `FirewallPolicy`
   and from the VPC's default posture, never from routing.

So importing a [peered VPC](vpc-peering.md)'s prefixes makes those destinations reachable
but grants nothing: traffic flows only where the destination's firewall already admits it.
Under `defaultPolicy: Deny`, or in a direction a policy governs, that takes a matching
`FirewallPolicy`. Likewise, [load-balancer](loadbalancer.md) membership is pure forwarding
data: a NIC being an LB backend adds no firewall rule (see below).

## Load-balanced traffic

Being a [load-balancer](loadbalancer.md) backend adds no firewall rule, so a backend admits LB
traffic only through its own ingress policy. Because a rule names the peer, that policy is
written for the clients, not for any address of the backend: an ingress rule allowing the
clients' source range (`0.0.0.0/0` and `::/0` for an internet-facing service) on the service
port admits the traffic. Neither the LB address nor the backend's overlay IP appears in the rule;
the destination address is never part of an ingress match.

(An earlier version of this page said a backend needed an `LB address:port` rule because of DSR.
That described the pre-classifier rule table, which could also match the local side; a
`FirewallPolicy` rule never could.)

## How it's wired

```
FirewallPolicy { interfaceSelector, priority, ingress[], egress[] }  + VPC.spec.defaultPolicy
        │  CompiledNICReconciler → CompileFirewall()
        │    · match selector → NIC labels
        │    · rank rules by priority, drop shadowed ones
        │    · add the default posture's allow-all pair
        │    · enforce the 256-per-family budget (else keep last good; report on the NIC)
        ▼
CompiledNIC.Spec.Firewall { Ingress[], Egress[] }
        │  agent.ReconcileFirewall() — whole desired set, per interface
        ▼
DataplaneNode gRPC: ReplaceInterfaceFirewall (per interface, whole rule set)
        │  compile into content-addressed scopes; create the missing ones;
        │  one FW_BIND write; bump the firewall epoch; free unreferenced scopes
        ▼
BPF maps: FW_BIND (ifindex → scopes), FW_CLASS{,6} / FW_POLICY{,6} (scope → tries), FW_EPOCH
        │
        ▼
datapath: fw_classify(pkt, ifindex, dir) → ACCEPT only if the deciding rule allows, else DROP
```

- CRD → compiler. `FirewallPolicy` selectors resolve to concrete, priority-ordered rules
  per NIC; the VPC's default posture decides where an explicit allow-all is added, so the
  deny-by-default datapath is only as permissive as the intent.
- Compiler → agent. The agent reads only `CompiledNIC.Spec.Firewall`, never the raw
  `FirewallPolicy`, and replaces each interface's whole rule set from it.
- Agent → dataplane. The dataplane compiles each interface's rules into its classifier scopes;
  `fw_classify` evaluates them on every new guest flow in both directions, and conntrack carries
  the flow from there (see [Connections and policy changes](#connections-and-policy-changes)).

## Related

- [Routing & multi-VNI tenancy](routing-vni.md) — the reachability half of the two-step.
- [Load balancing (Maglev + DSR)](loadbalancer.md) — backends admit LB clients through their own policy.
- [VPC peering](vpc-peering.md) — imports grant reachability, not permission.
- [Compilers: CompiledNIC](../architecture/compile-sync-materialize.md)
