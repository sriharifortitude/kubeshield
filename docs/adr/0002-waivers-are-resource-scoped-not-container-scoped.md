# 2. A waiver covers a whole resource, not one container inside it

Status: accepted — 2026-09-24

## Context

Several rules (`privileged-container`, `run-as-root`, `missing-resource-limits`, ...)
are findings about one container within a Pod/Deployment/StatefulSet/etc,
not about the resource as a whole -- a multi-container Pod could have one
container that is fine and a sidecar that genuinely needs a waiver. The
finest-grained waiver would therefore key on rule + kind + namespace +
name + *container*.

## Decision

A waiver entry matches on rule, kind, namespace and name -- not
container. Accepting the coarser grain was a deliberate trade against
container-level precision, for a concrete reason: a waiver is something
a reviewer signs off on, and "this resource, this rule, here is why" is
what gets approved in practice (a PR review, a security exception
ticket). "This resource, this rule, but *only* for the container named
`log-shipper`, not the other two containers in the same pod spec that
happen to share the name `privileged-container` finding" is a much
harder thing for a human to verify at a glance, and a much easier place
for a waiver to silently cover more than its author intended if a
container gets renamed or a new one is added later with the same rule
violation.

## Consequences

- If a Pod has two containers both triggering `run-as-root`, one waiver
  entry (rule + kind + namespace + name) suppresses the finding for
  both. A team that genuinely wants per-container granularity has to
  split the workload into separate resources, or accept the coarser
  grain -- this is a real limitation, stated here and in the README, not
  hidden as an edge case.
- Conversely, a new container added later to an already-waived resource
  inherits the waiver for that rule automatically. This is the correct
  default for how manifests actually evolve (a sidecar added to an
  already-reviewed Deployment is still part of the same reviewed
  resource) but it does mean a waiver's scope can grow without the
  waiver file itself changing -- worth knowing before waiving broadly on
  a resource that changes often.
- `report.Row`'s underlying `rules.Finding` still carries the container
  name and shows it in every output format, so a reviewer reading the
  report always sees exactly which container triggered a still-failing
  or still-waived finding, even though the waiver itself cannot target
  one.
