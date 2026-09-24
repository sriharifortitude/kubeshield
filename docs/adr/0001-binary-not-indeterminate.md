# 1. Every check is a plain pass/fail -- no third "indeterminate" outcome

Status: accepted — 2026-09-24

## Context

tfwarden (this portfolio's Terraform scanner) has a third result besides
Fail and Pass: Indeterminate, for a value Terraform has not resolved yet
(`after_unknown` in a plan). That distinction exists because a Terraform
*plan* is a prediction -- some attributes genuinely are not known until
`apply` actually runs.

A Kubernetes manifest is not a prediction. `securityContext.privileged`
either says `true`, says `false`, or is absent (which the API server
resolves to a concrete default the moment the object is created) --
there is no equivalent of "this will be computed later." Copying
tfwarden's three-way result into a tool that has no attribute which is
ever actually unknown would be adding a concept for its own sake, not
because the domain needs it.

## Decision

Every kubeshield rule returns Fail or Pass, and Pass is never asserted as
its own value -- it is simply the absence of a Finding, the same
convention tfwarden already uses for its own Pass case. Where Kubernetes
itself applies a default when a field is left unset (`allowPrivilegeEscalation`
defaults to `true`, not `false`), the rule treats "absent" as that real
default, not as "unknown" -- because it isn't unknown; the Kubernetes API
server's behaviour here is documented and fixed.

## Consequences

- The report format has two waiver-independent statuses (FAIL, and the
  absence of a row), not three -- one fewer state for a reader of the
  JSON or terminal output to reason about, because the domain has one
  fewer real state to represent.
- A rule author has to know, per field, whether "absent" means "the
  Kubernetes default applies" (most of this tool's fields) or would need
  its own explicit handling -- there is no attribute-agnostic shortcut,
  same discipline tfwarden's rules require, just without a bucket to
  fall back on if that discipline slips.
- What this does not solve: a manifest can still reference something
  that does not exist in the cluster it will be applied to (a ConfigMap,
  a StorageClass) -- kubeshield has no cluster connection and cannot
  know. That is a different kind of unknown (missing dependency, not
  unresolved value) and is out of scope entirely, not represented as a
  result at all.
