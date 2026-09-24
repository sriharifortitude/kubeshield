# kubeshield

[![CI](https://github.com/sriharifortitude/kubeshield/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/kubeshield/actions/workflows/ci.yml)

A Kubernetes manifest security scanner: ten checks for the pod-security
and RBAC misconfigurations that turn a compromised container into a
compromised node, or a compromised node into a compromised cluster --
privileged containers, host namespace sharing, hostPath volumes,
wildcard RBAC, unpinned images, missing resource limits. Reads plain
YAML (raw manifests, or `helm template` output piped in on stdin), not a
live cluster -- see [ADR 1](docs/adr/0001-binary-not-indeterminate.md)
for why that also means no third "maybe" result the way this
portfolio's Terraform scanner has.

```
$ kubeshield scan --waivers testdata/waivers.yaml testdata/small.yaml

EXPIRED       prod/Pod/debug-tool            CRITICAL spec.hostNetwork is true
              fix: remove hostNetwork, or set it to false
              WAIVER EXPIRED 2025-01-01: was meant to be temporary while the sidecar proxy was being set up
FAIL          ClusterRole/everything         CRITICAL rules[0] uses a wildcard "*" in verbs and resources and apiGroups
              fix: list the specific verbs, resources and API groups the workload actually needs instead of "*"
waived        prod/Pod/legacy-worker (worker) MEDIUM   runAsNonRoot is not set to true, at either the container or pod level
              waived 2030-01-01: pre-dates the policy, migration ticket JIRA-1
FAIL          prod/Deployment/web (app)      MEDIUM   image "example/web:latest" uses the "latest" tag
              fix: pin the image to a digest (image@sha256:...) or at minimum a specific version tag, never :latest or an untagged reference
FAIL          prod/Deployment/web (app)      MEDIUM   resources.limits has neither cpu nor memory set
              fix: set resources.limits.cpu and resources.limits.memory
FAIL          prod/Deployment/web (app)      CRITICAL securityContext.privileged is true
              fix: remove securityContext.privileged, or set it to false explicitly
FAIL          prod/Deployment/web (app)      MEDIUM   runAsNonRoot is not set to true, at either the container or pod level
              fix: set securityContext.runAsNonRoot: true (at the container or pod level)

7 findings: 5 failing, 1 waived, 1 expired waivers
$ echo $?
1
```

(Real output from `testdata/small.yaml` and `testdata/waivers.yaml` in
this repository, checked in CI against these exact strings -- run it
yourself with the command above. `testdata/small.yaml` also has a fully
clean `Deployment/api`, which produces nothing: this tool only ever
tells you about a problem, never about the absence of one.)

## The checks

| rule | severity | what it catches |
| --- | --- | --- |
| `privileged-container` | Critical | `securityContext.privileged: true` |
| `host-namespace` | Critical | `hostNetwork`, `hostPID` or `hostIPC: true` on the pod spec |
| `dangerous-capabilities-added` | Critical | `capabilities.add` including `ALL`, `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `SYS_RAWIO` or `DAC_READ_SEARCH` |
| `rbac-wildcard` | Critical | a Role/ClusterRole rule with `"*"` in `verbs`, `resources` or `apiGroups` |
| `hostpath-volume` | High | a volume of type `hostPath` |
| `allow-privilege-escalation` | High | `allowPrivilegeEscalation` left unset (Kubernetes defaults it to `true`) or explicitly `true` |
| `run-as-root` | Medium | `runAsNonRoot` not set to `true`, at the container or pod level |
| `missing-resource-limits` | Medium | no `resources.limits.cpu` or no `resources.limits.memory` |
| `image-not-pinned` | Medium | an image with no tag, the `latest` tag, or no digest |
| `read-only-root-filesystem-missing` | Low | `readOnlyRootFilesystem` not set to `true` |

Every finding names the exact evidence and the exact container (when the
finding is container-scoped), never just the workload, and carries a
one-line fix. `docs/adr/` explains the two decisions that most shape the
design.

## Waivers

Accepted risk is named per rule and per resource (kind, namespace, name
-- not per container; see
[ADR 2](docs/adr/0002-waivers-are-resource-scoped-not-container-scoped.md)
for why), with a reason and an expiry date, all four required. An
expired waiver stops suppressing its finding and shows as `WAIVER
EXPIRED`, still failing the gate:

```yaml
waivers:
  - rule: run-as-root
    kind: Pod
    namespace: prod
    name: legacy-worker
    reason: pre-dates the policy, migration ticket JIRA-1
    expires: "2030-01-01"
```

## Output formats and exit codes

`--format terminal|json|sarif`, `--output FILE`, `--fail-on
low|medium|high|critical` (default `low`). SARIF results carry a file
location and a logical location naming the resource, not a line number
-- `internal/manifest` decodes into plain maps rather than
position-tracking `yaml.Node`s, so it has no line to report. Stated as a
real limitation, not silently worked around with a fake line 1.

| exit code | meaning |
| --- | --- |
| 0 | nothing failing at or above `--fail-on` |
| 1 | at least one finding does (an expired waiver counts) |
| 2 | the path/stdin couldn't be read or parsed, or no manifest was found |

## Running it

    go install github.com/sriharifortitude/kubeshield/cmd/kubeshield@v0.1.0
    kubeshield scan ./deploy
    helm template mychart | kubeshield scan -

A path may be a single file or a directory, walked recursively for
`.yaml`/`.yml` files; `-` reads stdin, for piping in `helm template` or
`kustomize build` output directly.

Or the image: `docker run --rm -v "$PWD:/w" ghcr.io/sriharifortitude/kubeshield:0.1 scan /w/deploy`.

## Checks

    go build ./... && go vet ./... && staticcheck ./...
    go test ./... -race -cover

45 tests: `internal/manifest` parses real multi-document YAML, including
every pod-spec nesting depth (`Pod` direct, `Deployment`/`StatefulSet`/
etc under `.spec.template.spec`, `CronJob` nested twice under
`.spec.jobTemplate.spec.template.spec`); `internal/rules` builds
resources from real YAML fixtures (not hand-built Go maps) for every
rule's fail/pass edges, including run-as-root's pod-level security
context fallback and image-not-pinned's registry-port-vs-tag ambiguity;
`internal/waiver` and `internal/report` are hand-verified against exact
text; `cmd/kubeshield` runs the whole pipeline against real files and a
real directory tree.

## What it deliberately does not do

- **No live cluster connection.** It reads manifests, never `kubectl
  get`. It cannot see admission-controller policy already enforced
  cluster-wide, a NetworkPolicy default-deny at the namespace level, or
  anything else that exists outside the files it was given.
- **No cross-resource or cross-namespace checks**, such as "does this
  namespace have a default-deny NetworkPolicy" -- a partial set of
  manifests can't honestly answer a question that depends on knowing
  every resource in a namespace, so this tool doesn't ask it.
- **Ten checks, not the whole CIS Kubernetes Benchmark.** Depth over
  coverage, the same bet the rest of this portfolio makes.
- **Waivers are resource-scoped, not container-scoped** (ADR 2) -- a
  stated trade-off, not an oversight.
- **No remediation applied.** It tells you what is wrong and one way to
  fix it; it edits nothing.

## Licence

MIT.
