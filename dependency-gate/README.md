# dependency-gate

A composite GitHub Action that flags the dependencies a pull request newly introduces,
and the existing ones it repoints at a new source, then requires an explicit human
sign-off label before the pull request can merge.

It answers one security question: *was the provenance of this package checked before it
became a dependency?* It does not judge whether a package is trustworthy. It makes a new
package, or a quietly redirected one, impossible to merge unnoticed, and records who
accepted it.

## What v2 changes

v1 compared package **names**. That left three holes, each now closed.

1. **Source substitution.** Rewriting `"husky": ["husky@8.0.3"` to
   `husky@https://attacker.invalid/evil.tgz` in a real `bun.lock` leaves the name list
   byte-identical, 145 entries before and after, so v1 reported nothing. v2 compares
   name **and source**.
2. **Stale sign-off.** v1 checked only that the label was currently present. Approving
   package A therefore let package B merge unreviewed on a later push. v2 binds
   sign-off to a digest of the exact finding set and drops the label when that digest
   moves.
3. **Workflow tampering.** Under plain `pull_request` the pull request's own copy of the
   workflow runs, so a pull request can empty the `lockfiles` input in the same diff
   that adds a package. v2 supports `pull_request_target`, where the workflow comes from
   the base branch.

## Usage

Two trigger modes are supported, and which one you can use depends on whether this
workflow already exists on your base branch. Start at step 1 and move to step 2.

### Step 1: `pull_request`, to get the gate merged

```yaml
name: Dependency gate

on:
  pull_request:
    types: [opened, synchronize, reopened, labeled, unlabeled]

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          fetch-depth: 0
      - uses: velocity-exchange/dependency-gate@v2
        with:
          lockfiles: bun.lock ui/bun.lock
```

`fetch-depth: 0` is required: the action compares against the base commit, which a
shallow clone does not contain.

In this mode the action emits a `::warning::` on every run, because the workflow it is
running from is the pull request's own copy. That is not paranoia, it is the residual
hole from v1, and the warning is there to stop the mode becoming permanent.

### Step 2: `pull_request_target`, once the workflow is on the base branch

```yaml
on:
  pull_request_target:
    types: [opened, synchronize, reopened, labeled, unlabeled]

# ... same permissions ...

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          fetch-depth: 0
      - uses: velocity-exchange/dependency-gate@v2
        with:
          lockfiles: bun.lock ui/bun.lock
          require-pull-request-target: "true"
```

Set `require-pull-request-target: "true"` at the same time. It makes the action fail if
it is ever triggered by anything else, so the trigger cannot be quietly downgraded.

**Why both modes exist.** Under `pull_request_target` the workflow is read from the base
branch, so a pull request that *introduces* the gate does not run it at all: there is no
gate on the base branch yet to run. Shipping `pull_request_target` alone would mean the
gate silently produces no check on exactly the pull request that adds it. So
`pull_request` is a first-class mode for bootstrapping, not a deprecated fallback. Merge
the workflow with `pull_request`, then switch the trigger.

### Do not check out the pull request under `pull_request_target`

Under `pull_request_target` the job runs with a writable token. The action is safe there
because the pull request's code is never checked out or executed:

- `actions/checkout` with no `ref` gets the base branch.
- The action reads the pull request's lockfiles as **bytes** through the contents API at
  the pinned `github.event.pull_request.head.sha`, and only ever parses them as text.
- The parser never installs, resolves, evaluates or reaches the network.

If you add `ref: ${{ github.event.pull_request.head.sha }}` to that checkout, or run any
install step, you reintroduce the hazard this mode exists to avoid.

### Inputs

| Input | Default | Description |
| --- | --- | --- |
| `lockfiles` | required | Space-separated, repo-relative lockfile paths to watch. |
| `label` | `deps-reviewed` | Label recording sign-off on the reported findings. |
| `comment` | `true` | Post or update a sticky comment listing the findings. |
| `comment-author` | `github-actions[bot]` | Login that must have authored a comment for the sign-off marker inside it to be honoured. Change this only if `token` is not the default `GITHUB_TOKEN`, since the marker is then written under that token's identity. |
| `require-pull-request-target` | `false` | Fail unless the run was triggered by `pull_request_target`. |
| `token` | `github.token` | Token used to read the pull request and write the comment. |

### Outputs

| Output | Description |
| --- | --- |
| `count` | Number of findings. |
| `digest` | Digest of the finding set that sign-off is bound to. |
| `findings` | Tab-separated `lockfile<TAB>change<TAB>name<TAB>source` lines. |

v1's `packages` output is gone; `findings` replaces it with a different shape. Anything
reading `packages` must be updated.

### Required permissions

```yaml
permissions:
  contents: read        # read the base branch and the head lockfiles
  issues: write         # delete a stale label, which goes through the issues API
  pull-requests: write  # post and update the sticky comment
```

`issues: write` is new in v2. Without it the action still enforces, but it cannot remove
a label that was applied for a different finding set, and it will say so as a warning
instead. Since a stale label does not grant sign-off either way, the gate stays correct
without the permission; it is just less tidy.

## How sign-off works

1. The action computes the findings and a digest over them.
2. If there are findings and the label is absent, the job fails.
3. Applying the label re-runs the workflow (hence the `labeled` trigger). The label was
   applied for the set that run computes, so the run passes and records
   `<!-- gate-approved: DIGEST -->` in its own sticky comment.
4. On a later push the digest is recomputed. If it still matches the recorded one, the
   sign-off stands. If it moved, the label is deleted and the job fails, so the new set
   gets reviewed rather than inheriting the old approval.

The digest is 24 hex characters, 96 bits, over the sorted finding set. Sorting makes it
independent of the order findings happen to be produced in. 96 bits is chosen so that
searching for a second finding set with an already-approved digest is not feasible, even
though package names can be picked freely.

### What the marker does and does not protect

The marker is only honoured on comments authored by `comment-author`, so nobody who can
merely comment on a pull request can forge a sign-off. In particular a pull request from
a fork cannot: its `GITHUB_TOKEN` is read-only, so it cannot post as the bot at all.

Be clear about the limit, though. Anyone who can make *any* workflow in the repository
comment with `GITHUB_TOKEN` can write a comment carrying the marker, so a same-repository
pull request that adds a workflow of its own could record a digest the gate would later
honour. That grants no new capability: applying the label already requires write or
triage access, and anyone with that can simply apply it. The marker guards against
outside comments, not against people who could approve anyway. Closing it needs the same
repository configuration as the point below.

## What cannot be closed from inside a workflow

Two gaps remain, and both need repository configuration rather than code:

- **Require the check.** Nothing here stops a pull request deleting its own workflow
  file, or, under `pull_request`, editing it. Require this job through a branch ruleset,
  so a missing check blocks the merge instead of reading as a pass. This also pins the
  check to a head SHA, which is what stops a pull request being merged with a newer,
  ungated head.
- **Own `.github/**`.** Add a CODEOWNERS entry for `.github/**` so workflow changes need
  a review from someone who is not the author. This is also what closes the marker
  caveat above, since it stops a pull request adding a workflow that comments as the bot.

Neither can be asserted by the action. If your repository has not set both up, this gate
is a strong speed bump, not a wall.

## What counts as a changed source

A finding is `new` when the package name is absent from the base lockfile, and `source`
when the name is already there but is fetched from somewhere new.

"Source" means the **origin of the bytes**, not their content:

- A registry download collapses to the registry's base URL, so **an ordinary version
  bump produces no finding**.
- Any change of **protocol, host or path** produces a finding: a tarball URL, a git
  remote, a local `file:`/`link:` path, an `npm:` alias to a different package, or a
  different registry.
- The **resolved** revision is dropped, and only the resolved one. A git dependency on
  `?branch=main` stays quiet as the branch advances, because nothing the repository asked
  for changed. Repointing it at `?rev=<commit>` is reported, because someone chose a
  different commit deliberately.

Registries are recognised **structurally**, by the `<name>/-/<file>` download path every
npm-compatible registry serves, not by a list of known hostnames. A hostname allowlist
would classify every entry in a repository installing from Artifactory, GitHub Packages
or Verdaccio as a non-registry source, so every routine bump would raise a finding. A
gate that cries wolf on every bump gets its label applied without being read, which is a
worse failure than the one it was protecting against.

Known limits, stated rather than hidden:

- A new release from the same registry, or a new commit on the same branch, is out of
  scope by design. This gate reports a change of origin, not a change of content.
- `pnpm-lock.yaml` records no per-package registry in v9, so a registry swap made only in
  `.npmrc` is invisible here. Tarball and git overrides in a `resolution:` block *are*
  read.

## Supported lockfiles

`bun.lock`, `yarn.lock` (v1 classic and berry), `pnpm-lock.yaml`, `Cargo.lock`, `uv.lock`.

Files are dispatched by filename, so the path may be nested but the basename must be one
of the above. `bun.lockb` is bun's binary format and is not supported; convert it to the
text `bun.lock` format to gate it.

`bun.lock` is parsed as the JSONC document bun itself reads, rather than scanned line by
line, so reformatting the file cannot hide an entry from a line-anchored pattern.

An unparseable lockfile is a hard error. This runs as a merge gate, and "unparseable"
must never be read as "nothing was added".

The parser reads text only. It never installs, resolves, or reaches the network, so it is
safe to run against a lockfile from an untrusted pull request.

## Why the parser lives here

The obvious implementation puts the script in each repository, next to the workflow. That
has a hole: on a `pull_request` event the workflow runs against the merge commit, so the
script is the pull request's own copy. A pull request can add a dependency and edit the
script meant to report it, in one diff, and the check passes.

Shipping the parser inside the action removes it from that editable surface. Callers
reference it by tag or commit SHA, and the code that runs is the code in this repository.

## Behaviour outside a pull request

On a `push` event, or any other event, the action reports to the job summary and never
fails, since there is nothing to label. This is useful where an automation commits
dependency bumps straight to a branch, so the change is at least recorded. A push with no
predecessor (a new branch, a first push, a force push) has nothing to compare against and
is skipped.

## Fork pull requests

A pull request from a fork gets a read-only token, so commenting fails. The action
downgrades that to a warning and still enforces the label, rather than aborting before
the check it exists to perform.

## Requirements

`bash`, `python3`, `jq` and `gh`, all present on GitHub-hosted Linux and macOS runners.
Windows runners are not supported.

Under `pull_request_target` the action lists the head tree in one API call. If that
listing comes back truncated, which needs a very large repository, the job fails rather
than guess which lockfiles exist.

## Development

```bash
python3 tests/test_parser.py
```

No third-party packages. A dependency gate that needed its own dependency tree would be a
poor advertisement for itself.

The tests are the specification for what "source" means. Two cases matter most and are
asserted directly: an ordinary registry version bump produces no finding, and a change of
protocol, host or path does. When changing the parser, add a case first. Every consumer
repository pins this action, so a defect here reaches all of them at once.

This repository also gates itself. `.github/workflows/dependency-gate.yml` watches
`tests/fixtures/Cargo.lock` under `pull_request_target`, so the failure path runs for
real on any pull request that touches it. The dogfood jobs in `test.yml` watch the
never-changing fixtures under `tests/fixtures/stable/` and assert a zero count in both
trigger modes.
