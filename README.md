# shared-workflows

Reusable GitHub Actions workflows shared across `velocity-exchange` repos.

| workflow | what it does |
| --- | --- |
| [`publish-image.yml`](.github/workflows/publish-image.yml) | The central image publisher. Builds, pushes to non-prod ECR, copies to prod by digest, and cosign-signs both. |
| [`secret-scan-reusable.yml`](.github/workflows/secret-scan-reusable.yml) | TruffleHog scan of a pull request's own commits. |

## Why this repo is public

A **public** repository cannot consume a reusable workflow from a **private**
one, and the org is on the GitHub Team plan, so `internal` visibility does not
exist. With repos on both sides of that line, a public host is the only
arrangement that works for every caller.

Nothing sensitive lives here. Role ARNs come from repository/org `vars`,
registries are resolved at runtime, and build secrets are passed in by the
caller via `secrets:`. Publishing the *logic* is fine; what matters is who can
change it — see below.

## ⚠️ This repo is a trust root

`publish-image.yml` is the single workflow identity the Kubernetes admission
policy trusts. For a reusable workflow the cosign keyless certificate identity
is the `job_workflow_ref` — this file's path at its ref — and the
ClusterImagePolicy pins exactly:

```
https://github.com/velocity-exchange/shared-workflows/.github/workflows/publish-image.yml@refs/heads/master
```

Two consequences:

1. **Whoever can merge to `master` here controls what reaches prod ECR.**
   Branch protection and CODEOWNERS on this repo are load-bearing, not
   hygiene. The security argument in `publish-image.yml` is literally "`@master`,
   whose content is protected by this repo's branch rules".
2. **Moving, renaming or re-reffing that file breaks image admission in both
   clusters** until the policy is updated. The policy lives in the
   `infrastructure-v3` repo at
   `gitops/<env>/platform/policy-controller/cluster-image-policy.yaml`.

To change the publisher's path or ref, use the dual-identity sequence: add the
new subject to the policy alongside the old one, let both environments sync
(prod tracks the `mainnet-beta` release branch, so that is a second PR),
re-release images through the new identity, and only then drop the old entry.
Doing it in the other order rejects every image.

## Usage

```yaml
jobs:
  secret-scan:
    uses: velocity-exchange/shared-workflows/.github/workflows/secret-scan-reusable.yml@master
    with:
      runner: ubicloud
```

Pin `publish-image.yml` to a tag rather than a moving ref where you can: a
change there lands in every consumer's build pipeline at once. The secret scan
is deliberately the opposite — a moving ref, so detector fixes reach all repos
immediately.
