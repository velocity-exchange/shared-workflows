# shared-workflows

Reusable GitHub Actions workflows shared across `velocity-exchange` repos.

## `publish-image.yml`

The central image publisher. Builds an image, pushes it to the non-prod ECR,
copies it to prod by digest, and cosign-signs it in both registries.

Runs on release tags. It fails the build unless the tagged commit is already on
the calling repo's `master`, so releases can only be cut from reviewed code.
AWS access is via OIDC; role ARNs come from the caller's
`VELOCITY_NON_PROD_ECR_PUBLISH_ROLE` / `VELOCITY_PROD_ECR_PUBLISH_ROLE` repo or
org variables.

```yaml
jobs:
  publish:
    uses: velocity-exchange/shared-workflows/.github/workflows/publish-image.yml@master
    with:
      ecr_repository: my-service
      image_tag: ${{ github.ref_name }}
```

| input | required | default | notes |
| --- | --- | --- | --- |
| `ecr_repository` | yes | — | ECR repo name; the same in both registries |
| `image_tag` | yes | — | e.g. `v1.2.3` |
| `dockerfile` | no | `Dockerfile` | |
| `context` | no | `.` | Docker build context |
| `build_args` | no | — | Newline-separated `KEY=value` |
| `cache_scope` | no | — | gha cache scope; empty disables the cache |
| `checkout_submodules` | no | `false` | `false`, `true` or `recursive` |
| `runner` | no | — | Runner label for the build |

Secrets: `build_secrets`, newline-separated `id=value` docker build secrets.

## `secret-scan-reusable.yml`

Scans a pull request's own commits (`merge-base..head`) with TruffleHog.

| tier | behaviour |
| --- | --- |
| verified — replayed against the issuing provider and it authenticated | fails the job |
| unknown — matched, but verification could not conclude | annotates |
| possible Solana keypair — a 64-byte array | annotates |

Findings report the detector and `file:line` only, never the matched value.

```yaml
on:
  pull_request:

permissions:
  contents: read

jobs:
  secret-scan:
    uses: velocity-exchange/shared-workflows/.github/workflows/secret-scan-reusable.yml@master
    with:
      runner: ubicloud
```

| input | required | default | notes |
| --- | --- | --- | --- |
| `runner` | no | `ubicloud-standard-8` | Most repos want `ubicloud` |
| `fail_on_verified` | no | `true` | `false` makes the job annotate-only |

Callers must be triggered by `pull_request`; the workflow fails fast under any
other trigger.
