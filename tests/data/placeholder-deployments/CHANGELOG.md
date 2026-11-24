# Deployment changelog

One section per release directory, newest first. The heading must be exactly
`## <directory name>`; `tools/validate_deployments.py` checks that it exists.

Each entry states: date of rollout, what changed and why, the new compose hash
and COMPOSE_DIGEST, whether MRTD/RTMR0-2 or the OS image changed, and which
keys rotated (in-enclave keys rotate on every restart).

<!-- Add new releases directly below this line. -->

## PENDING

PLACEHOLDER. No release has been published in this repository yet. The first
entry will be written when the post-migration deployment is live and has been
verified with `verify/verify.py`.

Template for a real entry:

    ## v0.1.0-rc.NN
    - Rolled out: YYYY-MM-DD HH:MM UTC
    - Changes: ...
    - compose_hash: <64 hex>          (previous: <64 hex>)
    - COMPOSE_DIGEST: sha256:<64 hex>
    - OS image: dstack-nvidia-X.Y.Z, os_image_hash <64 hex> (changed / unchanged)
    - MRTD, RTMR0-2: changed / unchanged
    - Images: attest-proxy@sha256:..., inference@sha256:...
    - Operator-settable variables (allowed_envs): ...
    - First history entry under this release: seq N
