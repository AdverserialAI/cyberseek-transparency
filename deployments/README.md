# deployments/

One directory per release that has ever served production traffic. Releases are
never edited after publication and never deleted: the history refers to them.

    deployments/
      CURRENT                 first line: name of the directory that production should match;
                              "#" comment lines after it say so when that release is not verified yet
      CHANGELOG.md            one "## <directory>" section per release
      <release>/
        docker-compose.yml    the compose text running in the VM, byte for byte
        app-compose.json      the dstack manifest that is hashed into the VM's measurements
        policy.json           the measurements and digests a verifier must see

## What each file is for

**app-compose.json** is the file whose SHA-256 is the `compose_hash` that the
VM's operating system writes into the hardware-signed measurement log before
any container starts. It embeds the whole docker compose text, the pre-launch
script, and `allowed_envs`, the list of environment variable *names* the
operator can set at deploy time. It must be published in canonical form (sorted
keys, compact, no null values), so that

    sha256sum deployments/<release>/app-compose.json

prints the compose hash with no tooling. See `verify/avlib/compose.py` for the
exact rule.

**docker-compose.yml** is the same compose text as a readable file. It must be
byte-identical to `docker_compose_file` inside app-compose.json.

**policy.json** lists what a verifier must find: `tdx.mrtd`, `tdx.rtmr0-2`
(firmware, kernel, initrd), `tdx.os_image_hash`, `tdx.app_id`,
`tdx.compose_hash`, image digests, the minimum GPU count, and a `verifier`
block:

| Key | Meaning |
|---|---|
| `accepted_tcb_status` | Intel TCB statuses the verifier accepts (default: only `UpToDate`) |
| `allowed_envs` | The operator-supplied variable names. Must equal the manifest's `allowed_envs` and the `${NAME}` references in the compose |
| `proxy_service`, `inference_service` | Compose service names of the proxy (default `attest-proxy`) and the model server (default `sglang`) |
| `enclave_key_proxy_digests` | Digests of proxy images whose source refuses operator-supplied keys (in the source from v0.1.0-rc.31; v0.1.0-rc.33 is the first such release that was deployed). Each entry must be backed by `gh attestation verify oci://ghcr.io/adverserialai/attest-proxy@<digest> -R AdverserialAI/attest-proxy` |
| `operator_key_envs` | Optional extra variable names to treat as operator-supplied key material. The built-in four cannot be removed |

Optional pins, checked when present: `receipt_keys` (list of receipt key ids;
the key is generated at first boot and kept on the encrypted disk, so it is
stable across restarts) and `tls_spki_sha256`.

## Pending releases

A release can be rolled out before it can be verified, for example when the
VM is up but the service does not answer yet. It is published anyway, so that
what was rolled out is on record from the first day, but honestly:

    "status": "pending",
    "pending": {
      "reason":  "measurements, TLS pin and receipt key pending first live attestation",
      "missing": ["tdx.mrtd", "tdx.rtmr0", "tdx.rtmr1", "tdx.rtmr2", "tls_spki_sha256", "receipt_keys"]
    }

* The values named in `missing` are simply absent from `policy.json`. Nothing
  is guessed or filled with a dummy. Only values that a live attestation
  supplies may be missing: MRTD, RTMR0-2, and the optional pins
  `tls_spki_sha256`, `receipt_keys`, `model_artifact_digest`. `tdx.app_id`,
  `tdx.compose_hash` and `tdx.os_image_hash` are always required.
* Every other rule applies in full: the secret scan, the compose hash, the
  COMPOSE_DIGEST and all static compose checks. `tools/validate_deployments.py`
  reports the release as `PENDING`, and `--fail-on-pending` turns that into an
  error.
* `verify/verify.py` never returns `PASS` against a pending policy. The check
  `policy.not_pending` is skipped, which makes the verdict `INCOMPLETE`, and
  its line says what is missing.
* `CURRENT` and the release's `CHANGELOG.md` section must say
  `ROLLED OUT, NOT YET VERIFIED LIVE`. The tools write and check both.
* The recorder writes `"policy_state":"pending"` into every history line it
  records against such a policy and never records `PASS`.

### Completing a pending release

When the endpoint answers:

1. Fetch and inspect, without trusting the result yet:
   `python verify/verify.py https://api.adverserial.ai --deployment deployments/<release> --json --save-dir ../first-attestation`
   The verdict must be `INCOMPLETE` with nothing failed, and the only skipped
   checks must be `policy.not_pending` and `policy.mrtd`, `policy.rtmr0`,
   `policy.rtmr1`, `policy.rtmr2`. In particular `tdx.quote_signature`,
   `tdx.collateral_tcb`, `policy.compose_hash`, `policy.app_id`,
   `policy.os_image_hash`, `compose.*` and `keyatt.*` must be `PASS`.
2. Take MRTD and RTMR0-2 from `summary.measurements` and compare them with the
   values the OS image vendor publishes for the image named in the changelog
   (for dstack, the image's reference measurements for this VM size). Do not
   copy them from the endpoint without that comparison: the endpoint is what
   is being checked.
3. Copy `policy.json` out of the repository, delete `status` and `pending`,
   add `tdx.mrtd`, `tdx.rtmr0`, `tdx.rtmr1`, `tdx.rtmr2`, and the pins:
   `tls_spki_sha256` (`summary.tls_spki_sha256`), `receipt_keys`
   (`[summary.keys.receipt_kid]`) and `model_artifact_digest`
   (`summary.model_digest`). Change nothing else.
4. `phala cvms get <id> --json > ../cvm.json`, then
   `python tools/prepare_release.py ../cvm.json ../policy.json <release> --complete --completed-on "<UTC time>"`
   It replaces only `policy.json`, and only if every published value is
   unchanged and the VM still reproduces the published manifest and compose.
   It also removes the status lines from `CURRENT` and the changelog section.
5. `python verify/verify.py https://api.adverserial.ai --deployment deployments/<release>`
   must print `VERDICT: PASS`, and
   `python tools/validate_deployments.py --fail-on-pending` must print `OK`.
6. Open a pull request. CI accepts this one kind of change to a published
   release (`tools/validate_deployments.py --immutable-since`) and no other.
   After the merge the scheduled recorder records `PASS` on its next run; put
   that entry's `seq` into the changelog section.

## No secrets, ever

Nothing here may contain a credential. Secrets reach the VM as encrypted
environment variables; the compose only refers to them as `${NAME}`.
`tools/check_no_secrets.py deployments/` runs in CI on every change and fails
on anything that looks like a token, a private key, or a literal assigned to a
variable named like `*KEY`, `*SEED`, `*TOKEN`, `*SECRET`.

A compose with literal secrets cannot be made publishable by redacting it: the
hash covers the secrets. It has to be redeployed with references instead.

Note what this means for trust: the *values* of the variables in `allowed_envs`
are chosen by the operator and are not measured. The verifier prints the list
and fails unless it is exactly the policy's list and each name is used only as
the whole value of an environment variable.

## Publishing a release

1. Deploy. Save the VM description outside this repository; it is only an
   input: `phala cvms get <id> --json > ../cvm.json`
2. Write the policy for the deployment (start from the previous release's
   `policy.json`) from values you verified yourself. Before listing a proxy
   digest under `verifier.enclave_key_proxy_digests`, run the
   `gh attestation verify` command above for it.
3. `python tools/prepare_release.py ../cvm.json ../policy.json <release> --rolled-out "<UTC time>" --changes "<what and why>"`
   It writes `deployments/<release>/`, points CURRENT at it and adds the
   CHANGELOG section. It writes nothing if a hash does not match the VM, if
   anything looks like a credential, or if a static verifier check would fail.
   Add `--dry-run` to only check, and `--pending` when the policy is marked
   pending (see above); then steps 4 and 5 wait for the completion.
4. `python verify/verify.py https://api.adverserial.ai --deployment deployments/<release>`
   must print `VERDICT: PASS`.
5. `python tools/validate_deployments.py` must print `OK`. Open a pull request.
   The `deployments` workflow validates it again and, on merge, publishes a
   Sigstore attestation for every file.

`tools/canonicalize_app_compose.py` does only the first half (manifest and
compose, no policy, no CURRENT) and is kept for inspecting a VM description.

Order matters: merge the release directory *before* (or within 30 minutes of)
the rollout. If production shows measurements that match no directory here,
the scheduled recorder fails and opens an issue.

Published release files never change afterwards. The single exception is the
completion of a pending `policy.json` described above.
