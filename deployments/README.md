# deployments/

One directory per configuration that was rolled out to production. Releases are
never edited after publication and never deleted: the history refers to them.
A directory is named after the proxy release; when the same proxy release is
rolled out again under a different measured configuration, the name says what
changed (`v0.1.0-rc.33-os-0.6.5`: rc.33 on the OS image dstack-0.6.5).

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
script, `allowed_envs` (the list of environment variable *names* the operator
can set at deploy time) and, from manifest version 3, `requirements`, which
holds the GPU policy. It must be published as exactly the bytes the guest
measured, so that

    sha256sum deployments/<release>/app-compose.json

prints the compose hash with no tooling.

The guest hashes the file it receives; it does not re-serialise it. The bytes
are: one JSON object, keys sorted, compact separators, UTF-8, no trailing
newline, no keys whose value is null. Everything else is kept, including
`"name":""`. `"init_script":[]`, which the hosting provider's API shows for
every VM, is **not** part of the bytes for `"manifest_version":2` (dstack
0.5.x) and **is** part of them for `"manifest_version":"3"` (dstack 0.6.x;
the version is a string there). `verify/avlib/compose.py` holds this rule and
`tools/prepare_release.py` applies it to the VM description; it writes nothing
unless the result hashes to the compose hash the VM reports. Proof for the two
manifests published here:

    sha256sum deployments/v0.1.0-rc.33/app-compose.json            # 275c6e53...1a1d, version 2
    sha256sum deployments/v0.1.0-rc.33-os-0.6.5/app-compose.json   # 9c78bf82...b820, version "3"

**docker-compose.yml** is the same compose text as a readable file. It must be
byte-identical to `docker_compose_file` inside app-compose.json.

**policy.json** lists what a verifier must find: `tdx.mrtd`, `tdx.rtmr0-2`
(firmware, kernel, initrd), `tdx.os_image_hash`, `tdx.app_id`,
`tdx.compose_hash`, `tdx.gpu_policy_hash` (manifest version 3 only, see
below), image digests, the minimum GPU count, and a `verifier` block:

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

## The GPU policy (manifest version 3, dstack 0.6.x)

dstack 0.6.x measures `requirements.gpu_policy` of the manifest into the event
log as `gpu-policy-hash`, before the VM gets its keys:

    gpu_policy_hash = SHA-256( canonical JSON (RFC 8785) of requirements.gpu_policy )

`policy.json` must carry that value as `tdx.gpu_policy_hash`;
`tools/validate_deployments.py` recomputes it from the manifest. By default
the OS then attests every GPU and requires its Confidential Computing mode to
be on before it releases the keys, and records a `gpu-attestation` event.

In `v0.1.0-rc.33-os-0.6.5` the policy is `{"attest_gpu":false}`
(`gpu_policy_hash` `930188e08f58d0c555acff500a40be79c1f7e1d9ae23d26d901486cc9cc1a77d`):
the hosting provider switched the check off, because dstack 0.6.5 does not
recognise the multi-GPU Protected PCIe mode of eight-GPU H200 machines and
would refuse to boot. The protection is what it was on dstack 0.5.x, which had
no such check, but nothing in the measured boot chain verifies the GPUs'
protected mode. `verify/verify.py` reports this as `WARN gpu.os_attestation`
on every run: it does not change the verdict, and it is written into every
history line. The top-level `README.md` has the full explanation. Removing the
flag changes the manifest and therefore the compose hash: it will be a new
release directory.

## Superseded releases

A pending release can be overtaken before it ever answers. On 2026-11-24
`v0.1.0-rc.33` was rolled out on the OS image dstack-nvidia-0.5.15, never
served a request (one of eight GPUs failed to initialise at every boot), and
was replaced the same day when the hosting provider moved the VM to
dstack-0.6.5 and changed the manifest.

Such a directory is not edited and not deleted. Its `policy.json` stays
pending for good. What marks it is the first line of its section in
`CHANGELOG.md`:

    - Status: SUPERSEDED BEFORE IT EVER SERVED (<date>): <why>

`tools/validate_deployments.py` then reports it as `SUPERSEDED`, does not
count it under `--fail-on-pending`, refuses it as `CURRENT`, and
`tools/prepare_release.py --complete` refuses to complete it. Only a pending
release can be marked this way; a release with a final policy has served and
stays a release.

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
   `policy.os_image_hash`, `policy.gpu_policy_hash`, `compose.*` and
   `keyatt.*` must be `PASS`. `gpu.os_attestation` reads `WARN` for a release
   whose manifest says `"attest_gpu": false`; that is expected and is not a
   reason to stop, but `gpu.evidence` and `gpu.signatures` must be `PASS`.
2. Take MRTD and RTMR0-2 from `summary.measurements` and compare them with the
   values the OS image vendor publishes for the image named in the changelog
   (for dstack, the image's reference measurements for this VM size). Do not
   copy them from the endpoint without that comparison: the endpoint is what
   is being checked. For dstack-0.6.5 the MRTD is printed on the image's
   release page
   (<https://github.com/Dstack-TEE/dstack/releases/tag/mkosi-os-v0.6.5>);
   RTMR0 depends on the VM's size (CPUs, memory, GPUs), so RTMR0-2 are
   compared with what the vendor's `dstack-mr` tool computes from the
   downloaded image for this VM's shape, or failing that with the values the
   hosting provider's API reports for the VM, and the changelog entry says
   which comparison was made.
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
   pending (see above); then steps 4 and 5 wait for the completion. For a
   manifest of version 3 the policy must carry `tdx.gpu_policy_hash`.
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
completion of a pending `policy.json` described above. When production changes
before a pending release was ever verified, the release is not rewritten: a
new directory is published and the old one is marked superseded in the
changelog (see "Superseded releases").
