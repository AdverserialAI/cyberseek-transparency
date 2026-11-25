# Verify the Adverserial confidential inference deployment

> **Status on 2026-11-24: live, and verified by this repository since 19:19 UTC.**
>
> * **Running:** `attest-proxy` v0.1.0-rc.33, the first deployed release that
>   generates its keys inside the VM, on the OS image `dstack-0.6.5`. Its
>   compose, measured manifest and completed policy are in
>   [`deployments/v0.1.0-rc.33-os-0.6.5/`](deployments/v0.1.0-rc.33-os-0.6.5/).
>   The proxy reports that it has been up since 18:28 UTC and that the model
>   was ready at 18:42 UTC.
> * **Verified live.** The verifier here first ran against the live endpoint
>   at 19:13 UTC, against the policy that was still pending: `INCOMPLETE` as
>   designed, nothing failed. The measurements from that quote were compared
>   with the OS vendor's release page and measurement tool, the policy was
>   completed, and at 19:19 UTC the verifier printed `VERDICT: PASS`: 41
>   checks passed, none failed, none skipped, one warning (next point).
>   [`deployments/CHANGELOG.md`](deployments/CHANGELOG.md) says exactly what
>   was compared with what, and where that comparison has a limit.
> * **GPU attestation by the OS is switched off.** The provider added
>   `"attest_gpu": false` to the measured manifest, because the check in
>   `dstack-0.6.5` cannot handle this eight-GPU machine. Nothing in the
>   measured boot chain currently verifies the GPUs' protected mode, and a
>   `PASS` does not cover it. The verifier says so on every run
>   (`[WARN] gpu.os_attestation`). See
>   [GPU evidence](#gpu-evidence-what-is-and-is-not-verified).
> * **The history has started.** Entry `seq 0` was recorded at 19:22:37 UTC
>   (`PASS`), by hand. `seq 1` (19:25:57 UTC, `PASS`) was recorded by the
>   recorder workflow, started by hand, and its head is attested through
>   Sigstore. GitHub's own scheduler then started the recorder only once in
>   its first ten hours (03:44 UTC on 25 November), so the early history has
>   gaps of several hours. **Since 25 November 2026, 06:39 UTC, an external
>   timer (Google Cloud Scheduler) starts the recorder at minutes 9 and 39 of
>   every hour.** A 30-minute cadence therefore exists only from that moment.
>   Read the timestamps in `history/attestations.jsonl`: the history shows
>   that the service verified at those moments, not a long track record.
> * **The client policy is signed.** The policy the operator's own clients
>   use has been served with a Sigstore signature since about 19:03 UTC
>   (Rekor log index 4085227850) and pins the same measurements as this
>   repository. Both watch workflows passed when started by hand at 19:25
>   UTC and are started by the same external timer since 25 November. The
>   transparency-log monitor was reset on 25 November at 06:47 UTC, because it
>   could not catch up on its backlog; it looks forward only from then and has
>   not yet shown that it completes every hour.
> * **Earlier the same day:** the first rollout of rc.33, on
>   `dstack-nvidia-0.5.15`, never served a request (one of the eight GPUs
>   failed to initialise at every boot). The hosting provider moved the VM to
>   `dstack-0.6.5` at about 14:00 UTC, which changed the OS image hash and the
>   compose hash. The directory published that morning,
>   [`deployments/v0.1.0-rc.33/`](deployments/v0.1.0-rc.33/), is kept as
>   published and marked *superseded before it ever served*.
>
> See [What is not here yet](#what-is-not-here-yet).

Adverserial runs a language model inside a *confidential virtual machine*: an
Intel TDX machine with eight NVIDIA H200 GPUs, hosted by Phala Cloud. The
promise is that nobody outside that machine, including the company operating
it, can read what you send to the model.

This repository lets you check that promise yourself, without trusting the
operator's word or the operator's own client software. It contains:

| Path | What it is |
|---|---|
| `verify/` | A small command-line verifier you can read in an afternoon |
| `deployments/` | The exact configuration of every release, with no secrets in it |
| `history/` | An append-only, hash-chained log of attestations, recorded every 30 minutes |
| `tools/` | The secret scanner, the release publisher and the deployment validators used by CI |
| `THREAT_MODEL.md` | Who could cheat, and which check would catch them |

The software that runs in the VM and the client that talks to it are published
separately:

| Repository | What it is |
|---|---|
| [AdverserialAI/attest-proxy](https://github.com/AdverserialAI/attest-proxy) | The proxy that terminates your connection, the GPU evidence collector and the model measurer |
| [AdverserialAI/adverserial-confidential-kit](https://github.com/AdverserialAI/adverserial-confidential-kit) | The client kit |
| [AdverserialAI/confidential-open-webui](https://github.com/AdverserialAI/confidential-open-webui) | The chat application |

## Verify it in three commands

```sh
git clone https://github.com/AdverserialAI/cyberseek-transparency && cd cyberseek-transparency
python3 -m pip install --require-hashes -r verify/requirements.txt
python3 verify/verify.py https://api.adverserial.ai --deployment "deployments/$(head -n 1 deployments/CURRENT)"
```

The third command prints one line per check and a verdict. While the VM is
restarting it ends with a connection error instead (exit status 3).

```
[PASS] tdx.quote_signature   Quote is signed by a key certified up to Intel's root CA
[PASS] tdx.collateral_tcb    Intel collateral: not revoked, platform TCB level acceptable
[PASS] binding.report_data   Quote binds the nonce, TLS key, receipt key and HPKE (EHBP) key
[PASS] policy.compose_hash   compose_hash matches the policy
[PASS] keyatt.keys_origin    The measured proxy states that it generated its keys inside the VM
[WARN] gpu.os_attestation    The OS attested the GPUs and their confidential mode before releasing keys
...
WARNING (gpu.os_attestation): GPU attestation by the OS is disabled by policy (attest_gpu=false). ...

VERDICT: PASS (every check that could run passed; 1 WARNING above: gpu.os_attestation)
```

* `PASS` the property was established.
* `FAIL` the property is false. Do not send anything confidential.
* `SKIP` an input was missing, for example no network access to Intel. A
  skipped check makes the verdict `INCOMPLETE`, never `PASS`.
* `N/A` the property cannot exist in this mode. A saved file cannot be "fresh".
* `WARN` the evidence matches the published policy, but the policy itself
  switches a protection off. It does not change the verdict, because the
  machine is exactly what this repository says it is. It is printed in the
  list, again above the verdict, and written into every history line, so a
  `PASS` is never read as covering that property. Today there is one:
  `gpu.os_attestation`.

A release can be published here before it has answered a single attestation.
Its policy then carries `"status": "pending"` and lists what is missing. The
check `policy.not_pending` is skipped for such a policy, so the verdict cannot
be `PASS`, whatever else holds.

### Check where the proxy image was built

The proxy image in the compose is pinned by digest. That this digest was built
by GitHub Actions from the tagged public source is recorded in a signed build
provenance, which you check with the GitHub CLI:

```sh
gh attestation verify oci://ghcr.io/adverserialai/attest-proxy@sha256:5a41bcfb6d7f4f3d3df53ad5ac39a45d1d32a6db206e35c0380b81d56404824b -R AdverserialAI/attest-proxy
```

It must exit 0 and name `refs/tags/v0.1.0-rc.33` of
`AdverserialAI/attest-proxy` as the source (add `--format json` to see the
commit and the workflow). This does not depend on the service being up; it
passed when this release was published here.

Add `--json` for machine-readable output. Exit status: 0 pass, 1 fail,
2 incomplete, 3 could not fetch.

To re-check a recorded attestation from the history instead of a live one:

```sh
d=history/evidence/2027/01/31/120700Z-ab12cd34      # any recorded directory
python3 verify/verify.py --file $d/evidence.json --collateral $d/collateral.json \
    --nras-jwks $d/nras-jwks.json --key-attestation-file $d/key-attestation.json \
    --meter-jwks-file $d/meter-jwks.json --statusz-file $d/statusz.json \
    --deployment deployments/<release> --at <timestamp of that history line>
```

## What is proven

When the verdict is `PASS`, the following has been established by signatures
that chain to Intel, by hashes you can recompute, and by nothing else.

1. **The machine is a genuine Intel TDX confidential VM, not in debug mode.**
   Its attestation "quote" is signed by a key that Intel's certificate chain
   vouches for, the platform is not revoked, and its firmware level (TCB) is
   one the policy accepts. The quote's signature chain is checked twice: by a
   short built-in implementation against the Intel root certificate stored in
   `verify/trust/`, and by the `dcap-qvl` library against Intel's current
   collateral.

2. **It booted the expected operating system.** The quote contains
   measurements of the virtual firmware (MRTD), kernel and boot files
   (RTMR0-2). They must equal the values in `policy.json`. The OS image hash
   recorded at boot must equal the published one. For `dstack-0.6.5` that
   hash can be recomputed from the public image, see
   [What you still have to trust](#what-you-still-have-to-trust). The
   expected values in `policy.json` were not simply copied from the endpoint:
   before they were written down they were compared with what the OS vendor
   publishes and with what its `dstack-mr` tool computes from the public
   image. `deployments/CHANGELOG.md` records that comparison and its limit
   (the VM configuration that RTMR0 depends on is not published by the
   hosting provider; part of it was inferred).

3. **It runs exactly the published configuration.** Before starting any
   container, the OS records the SHA-256 of the application manifest
   (`app-compose.json`) in a fourth measurement register (RTMR3). The verifier
   replays the event log, confirms it reproduces the signed RTMR3, and confirms
   that `sha256(deployments/<release>/app-compose.json)` is the recorded value.
   That manifest contains the full docker compose file, so every container is
   known, and every image in it is pinned by digest, including the
   `attest-proxy` image that terminates your connection.

4. **You are talking to that machine, now.** You send a random number
   (nonce). The quote's `report_data` field must equal a hash over your nonce,
   the TLS public key, the receipt-signing key and the HPKE key (details
   below). A recording of an old attestation cannot contain your nonce. The
   verifier then checks that the TLS certificate of the connection it actually
   used has that same public key.

5. **The keys belong to the machine, and were made there.** The TLS key, the
   HPKE key used to encrypt request bodies end to end, the key that signs
   receipts and the key that signs billing records are all named in a
   hardware-signed quote. In v0.1.0-rc.33 they are generated inside the VM:
   the measured compose gives the proxy nowhere to take a key from
   (`compose.keys_in_enclave`), and the proxy says so in a statement bound
   into a second quote (`keyatt.keys_origin`). See
   [Keys generated inside the VM](#keys-generated-inside-the-vm).
   *That was not always so. Releases up to and including v0.1.0-rc.30 were
   given their signing seeds and HPKE identity by the operator, through the
   compose file, which also contained literal secrets. For those releases the
   operator held the keys, the verifier reports `FAIL` on
   `compose.keys_in_enclave`, and their compose files cannot be published
   here. Key generation inside the VM entered the proxy source with
   v0.1.0-rc.31. rc.31 and rc.32 were never deployed; v0.1.0-rc.33, rolled
   out on 2026-11-24, is the first release that runs with it.*

6. **The model server cannot be reached around the proxy.** In the measured
   compose the inference container publishes no port and sits on a Docker
   network declared `internal: true`, shared only with the proxy; the proxy
   is the only container that publishes a port
   (`compose.inference_isolated`, `compose.single_ingress`).

7. **The GPUs passed NVIDIA's attestation**, as far as the proxy exposes it:
   see [GPU evidence](#gpu-evidence-what-is-and-is-not-verified). That
   section also says what is *not* proven about the GPUs in the current
   release, where the OS's own GPU check is switched off.

Taken together: your prompt is encrypted to a key that exists only inside a
machine running exactly the published software, and that software, which you
can read, does not hand prompts to the operator.

### How the binding is computed

For a fresh attestation (`GET /attestation?nonce=<base64url, 16-64 bytes>`):

```
report_data[0:32]  = SHA-256( "adverserial-attestation-v2\x00"
                              || nonce_bytes
                              || TLS SubjectPublicKeyInfo (DER)
                              || receipt key SubjectPublicKeyInfo (DER)
                              || HPKE receiver public key (32 bytes, X25519) )
report_data[32:64] = 32 zero bytes
```

For the key statement (`GET /.well-known/adverserial-key-attestation`), which
returns `{"statement": "<JSON text>", "quote": "<hex>", "event_log": ...}`:

```
report_data = SHA-512( "adverserial-key-attestation-v1\n" || statement )      (all 64 bytes)
```

`statement` is hashed exactly as served, as UTF-8 bytes. It is canonical JSON
(sorted keys, no whitespace) with these fields:

| Field | Meaning |
|---|---|
| `type` | `adverserial-key-attestation/v1` |
| `issued_at` | when the proxy built the statement (it reuses one for 60 seconds) |
| `proxy_version` | the proxy build |
| `keys_origin` | `enclave-generated`, or `operator-seed` / `process-ephemeral` outside confidential mode |
| `receipt_pubkey_jwk` | receipt-signing key (P-256) |
| `meter_pubkey_jwk` | billing-record signing key (Ed25519) |
| `ehbp_public_key`, `ehbp_public_key_sha256` | HPKE receiver key (X25519) and its hash |
| `tls_spki_sha256` | hash of the serving certificate's public key |

The two domain strings differ and the first construction always ends in 32
zero bytes, so a quote of one kind can never be passed off as the other.

### Keys generated inside the VM

Three independent things have to hold, and the verifier checks each.

**1. The measured configuration leaves the proxy no other source of keys**
(`compose.keys_in_enclave`). In the published compose, the `attest-proxy`
service must

* set `CONFIDENTIAL_MODE` on, `ENCLAVE_KEY_DIR` (where the proxy stores the
  keys it generates, on the VM's encrypted disk) and
  `UPSTREAM_BEARER_TOKEN_FILE` (the proxy-to-model credential, written by a
  container inside the VM at every boot), both as fixed absolute paths;
* set none of `RECEIPT_SIGNING_SEED`, `METER_SIGNING_SEED`,
  `EHBP_IDENTITY_B64`, `UPSTREAM_BEARER_TOKEN`: the four variables through
  which earlier releases received keys and credentials from the operator.
  They must not appear on any service, nor among the operator-supplied
  variables;
* run a proxy image whose source *refuses to start* when one of those four
  is set. The policy lists the image digests for which that holds
  (`verifier.enclave_key_proxy_digests`); the verifier checks the compose
  uses one of them. That a digest was really built from that source is
  established by the image's build provenance, which you check yourself:

  ```sh
  gh attestation verify oci://ghcr.io/adverserialai/attest-proxy@<digest> -R AdverserialAI/attest-proxy
  ```

  The verifier prints this command with the digest filled in. The refusal is
  in `internal/config/config.go` (`ExternalSecretEnv`) of the proxy source;

and no value anywhere in the compose may look like a literal credential (the
rules of `tools/check_no_secrets.py`).

**2. The proxy states where its keys came from, inside a quote**
(`keyatt.*`). The verifier follows the recipe in the proxy's README:

| Check | What it establishes |
|---|---|
| `keyatt.report_data` | The second quote commits to the statement, byte for byte, and the statement is canonical JSON |
| `keyatt.quote` | That quote is signed up to Intel's root, the platform's TCB level is acceptable, it is not a debug VM, and its MRTD and RTMR0-3 equal the fresh quote's: same machine, same measured software. Its own event log must replay to the same compose hash |
| `keyatt.statement` | Right `type`, no `dev` flag, same proxy version, issued within six minutes of the fresh attestation |
| `keyatt.keys_origin` | `keys_origin` is `enclave-generated` |
| `keyatt.keys_match` | The receipt key equals the one in the fresh attestation (and the policy's `receipt_keys`, when pinned); the HPKE key equals the fresh attestation's; the TLS key hash equals the fresh attestation's, the certificate of the live connection, and the policy's `tls_spki_sha256`, when pinned |
| `keyatt.meter_key` | `/.well-known/adverserial-meter-jwks.json` serves exactly the meter key in the statement, nothing more |

**3. Neither is enough alone.** A compose check says nothing about what the
binary does; a statement by the proxy is only as good as the proxy. Together
with the measured image digest they say: this exact, published proxy build,
which generates its keys at first boot and refuses outside ones, is the
software that holds the keys named in the quote.

### What the compose checks establish

All of them read `deployments/<release>/docker-compose.yml`, which
`compose.docker_compose` has shown to be the text inside the measured
manifest. The file is parsed by a deliberately strict reader
(`verify/avlib/miniyaml.py`) that rejects YAML anchors, aliases, merge keys,
tags and anything else it does not fully understand; a compose it cannot read
fails these checks. `include`, `extends` and `env_file` are refused because
they pull configuration from outside the measured file.

| Check | Passes when | Why it matters |
|---|---|---|
| `compose.images_pinned` | Every service runs an image named by `@sha256:` digest, none is built in place, and the policy's proxy and runtime digests are among them | A tag can be moved to different code; a digest cannot |
| `compose.unmeasured_inputs` | The variables the operator supplies at deploy time are *exactly* the policy's `verifier.allowed_envs`, in three places: the `${NAME}` references in the compose, `allowed_envs` in the manifest, and the policy. Each may be used only as the whole value of an environment variable | These values are encrypted to the VM and not measured. Substitution into an image name, a port, a volume or a command would let an unmeasured value change what the measured file means |
| `compose.keys_in_enclave` | See above | The operator must not be able to hand the proxy a key |
| `compose.inference_isolated` | The inference service (`sglang`) publishes no ports, sets no `network_mode` (so not `host`, not another container's network), and is attached only to networks declared `internal: true` that it shares with nothing but the proxy | Plaintext prompts exist between the proxy and the model server. An internal Docker network has no route in or out of the VM, so that hop cannot be reached or observed from outside, and no helper container sits on it |
| `compose.single_ingress` | `attest-proxy` is the only service with `ports`, and no service uses host or shared-container networking | Everything entering the VM passes through the code that enforces attestation, encryption and metering |

For the current release the operator-supplied variables are `HF_TOKEN`
(downloading the model weights), `CLOUDFLARE_API_TOKEN` (DNS challenge for the
TLS certificate), `NV_ATTESTATION_SERVICE_KEY` (NVIDIA's attestation service)
and `METER_INGRESS_SHARED_SECRET` (authenticating to the billing service).
None of them is a key that protects your prompts.

`statusz.consistent` is informational. `/statusz` is an unauthenticated status
page; the verifier fetches it and compares its `version`, `keys_origin`,
`receipt_kid` and `ehbp_public_key_sha256` with the attested values. A
contradiction is reported as `FAIL` because it means the endpoint disagrees
with itself; its absence changes nothing, and no trust decision rests on it.

### How the configuration hashes are computed

```
compose_hash   = SHA-256( bytes of app-compose.json )
```

The guest hashes the manifest file it was given, byte for byte: no parsing, no
re-serialisation. `app-compose.json` is published here as exactly those bytes,
so

```sh
sha256sum deployments/<release>/app-compose.json
```

prints the compose hash with no tooling, and the verifier compares that with
the `compose-hash` event in the hardware-signed log.

Those bytes are one JSON object with keys sorted, compact separators (`,` and
`:`), UTF-8, and no trailing newline. Compared with what the hosting
provider's API shows for the VM, keys whose value is `null` are absent, and
nothing else is: empty strings such as `"name":""`, `false` and empty lists
are part of the bytes. There is one difference between manifest versions, and
it is easy to get wrong:

| Manifest | OS | `"init_script":[]` shown by the API |
|---|---|---|
| `"manifest_version":2` (a number) | dstack 0.5.x | is **not** in the measured bytes |
| `"manifest_version":"3"` (a string) | dstack 0.6.x | **is** in the measured bytes |

The rule lives in `verify/avlib/compose.py` and is used only to rebuild the
bytes from the API's view when a release is prepared; the tools refuse to
publish unless the result hashes to the compose hash the VM reports. The
three compose hashes seen on this deployment are reproduced by it:
`847813c4...` (an earlier release, version 2, whose compose held secrets and
is not published), `275c6e53...`
(`deployments/v0.1.0-rc.33`, version 2) and `9c78bf82...`
(`deployments/v0.1.0-rc.33-os-0.6.5`, version "3"). The last two you can check
with `sha256sum`.

From manifest version 3 the OS measures one more value, the GPU policy:

```
gpu_policy_hash = SHA-256( canonical JSON (RFC 8785) of app-compose.requirements.gpu_policy )
```

It is recorded as the event `gpu-policy-hash`, before the VM gets its keys.
For the current release the policy is `{"attest_gpu":false}`, and

```sh
printf '%s' '{"attest_gpu":false}' | sha256sum     # 930188e08f58d0c555acff500a40be79c1f7e1d9ae23d26d901486cc9cc1a77d
```

```
COMPOSE_DIGEST = "sha256:" + SHA-256( docker-compose.yml with the COMPOSE_DIGEST
                                      value replaced by the text sha256:SELF )
```

This second value is what the proxy reports about itself. It is a convenience;
the hardware-backed fact is `compose_hash`.

### GPU evidence: what is and is not verified

Verified: every NVIDIA token in the evidence is signed by a key that NVIDIA
publishes at `nras.attestation.nvidia.com` (the address is fixed in the
verifier, not read from the evidence); NVIDIA's overall verdict is positive;
each per-GPU token is the one the overall token lists, reports matching
measurements, secure boot on and debug off; at least the number of GPUs the
policy requires are present; the tokens were valid when the quote was issued.

**Not verified:** that those GPUs are the ones attached to this VM. The GPU
evidence is collected by a container inside the VM and relayed by the proxy; it
is not bound to the TDX quote or to your nonce. You are trusting the measured
collector and proxy code to relay honest evidence. Also not verified here: the
GPU firmware and driver measurements themselves, which NVIDIA's service
compares against its own reference values. The verifier prints this limitation
on every run as `[N/A ] gpu.bound_to_vm`.

**Switched off in the current release: GPU attestation by the OS.**
`dstack` 0.6.x can attest the GPUs itself, at boot: it asks each GPU for an
attestation, requires each GPU's Confidential Computing mode to be on, and
only then lets the VM obtain its keys. The result is recorded in the
hardware-signed log as a `gpu-attestation` event. Whether it does this is
decided by `requirements.gpu_policy` in the measured manifest, and in
`deployments/v0.1.0-rc.33-os-0.6.5/app-compose.json` that policy is
`{"attest_gpu":false}`.

Why: a machine with eight H200 GPUs runs them in NVIDIA's multi-GPU *Protected
PCIe* mode. In that mode the per-GPU Confidential Computing status reads
"off". The check in `dstack-0.6.5` does not know that mode, sees "off", and
refuses to boot. The hosting provider therefore disabled the check for this
VM, and says it will add support for the mode and tell us when the flag can
be removed.

What that means, plainly:

* The protection is the same as on dstack 0.5.x, which never had this check.
  Nothing was taken away that an earlier release had.
* Nothing in the measured boot chain currently verifies that the GPUs are in
  their protected mode. A `PASS` from this verifier does not cover it.
* The opt-out is public and cannot be hidden: it is in the measured manifest
  (so it is covered by `compose_hash`), it is recorded as the event
  `gpu-policy-hash` = `930188e0...a77d`, and the log has no `gpu-attestation`
  event.
* What is checked in the meantime is the evidence described above: our own
  collector asks NVIDIA's remote attestation service, which establishes
  genuine GPUs, firmware measurements NVIDIA accepts, secure boot on and debug
  off. That evidence is not bound to the TDX quote, and it does not by itself
  prove Protected PCIe mode.

The verifier reports this as `[WARN] gpu.os_attestation`, with the text "GPU
attestation by the OS is disabled by policy (attest_gpu=false)". It checks
that the measured `gpu-policy-hash` is the hash of the policy in the published
manifest and equals `tdx.gpu_policy_hash` in `policy.json`
(`policy.gpu_policy_hash`). It fails if the log and the policy contradict each
other: a `gpu-attestation` event although the policy says off, or none
although the policy requires one. Both events must be unique and written
before boot completes, so an application cannot add one later. When the flag
is removed the manifest changes, so the compose hash changes, and that will
be a new release directory here.

## How the history works

Every 30 minutes a GitHub Actions workflow runs `history/record.py`. It picks
a new random nonce, fetches an attestation, runs the same verifier, and appends
one line to `history/attestations.jsonl`:

```json
{"seq":41,"timestamp":"...","nonce":"...","verdict":"PASS","failed":[],"skipped":[],
 "warnings":["gpu.os_attestation"],"gpu_os_attestation":"disabled-by-policy","gpu_policy_hash":"...",
 "measurements":{"mrtd":"...","rtmr0":"...","rtmr1":"...","rtmr2":"...","rtmr3":"..."},
 "compose_hash":"...","os_image_hash":"...","app_id":"...","deployment":"<release>",
 "key_fingerprints":{"receipt_kid":"...","ehbp_public_key_sha256":"...","meter_kid":"...","key_statement_sha256":"..."},
 "keys_origin":"enclave-generated","tls_spki_sha256":"...","tcb_status":"UpToDate","gpu_count":8,
 "evidence_sha256":"...","files":{"evidence":{"path":"history/evidence/...","sha256":"..."}},
 "prev":"<SHA-256 of the previous line>"}
```

* **Every run is recorded**, including failures and "endpoint unreachable"
  (`"verdict":"UNREACHABLE"`, with the error and no measurements). Each line
  also says whether the policy it was checked against was `final` or
  `pending` (`policy_state`). A line recorded against a pending policy is at
  best `INCOMPLETE`.
* **Warnings are recorded.** `warnings` lists the checks that ended in
  `WARN`, and `gpu_os_attestation` says whether the OS attested the GPUs at
  boot (`attested-at-boot`), was told not to (`disabled-by-policy`), or cannot
  (`not-supported-by-os`). The history therefore shows for how long the
  opt-out lasted.
* **Lines are chained.** `prev` is the SHA-256 of the previous line, so the
  hash of the last line (the *head*) commits to the entire file. Editing or
  deleting any earlier line breaks the chain. Check it with:

  ```sh
  python3 history/check_chain.py
  ```

* **Raw evidence is kept** under `history/evidence/YYYY/MM/DD/`, together with
  the Intel collateral and NVIDIA keys used, the key attestation, the meter key
  set and the status page, so you can re-run the verifier on any past entry
  and need not trust the recorded verdict.
* **Each new head is timestamped by Sigstore.** The workflow creates a GitHub
  artifact attestation for `history/attestations.jsonl`, logged in the public
  Rekor transparency log. That proves the file existed in that state at that
  time, from this repository's workflow:

  ```sh
  gh attestation verify history/attestations.jsonl --repo AdverserialAI/cyberseek-transparency
  ```

  (This matches the file as of the newest commit. For an older state, check out
  that commit first.)
* **Changes are announced.** If the measurements seen in production match no
  directory under `deployments/`, or verification fails, the workflow run
  fails and opens an issue. A legitimate upgrade therefore always appears as a
  reviewed change to `deployments/` first. An unreachable endpoint and a
  still-pending policy are reported too, in the same single issue (label
  `attestation-failure`), which is rewritten in place instead of growing by a
  comment every 30 minutes and closes itself when the condition ends.

## What you still have to trust

A passing verdict removes the operator from the list of parties who can read
your prompts. It does not make the list empty.

* **Intel.** TDX hardware, its firmware, and Intel's signing keys. A flaw in
  TDX, or a platform running a vulnerable firmware level that the policy
  nevertheless accepts, breaks everything above. The accepted TCB statuses are
  listed in `policy.json` (`verifier.accepted_tcb_status`); the default accepts
  only `UpToDate`.
* **NVIDIA.** The GPUs, their firmware, and NVIDIA's attestation service. Data
  is processed in the clear inside GPU memory. The link between "these GPUs
  passed" and "these GPUs are in this VM" rests on measured software, not on a
  signature (see above).
* **That the GPUs are in their protected mode.** In the current release the
  OS does not attest the GPUs at boot (`"attest_gpu": false` in the measured
  manifest, reported as `[WARN] gpu.os_attestation`). The eight GPUs are meant
  to run in NVIDIA's multi-GPU Protected PCIe mode, which is set up by the
  host. No signature that this verifier checks proves that mode: NVIDIA's
  remote attestation proves genuine GPUs, accepted firmware, secure boot and
  debug off, not the mode, and it is not bound to the TDX quote. Until the
  hosting provider's OS can check that mode and the flag is removed, you are
  trusting the host to have configured the GPUs as agreed. This is the same
  position as on dstack 0.5.x.
* **Phala's dstack OS image and key management service.** The OS image is
  identified by hash and the verifier pins it. For `dstack-0.6.5` the image
  is a public download,
  <https://github.com/Dstack-TEE/dstack/releases/download/mkosi-os-v0.6.5/dstack-0.6.5.tar.gz>,
  and anyone can recompute the hash: `os_image_hash` is the SHA-256 of the
  file `sha256sum.txt` inside the archive, which in turn lists the hashes of
  the firmware, kernel, initramfs and `metadata.json` (the kernel command
  line there carries the root filesystem's hash). The result is
  `4771a29e...8623`, the value in `policy.json` and in the `os-image-hash`
  event. The image was built with `mkosi` from
  [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack) at the tag
  `mkosi-os-v0.6.5` (commit `350a0a73`, also named in the image's
  `metadata.json`). What that does not give you: the image carries no signed
  build provenance, so "this archive was built from that tag" is the
  publisher's statement, and neither this repository nor the operator has
  rebuilt it from source or audited it. The dstack KMS issues keys to the VM,
  including disk encryption keys and the decryption of operator-supplied
  environment variables; its identity is recorded in the event log
  (`key-provider`) and in the history, but its behaviour is trusted. The
  proxy's signing keys are generated in the VM and then kept on that
  encrypted disk so that they survive a restart: whoever could obtain the
  disk key from the KMS could read them.
* **The inference image.** The model server image is pinned by digest, so it
  cannot be swapped silently, but it is not reproducibly built and has not been
  audited here. If it wrote prompts somewhere it should not, attestation would
  not reveal that. The same applies to the model weights: their digest is
  reported by the proxy, not measured by hardware.
* **The proxy source and its build.** `attest-proxy` is published source and
  its image is pinned by digest with build provenance, but "this digest was
  built from that commit" rests on GitHub's build attestation
  (`gh attestation verify`, above), not on a reproducible build, and the
  verifier does not run that command for you. "The keys were generated in the
  VM" is, in the end, a statement made by that program about itself: the
  quote proves which program said it, and you can read the program.
* **Docker's network isolation.** That the model server is unreachable from
  outside is declared in the measured compose and enforced by Docker and the
  kernel of the pinned OS image, inside the VM. It is not a hardware
  guarantee of its own.
* **The platform's pre-launch script.** The measured `app-compose.json`
  contains the hosting platform's stock pre-launch script. It can install SSH
  keys for root from the platform's unmeasured per-VM user configuration and
  from `DSTACK_*` variables. Those variables are not among the four allowed
  sealed variables, and the production OS image is documented as shipping no
  SSH server, but that last point is a property of the OS image that this
  repository has not verified independently. Replacing the stock script with
  a minimal one is planned.
* **The past.** Releases up to and including v0.1.0-rc.30 ran with
  operator-provisioned keys (signing seeds and the HPKE identity passed in
  through the compose) and with literal secrets in the compose file. Nothing
  in this repository vouches for them: for those releases the operator could
  have signed receipts and decrypted request bodies. Key generation inside
  the VM entered the proxy source with v0.1.0-rc.31; rc.31 and rc.32 were
  never deployed, and v0.1.0-rc.33, rolled out on 2026-11-24, is the first
  release that runs with it. The history here starts with it.
* **Operator-set environment variables.** The compose refers to four secrets
  as `${NAME}`: `HF_TOKEN`, `CLOUDFLARE_API_TOKEN`,
  `NV_ATTESTATION_SERVICE_KEY`, `METER_INGRESS_SHARED_SECRET`. Their values
  are supplied encrypted at deploy time and are not measured. The verifier
  fails unless that list is exactly the policy's and each is used only as an
  environment value. Read the compose to see what each one can influence.
  One consequence to know: whoever controls the domain's DNS (the operator
  does) can obtain a certificate for it with a different key. That is why the
  verifier compares the live certificate's key with the attested one, and why
  request bodies are additionally encrypted to the attested HPKE key.
* **Billing metadata leaves the enclave.** To charge for usage, the proxy
  sends signed metering records to the operator's billing service: input,
  cached and output token counts, the model name, timestamps, and a
  reservation and request identifier that billing ties to your account. Prompt
  and response *content* is not included, but the operator learns who used the
  service, when, and how much.
* **Traffic metadata.** Your IP address, request sizes and timing are visible
  to the network and the host.
* **This repository's recorder.** The 30-minute history is recorded by a
  workflow in a repository the operator controls. It cannot forge a passing
  Intel signature, and it cannot rewrite the past without breaking the chain
  and contradicting Sigstore's public log, but it could *omit* runs. Gaps are
  visible. The strongest check is still the one you run yourself.
* **The policy.** `policy.json` says which measurements are "expected". This
  verifier proves the machine matches the policy and the published compose; it
  is the compose and the source code, which you can read, that say whether that
  configuration deserves trust.

## Why Python, and these two dependencies

The verifier is about 2,500 lines of Python, comments included, with two direct dependencies,
pinned by version and by hash:

* [`cryptography`](https://cryptography.io) for X.509, ECDSA and hashing. It
  is the most widely reviewed cryptographic library in the Python ecosystem.
* [`dcap-qvl`](https://github.com/Phala-Network/dcap-qvl) for Intel's DCAP
  verification rules (collateral signatures, revocation lists, TCB level
  matching, Quoting Enclave identity). Those rules are long and easy to get
  subtly wrong, so a maintained, open implementation is safer than a new one.

Everything specific to this deployment is implemented here, independently of
the operator's client kit: quote parsing and its signature chain (so that path
has two implementations), `report_data` bindings, event-log replay, compose
hashing, receipt and NVIDIA token checks, live TLS key comparison, and a strict
reader for the small part of YAML that a compose file needs (instead of a
third dependency).

The alternative, reusing the JavaScript verifier from the client kit under
Node, was rejected: a third party would be running the operator's verification
code to check the operator, a shared bug would go unnoticed, and the npm
dependency tree is much larger to audit. One overlap remains and should be
known: the kit uses the JavaScript build of the same `dcap-qvl` library.

No network access is needed beyond the endpoint itself, Intel's collateral
service and NVIDIA's key set, and both of the latter can be supplied as files
(`--collateral`, `--nras-jwks`, `--offline`).

## Tests

```sh
python3 -m pip install --require-hashes -r tests/requirements.txt
python3 -m pytest tests
```

The suite builds a complete synthetic deployment (its own certificate chain,
quote, event log, GPU tokens and key attestation) and checks that every kind of
tampering turns the corresponding check to `FAIL`. The key-attestation format
is additionally checked against `tests/vectors/key-attestation-rc32.json`,
which the proxy's own handlers produced at v0.1.0-rc.32 (throwaway public keys
only; the handler source, `internal/server/status.go`, is identical in
v0.1.0-rc.33). Tests
against real captured evidence run only when private fixtures are supplied
through environment variables (`tests/conftest.py`); they are never stored
here. Among them: the rc.30 deployment description must be refused by the
secret scanner and by `tools/prepare_release.py`.

## The client policy and its signature

The verifier in this repository compares the endpoint with
`deployments/<release>/policy.json`. The operator's own clients (the `ack`
kit, the chat application) compare it with a different document: the *client
policy* at <https://verify.adverserial.ai/policies/production.json>. Whoever
can change that file can change what those clients accept, so it matters how
it is published.

The client policy is published through
[`AdverserialAI/confidential-policy`](https://github.com/AdverserialAI/confidential-policy):
a change is merged there, a GitHub Actions workflow signs the exact file with
Sigstore keyless signing after a named person approves the run, and the
signature is recorded in the public Rekor transparency log. There is no
signing key. A valid signature proves that the file was on `main` of that
repository and that the signing workflow ran on it; the log makes every such
signature public. It does not prove the policy is right: the operator can
still sign a policy for a different deployment, but not without leaving a
permanent public record under one identity.

Check it yourself; you need [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/):

```sh
curl -sSO https://verify.adverserial.ai/policies/production.json
curl -sSO https://verify.adverserial.ai/policies/production.json.sigstore.json
cosign verify-blob --bundle production.json.sigstore.json \
  --certificate-identity https://github.com/AdverserialAI/confidential-policy/.github/workflows/sign-policy.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-trigger push production.json
```

If the second download is a 404, the policy being served is not signed.

This repository watches that from the outside, with two workflows. They are
switched on by the repository variable `POLICY_WATCH_ENABLED=true`, which has
been set since 2026-11-24 19:25 UTC:

* **`policy-watch`** (every 30 minutes) runs `tools/check_published_policy.py`:
  the served policy and bundle are byte-identical to the `signed` branch of the
  policy repository, `cosign` accepts them for that one identity, and the
  client policy pins the same workload as `deployments/<CURRENT>/policy.json`
  here. While the current release is pending, the last check reports
  `INCOMPLETE` instead of passing.
* **`rekor-monitor`** (hourly) runs Sigstore's
  [rekor-monitor](https://github.com/sigstore/rekor-monitor): it checks that
  the transparency log stays append-only and opens an issue for every
  signature made by a workflow of the policy repository. Each one must
  correspond to a commit on that repository's `signed` branch. A signature
  with no such commit is a policy that was signed and not published. The
  monitor only looks forward from its first run, which was at 19:25 UTC on
  2026-11-24: the signature made at 19:03 UTC that day is older and is
  covered by `policy-watch` and the `cosign` command above, not by an issue.

A monitor in the operator's own organisation is a convenience, not
independence. The identity to watch is one regular expression,
`^https://github\.com/AdverserialAI/confidential-policy/\.github/workflows/.*$`
with issuer `https://token.actions.githubusercontent.com`; anyone can run the
same monitor from their own account, and is encouraged to.

## What is not here yet

As of 2026-11-24, 20:00 UTC (the evening of the first verified run):

* **A track record.** The history starts on 2026-11-24 at 19:22 UTC and is a
  few entries long. It proves that the endpoint verified at those moments.
  It says nothing about earlier releases (see "The past" above), and a claim
  such as "continuously verified" only becomes checkable as the file grows.
  Count the lines and read the timestamps before relying on it:
  `wc -l history/attestations.jsonl`.
* **A run started by the schedule.** The recorder and the two watch
  workflows have each passed once, started by hand, on 2026-11-24 at 19:25
  UTC. Their schedules were enabled at the same time, and by 20:00 UTC
  GitHub had not started one on its own. Until the history shows entries
  about 30 minutes apart, do not assume it is being extended.
* **GPU attestation by the OS.** Switched off in the measured manifest, see
  [GPU evidence](#gpu-evidence-what-is-and-is-not-verified). Every `PASS`
  here carries the warning `gpu.os_attestation`. Turning it on needs a
  change in the hosting provider's OS and will be a new release here.
* **GPU evidence bound to the VM.** NVIDIA's tokens are checked, but they are
  not bound to the TDX quote or to your nonce (`[N/A ] gpu.bound_to_vm`).
* **A published VM configuration.** RTMR0 depends on the virtual machine's
  shape. The hosting provider does not publish it and the attestation does
  not carry it, so the comparison of RTMR0 with the vendor's tool rests in
  part on inferred inputs (`deployments/CHANGELOG.md`).
* **A rebuilt or audited OS image, model server or proxy.** Hashes and build
  provenance are checked; nobody here has rebuilt the OS image or the model
  server from source, and the proxy build is not reproducible.
* **An independent recorder.** The history and both watch workflows run in a
  repository the operator controls. Nobody outside the operator has
  reported running the verifier or the log monitor yet.
* **A Sigstore attestation of entry `seq 0` alone.** It was recorded by hand,
  before the workflow was switched on. The first attested state of the
  history file is the one with `seq 0` and `seq 1` (19:26 UTC); it covers
  both lines.
* **A transparency-log watch of the first policy signature.** `rekor-monitor`
  looks forward from its first run (19:25 UTC); the signature of 19:03 UTC
  predates it.
* **`deployments/v0.1.0-rc.33/` will never be completed.** It describes the
  configuration on `dstack-nvidia-0.5.15`, which never served. It stays as
  published, with its pending policy, so that what was announced that
  morning remains on record; `deployments/CHANGELOG.md` marks it superseded.

## Licence

Apache License 2.0, see [LICENSE](LICENSE). Copyright 2026 Adverserial AI LLC.
