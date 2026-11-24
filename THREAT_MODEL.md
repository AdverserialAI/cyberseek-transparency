# Threat model

Short version: assume the operator, the cloud host and the network are all
willing to cheat. This document lists what each could try and which check
stops it, then what nothing here stops.

## What is being protected

* The content of prompts and responses.
* The user's ability to know which software handles them.
* The integrity of the public record of what was deployed, and when.

## Who is assumed hostile

| Party | Capabilities assumed |
|---|---|
| Operator (Adverserial) | Deploys and restarts the VM, chooses the compose and environment variables, controls DNS, the billing service, and this repository |
| Host (Phala, data centre) | Controls the hypervisor, storage, the physical machine and the network path |
| Network attacker | Can intercept, replay and redirect traffic |

Not assumed hostile, because nothing here can check them: Intel, NVIDIA, and
the published dstack OS image (see "Residual trust").

## Attacks and the check that catches them

| Attack | Caught by |
|---|---|
| Serve from an ordinary server and fake the attestation | `tdx.quote_signature`, `tdx.collateral_tcb`: the quote must be signed under Intel's root |
| Run a TDX VM in debug mode, where the host can read memory | `tdx.not_debug` |
| Run on a revoked or out-of-date platform | `tdx.collateral_tcb` against the policy's accepted statuses |
| Replay an attestation recorded earlier from a genuine VM | `binding.nonce`, `binding.report_data`: the quote must contain the verifier's fresh nonce |
| Terminate TLS outside the VM and forward to it (man in the middle) | `tls.live_spki`: the live certificate key must be the attested key; request bodies are additionally encrypted to the attested HPKE key (`binding.ehbp_key`, `keys.hpke_endpoint`) |
| Substitute a different HPKE or receipt key | `binding.report_data`, `keyatt.keys_match` |
| Publish a billing key that is not the VM's | `keyatt.meter_key`: the served key set must be exactly the key in the quote-bound statement |
| Boot a modified kernel or OS image | `policy.mrtd`, `policy.rtmr0-2`, `policy.os_image_hash` |
| Quietly switch off the OS's GPU attestation, or claim it ran when it did not | The GPU policy is part of the measured manifest (`policy.compose_hash`) and is measured on its own (`policy.gpu_policy_hash`); `gpu.os_attestation` reports `WARN` on every run while it is off, and fails if the event log and the policy contradict each other. `eventlog.boot_order` rejects a `gpu-policy-hash` or `gpu-attestation` event written after boot |
| Deploy a modified compose (extra logging container, different image) | `eventlog.replay`, `policy.compose_hash`, `compose.app_compose_hash`, `compose.images_pinned` |
| Expose the model server directly, bypassing the proxy | `compose.inference_isolated`, `compose.single_ingress`: no published port, no host networking, internal network shared only with the proxy |
| Change what the measured compose means through an unmeasured variable | `compose.unmeasured_inputs`: deploy-time substitution is accepted only as a whole environment value, for exactly the names the policy lists |
| Hide configuration in YAML anchors, merge keys or included files | The strict compose reader rejects them, which fails every structural check |
| Append a second, benign-looking `compose-hash` event after boot | `eventlog.boot_order`: identity events must be unique and inside the boot boundary |
| Publish a compose that is not the one running | `compose.app_compose_hash`, `compose.docker_compose`: the published bytes must hash to the measured value |
| Keep signing or decryption keys outside the VM | `compose.keys_in_enclave`: the proxy is given a key directory and none of the variables that carry key material, and runs a build that refuses them; `keyatt.keys_origin`: the measured proxy states `enclave-generated` inside a quote |
| Run the proxy outside confidential mode, with an operator seed | `compose.keys_in_enclave` requires `CONFIDENTIAL_MODE`; `keyatt.keys_origin` would read `operator-seed` |
| Use a development build that fabricates evidence | `evidence.format` rejects `dev: true` |
| Present key-attestation from a different VM | `keyatt.quote`: measurements must equal the fresh quote's |
| Forge NVIDIA tokens or point the verifier at a fake NVIDIA service | `gpu.signatures`: the key set is fetched from a fixed NVIDIA address |
| Quietly change production between releases | The recorder fails and opens an issue when measurements match no `deployments/` entry |
| Rewrite or delete history after the fact | Hash chain (`history/check_chain.py`), the append-only check in CI, and Sigstore/Rekor timestamps of each head held outside the operator's control |
| Edit a published release directory | CI rejects modifications to existing release files; each file has a Sigstore attestation |
| Commit a credential to this public repository | `tools/check_no_secrets.py` runs before every commit made by CI and on every pull request |
| Tamper with the verifier's dependencies or the CI actions | Dependencies are installed with `--require-hashes`; actions are pinned by commit SHA |

## What is not caught

* **A hardware or firmware break of Intel TDX or of NVIDIA's GPU isolation**,
  or a compromise of their signing keys.
* **A malicious or flawed dstack OS image or KMS.** They are pinned and
  identified, not audited. The `dstack-0.6.5` image is a public download whose
  hash anyone can recompute, built from a public tag, but it carries no
  signed build provenance and has not been rebuilt here.
* **GPUs that are not in their protected mode.** In the current release the
  measured manifest says `"attest_gpu": false`: the OS (dstack 0.6.5) releases
  the VM's keys without attesting the GPUs or checking their confidential
  mode, because its check does not recognise the multi-GPU Protected PCIe mode
  that eight-GPU H200 machines use. The opt-out is visible (measured manifest,
  `gpu-policy-hash` event, no `gpu-attestation` event, `WARN` on every run and
  in every history line), but being visible is all it is: a host that left
  the GPUs unprotected would not be caught by any check here. NVIDIA's remote
  attestation, which the collector still obtains, proves genuine GPUs,
  accepted firmware, secure boot and debug off; it does not by itself prove
  Protected PCIe mode. dstack 0.5.x had no such check either, so this is not
  a regression, but it is a gap.
* **GPU substitution.** GPU evidence is not bound to the TDX quote. A hostile
  host that could attach a different, non-confidential GPU while the measured
  collector still obtains passing tokens from other GPUs would not be detected
  by this verifier.
* **Behaviour of pinned but unaudited images.** The inference server is pinned
  by digest and not reproducibly built. Attestation proves which image runs,
  not that the image is harmless.
* **Operator-supplied environment values.** They are unmeasured. A variable
  that could redirect data (an upstream URL, for instance) must not be in
  `allowed_envs`; reviewers of `deployments/` should treat additions to that
  list as security-relevant.
* **Metadata.** Billing records (token counts, account, time) and network
  metadata leave the VM by design.
* **Side channels** such as timing and response length.
* **Model behaviour.** Attestation says nothing about answer quality or about
  what the model was trained to do.
* **Omission.** The operator's recorder can skip runs or stop. It cannot
  produce a false `PASS`, but silence is only detectable as a gap in a
  30-minute series.
* **Freshness of the key statement.** The key-attestation endpoint has no
  nonce. Its statement is trusted only in combination with a fresh quote from
  the same measured VM, issued within six minutes of it, and for the keys that
  fresh quote also binds. The meter key appears only in the statement.
* **A proxy that lies about itself.** `keys_origin` is a claim made by the
  proxy. The quote proves which proxy image made it; that this image behaves
  as its source says rests on its build provenance
  (`gh attestation verify oci://ghcr.io/adverserialai/attest-proxy@<digest> -R AdverserialAI/attest-proxy`),
  which the verifier does not run for you, and the list of acceptable digests
  comes from the operator's policy.
* **Releases before v0.1.0-rc.33.** Up to and including v0.1.0-rc.30 the
  operator provisioned the signing seeds and the HPKE identity and the compose
  held literal secrets. This repository proves nothing about that period.
  (v0.1.0-rc.31 and rc.32 were never deployed.)
* **A release that was never verified.** A release whose policy is marked
  `pending` has been rolled out but not attested; its measurements are not
  known here. The verifier refuses to return `PASS` against it, and the
  history says `policy_state: pending` on every line recorded in that period.
  When the policy is completed, the measurements come from the first live
  attestation: compare them with the OS image vendor's published values
  yourself, as the person completing the policy is asked to.
* **A release that never served.** `deployments/v0.1.0-rc.33/` was published
  as pending on 2026-11-24 and overtaken the same day, when the hosting
  provider replaced the OS image. Nothing was ever verified under it. It is
  kept as published and marked superseded in the changelog; its policy can
  never be completed.
* **Verifier bugs.** This code is small so that it can be reviewed. Review it.

## Residual trust, in one sentence

After a `PASS` you are trusting Intel, NVIDIA, the dstack OS image and KMS, the
unaudited inference image, and your own reading of the published compose and
proxy source; you are no longer trusting the operator's or the host's word,
with one exception while `gpu.os_attestation` reads `WARN`: that the host put
the GPUs into their protected mode.

## Operational assumptions for this repository

* `main` is meant to be protected: no force pushes, and changes to
  `deployments/`, `verify/`, `tools/` and `.github/` require review. **As of
  2026-11-24 that protection is not switched on yet**: the repository is new
  and its owners push to `main` directly. Until it is on, the immutability of
  published releases is enforced only on pull requests, and otherwise rests
  on the Sigstore attestations of each deployment file and on anyone's clone.
  The recorder is the only automated writer and touches only `history/`.
* The recorder's workflow token is limited to contents, issues, attestations
  and OIDC signing. No deployment credential is ever present in this
  repository or its CI.
* Third parties are encouraged to mirror the repository; any clone can detect a
  rewritten history.
