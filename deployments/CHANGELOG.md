# Deployment changelog

One section per release directory, newest first. The heading must be exactly
`## <directory name>`; `tools/validate_deployments.py` checks that it exists.

Each entry states: date of rollout, what changed and why, the new compose hash
and COMPOSE_DIGEST, whether MRTD/RTMR0-2 or the OS image changed, and which
keys rotated. A release that is rolled out but has not been verified live yet
carries a `Status:` line saying so, and its `policy.json` is marked pending
(see `README.md` in this directory). A pending release that was overtaken
before it ever answered carries `- Status: SUPERSEDED BEFORE IT EVER SERVED`
instead; its directory stays as published and is never completed.

<!-- Add new releases directly below this line. -->

## v0.1.0-rc.33-os-0.6.5
- Status: ROLLED OUT, NOT YET VERIFIED LIVE. The policy is pending: measurements, TLS pin and receipt key pending first verified live attestation
- Rolled out: 2026-11-24 (OS image replaced about 14:00 UTC, proxy up 14:47 UTC)
- Changes: The hosting provider (Phala) replaced the OS image on 2026-11-24 at about 14:00 UTC: dstack-nvidia-0.5.15, on which one of the eight GPUs failed to initialise at every boot (NVIDIA driver 595.58.03), gave way to dstack-0.6.5 (one image, NVIDIA driver 595.91.07, no separate nvidia variant). The provider also changed two fields of the measured manifest: manifest_version 2 became "3" (a string), and "requirements":{"gpu_policy":{"attest_gpu":false}} was added. The docker compose text, the pre-launch script, the image digests and the operator-supplied variables are byte-identical to v0.1.0-rc.33, which this release supersedes and which never served a request. Why attest_gpu is false: dstack 0.6.x by default attests the GPUs at boot and requires each GPU's Confidential Computing mode to be on before it releases the VM's keys. Systems with eight H200 GPUs run in NVIDIA's multi-GPU Protected PCIe mode, in which the per-GPU Confidential Computing status reads off; the check in 0.6.5 does not recognise that mode and refuses to boot, so the provider switched the check off and says it will add support and tell us when the flag can be removed. Consequence: the protection is the same as on dstack 0.5.x, which never had this check, but nothing in the measured boot chain currently verifies the GPUs' protected mode. The opt-out is public: it is in the measured app-compose.json and in the RTMR3 event gpu-policy-hash, and there is no gpu-attestation event. The verifier reports it on every run as WARN gpu.os_attestation. Proxy v0.1.0-rc.33 came up at 14:47 UTC with keys generated inside the VM; the model was ready at 15:01 UTC; the VM was restarted once more at 15:39 UTC to replace one sealed variable (the key for NVIDIA's attestation service was not entitled, so the GPU evidence was stale), with the same configuration and compose hash.
- Proxy: v0.1.0-rc.33
- compose_hash: 9c78bf82dfad3a133838f2ac87406b3fe1c9d875d8a4d5fbe04e9f34d7d3b820
- COMPOSE_DIGEST: sha256:96ba75d8d59d93069da02661e2e6078f82b4cd7d2745a5b8b528057809831da4
- OS image: dstack-0.6.5, os_image_hash 4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623
- MRTD, RTMR0-2: pending first live attestation
- GPU policy (requirements.gpu_policy in the measured manifest): {"attest_gpu":false}, gpu_policy_hash 930188e08f58d0c555acff500a40be79c1f7e1d9ae23d26d901486cc9cc1a77d. GPU attestation by the OS is DISABLED by this policy
- Images: ghcr.io/adverserialai/attest-proxy@sha256:5a41bcfb6d7f4f3d3df53ad5ac39a45d1d32a6db206e35c0380b81d56404824b, ghcr.io/adverserialai/gpu-evidence-collector@sha256:88484069fde3c53f054b7d02645ab075166a24c0a43c2006723f148941967f06, vllm/vllm-openai@sha256:91ee972ab751fb7180bc71c175865e36b091686600dca783d52b2511399810b3, ghcr.io/adverserialai/model-measurer@sha256:5f5f0653a7f75a1414a68a0e063ba7fb628f225cfb81e3a21512c206c7f4ad82, lmsysorg/sglang@sha256:b4f09a2ccbcfcc262d49600c3cd7f8581a793ea7d104947257b6a95500953b90
- Operator-supplied variables (allowed_envs): CLOUDFLARE_API_TOKEN, HF_TOKEN, METER_INGRESS_SHARED_SECRET, NV_ATTESTATION_SERVICE_KEY
- First history entry under this release: none yet, pending first live attestation

## v0.1.0-rc.33
- Status: SUPERSEDED BEFORE IT EVER SERVED (2026-11-24): the provider replaced the OS image. This configuration never answered a request: on dstack-nvidia-0.5.15 one of the eight GPUs failed to initialise at every boot (NVIDIA driver 595.58.03), and at about 14:00 UTC the hosting provider moved the VM to dstack-0.6.5, which changes the OS image hash and the compose hash. Replaced by v0.1.0-rc.33-os-0.6.5. The directory is kept exactly as published; its policy.json stays marked pending and will never be completed, so no measurements, TLS pin or receipt key exist for it and no history entry will ever name it
- Rolled out: 2026-11-24
- Changes: First release published in this repository, and the first with keys generated inside the VM. attest-proxy v0.1.0-rc.33 generates its signing and HPKE keys in the VM and refuses to start if the operator supplies one (in the proxy source since v0.1.0-rc.31; rc.31 and rc.32 were never deployed, rc.33 is the first one rolled out). The compose holds no literal secrets, only four ${NAME} references, and the model server sits on an internal network behind the proxy. It was rolled out together with the hosting provider's KMS and OS image migration; previous releases (up to v0.1.0-rc.30) are not published here because their compose contained secrets.
- Proxy: v0.1.0-rc.33
- compose_hash: 275c6e538a381def20642459b5f5b37f5684d50b877604ee593c449ae51b1a1d
- COMPOSE_DIGEST: sha256:96ba75d8d59d93069da02661e2e6078f82b4cd7d2745a5b8b528057809831da4
- OS image: dstack-nvidia-0.5.15, os_image_hash 3bb7d262416f47db06855d7b7cf7d380538747206014b3c0adcddfef9b7c4ef2
- MRTD, RTMR0-2: never observed (no attestation of this configuration exists)
- Images: ghcr.io/adverserialai/attest-proxy@sha256:5a41bcfb6d7f4f3d3df53ad5ac39a45d1d32a6db206e35c0380b81d56404824b, ghcr.io/adverserialai/gpu-evidence-collector@sha256:88484069fde3c53f054b7d02645ab075166a24c0a43c2006723f148941967f06, vllm/vllm-openai@sha256:91ee972ab751fb7180bc71c175865e36b091686600dca783d52b2511399810b3, ghcr.io/adverserialai/model-measurer@sha256:5f5f0653a7f75a1414a68a0e063ba7fb628f225cfb81e3a21512c206c7f4ad82, lmsysorg/sglang@sha256:b4f09a2ccbcfcc262d49600c3cd7f8581a793ea7d104947257b6a95500953b90
- Operator-supplied variables (allowed_envs): CLOUDFLARE_API_TOKEN, HF_TOKEN, METER_INGRESS_SHARED_SECRET, NV_ATTESTATION_SERVICE_KEY
- First history entry under this release: none, and there will be none
