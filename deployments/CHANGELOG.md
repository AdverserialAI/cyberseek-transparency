# Deployment changelog

One section per release directory, newest first. The heading must be exactly
`## <directory name>`; `tools/validate_deployments.py` checks that it exists.

Each entry states: date of rollout, what changed and why, the new compose hash
and COMPOSE_DIGEST, whether MRTD/RTMR0-2 or the OS image changed, and which
keys rotated. A release that is rolled out but has not been verified live yet
carries a `Status:` line saying so, and its `policy.json` is marked pending
(see `README.md` in this directory).

<!-- Add new releases directly below this line. -->

## v0.1.0-rc.33
- Status: ROLLED OUT, NOT YET VERIFIED LIVE. The policy is pending: measurements, TLS pin and receipt key pending first live attestation
- Rolled out: 2026-11-24
- Changes: First release published in this repository, and the first with keys generated inside the VM. attest-proxy v0.1.0-rc.33 generates its signing and HPKE keys in the VM and refuses to start if the operator supplies one (in the proxy source since v0.1.0-rc.31; rc.31 and rc.32 were never deployed, rc.33 is the first one rolled out). The compose holds no literal secrets, only four ${NAME} references, and the model server sits on an internal network behind the proxy. Rolled out together with the hosting provider's KMS and OS image migration; previous releases (up to v0.1.0-rc.30) are not published here because their compose contained secrets.
- Proxy: v0.1.0-rc.33
- compose_hash: 275c6e538a381def20642459b5f5b37f5684d50b877604ee593c449ae51b1a1d
- COMPOSE_DIGEST: sha256:96ba75d8d59d93069da02661e2e6078f82b4cd7d2745a5b8b528057809831da4
- OS image: dstack-nvidia-0.5.15, os_image_hash 3bb7d262416f47db06855d7b7cf7d380538747206014b3c0adcddfef9b7c4ef2
- MRTD, RTMR0-2: pending first live attestation
- Images: ghcr.io/adverserialai/attest-proxy@sha256:5a41bcfb6d7f4f3d3df53ad5ac39a45d1d32a6db206e35c0380b81d56404824b, ghcr.io/adverserialai/gpu-evidence-collector@sha256:88484069fde3c53f054b7d02645ab075166a24c0a43c2006723f148941967f06, vllm/vllm-openai@sha256:91ee972ab751fb7180bc71c175865e36b091686600dca783d52b2511399810b3, ghcr.io/adverserialai/model-measurer@sha256:5f5f0653a7f75a1414a68a0e063ba7fb628f225cfb81e3a21512c206c7f4ad82, lmsysorg/sglang@sha256:b4f09a2ccbcfcc262d49600c3cd7f8581a793ea7d104947257b6a95500953b90
- Operator-supplied variables (allowed_envs): CLOUDFLARE_API_TOKEN, HF_TOKEN, METER_INGRESS_SHARED_SECRET, NV_ATTESTATION_SERVICE_KEY
- First history entry under this release: none yet, pending first live attestation
