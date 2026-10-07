# ADR 0005: russh transport, pinning and dependency policy

Date: 2026-10-06 (Asia/Manila)
Status: Accepted

Use russh 0.64.1 through `NetFactory::tcp_connect` and `client::connect_stream`. The original 0.54.6 pin cannot resolve on a fresh lockfile because libcrux-ml-kem 0.0.3 is yanked. Testing the next release, 0.55.0, exposed advisories including RUSTSEC-2026-0153 and RUSTSEC-2026-0154. Upgrade to the current release instead of suppressing those advisories. The `ring`, `rsa` and `des` features provide the required portable transport; compression is disabled.

The in-process replay server negotiates group1 SHA-1, ssh-rsa, AES-128-CBC and HMAC-SHA1 only after explicit per-device opt-in. Default negotiation uses `Preferred::DEFAULT`. Prefer modern algorithms even on an opted-in device; record whether negotiated algorithms actually were legacy. No system SSH subprocess fallback is needed for the locally tested case. Real 6.x equipment is still pending.

Host keys pin on first use in one SQLite transaction. A subsequent key or key-algorithm change is rejected; authentication and commands never proceed. There is no automatic repinning. Unknown host keys are accepted and audited as first seen. Commands are sequential and require the private-constructor allowlist type; output is capped at 4 MiB per command.

Cargo-deny includes one scoped exception for [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html). The current RSA crate has no patched version. NetworkMaster invokes RSA signing and signature verification for SSH, never RSA ciphertext decryption or PKCS#1 v1.5 depadding. Based on the [upstream padding issue](https://github.com/RustCrypto/RSA/issues/626), we assess the Marvin decryption oracle as unreachable in this use. This is an applicability assessment, not a claim that the dependency itself is fixed. Reassess the exception before adding RSA decryption, TLS RSA key exchange, or other RSA consumers. All other advisories remain enforced.

Session credentials are accessed inside an async arena closure. The arena mutex is released before network IO; forgetting removes the arena reference, and an in-flight authentication lease zeroizes when its closure ends. Raw output is scrubbed before persistence. Original config values are transiently parsed only to derive SNMP community presence/default booleans, never persisted.
