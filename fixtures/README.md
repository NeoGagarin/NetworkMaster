# Collection fixtures

The `synthetic-*` airOS sets and discovery `.bin` replies are generated examples for deterministic parser and transport tests. They are **not captured hardware results**. Real 6.x/8.x captures and AP/three-station validation remain pending; see `docs/HARDWARE-TESTING.md`.

Capture an enrolled device with `netmaster fixture capture --device <id> --out fixtures/airos/<model>-<firmware>/`. Assigned profiles prompt for session credentials. The command strips password/PSK/community/hash material and tokenizes IPs, MACs, names and SSIDs consistently across artifacts. Metadata records firmware/model, role, date and missing commands. Inspect every file before committing and keep one directory per device/firmware combination.

`test-keys/rsa` is a deliberately public, generated RSA test key for the local replay server. Never use it as a credential or server identity outside tests. It prevents slow RSA key generation in debug builds and needs no external key generator at test runtime.
