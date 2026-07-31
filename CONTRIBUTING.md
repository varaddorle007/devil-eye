# Contributing

Devil Eye is an **authorized-use** cybersecurity toolkit. Do not contribute exploit payloads, credential theft, malware, or unauthorized-access features.

## Development

```powershell
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

Live capture (optional, Windows):

```powershell
$env:LIB = "$env:USERPROFILE\npcap-sdk\Lib\x64;$env:LIB"
cargo test --features live
```

## Pull requests

1. Keep modules scoped and audited where active probing is involved.
2. Prefer offline PCAP fixtures for CI-safe tests.
3. Update `CHANGELOG.md` for user-facing changes.
4. Do not commit secrets, capture files with sensitive traffic, or audit logs.

## Releases

1. Bump version in `Cargo.toml` and update `CHANGELOG.md`.
2. Tag: `git tag v0.x.y && git push origin v0.x.y`
3. GitHub Actions `Release` workflow builds and attaches binaries.
4. Local Windows zip: `powershell -File scripts\package-windows.ps1`
