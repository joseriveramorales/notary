# Personal Notary

[![CI](https://github.com/joseriveramorales/notary/actions/workflows/ci.yml/badge.svg)](https://github.com/joseriveramorales/notary/actions/workflows/ci.yml)

A small **code-signing service** in C# / .NET. It signs and timestamps your own
documents so you can later **prove** any one of them existed on a given date and has
not been altered — verifiable by anyone, offline, without trusting the cloud that stores it.

Built to learn the cryptographic-trust domain (hashing, digital signatures, X.509/PKI,
Azure Key Vault, code signing).

## Architecture rule
- **This repo lives in your dev folder — never in iCloud.**
- The tool **operates on documents inside a folder you point it at** (e.g. an iCloud
  `Notary\` folder), writing detached sidecars next to each file.
- The signing key can be local (a PFX) **or** in **Azure Key Vault** (`--keyvault`), where the
  private key never leaves the vault — same `ISigningProvider` contract either way.

## What it does (detached signatures — originals never modified)
For `contract.pdf` it produces:
| File | Meaning |
|------|---------|
| `contract.pdf` | your original, untouched |
| `contract.pdf.sig` | signature over the file's SHA-256 hash |
| `contract.pdf.cert` | X.509 certificate (public key + identity) to verify with |
| `contract.pdf.tsr` | *(optional)* RFC 3161 trusted timestamp over the same hash — proves *when* |

## Run it
```bash
dotnet test                                   # 8 tests: trusted, tampered, untouched, reload, +2 timestamp, +2 key vault
dotnet run --project src/Notary.Cli -- notarize ./contract.pdf
dotnet run --project src/Notary.Cli -- notarize ./contract.pdf --timestamp   # also write .tsr (proves WHEN)
dotnet run --project src/Notary.Cli -- notarize ./contract.pdf \
    --keyvault https://my-vault.vault.azure.net --cert notary                # sign in Azure Key Vault
dotnet run --project src/Notary.Cli -- verify   ./contract.pdf               # identical regardless of key location
```
First local `notarize` generates `notary-key.pfx` (gitignored — keep it safe, off iCloud).
`--timestamp` uses an in-process RFC 3161 TSA (offline); `--tsa <url>` uses a real public TSA instead.
`--keyvault` authenticates with `DefaultAzureCredential` (env vars / managed identity / `az login`).

## Roadmap
1. ✅ Hash + sign + verify bytes (SHA-256, ECDSA P-256)
2. ✅ File-level detached signatures + self-signed X.509 cert
3. ✅ CLI `notarize` / `verify`, point at any folder, tamper detection
4. ✅ RFC 3161 trusted timestamping (`.tsr` sidecar) — proves *when* (`ITimestampAuthority`: local + HTTP)
5. ✅ Move the key into Azure Key Vault (swap `ISigningProvider`) — `KeyVaultSigningProvider`, key stays in the vault
6. ✅ ASP.NET Core Web API (`/sign`, `/verify`) + Docker + CI — same `NotaryService`, over HTTP, containerized, GitHub Actions

## Layout
```
src/Notary.Core   hashing, ISigningProvider (local PFX + Azure Key Vault), ITimestampAuthority (RFC 3161), NotaryService
src/Notary.Cli    notarize / verify commands
src/Notary.Api    ASP.NET Core /sign + /verify (Dockerfile at repo root)
tests/Notary.Tests  xUnit tests (incl. in-process API integration tests)
```

## Web API + Docker
```bash
docker build -t notary-api .
docker run -p 8088:8080 notary-api          # ephemeral key; mount a PFX or set NOTARY_KEYVAULT_URI for real use

# sign (multipart) -> JSON { signer, signature, certificate, timestamp? } as base64
curl -s -F file=@contract.txt -F timestamp=true http://localhost:8088/sign
# verify -> 200 + {status:"Trusted",...}  or  422 + {status:"Tampered",...}
curl -s -F file=@contract.txt -F signature=<sig.b64 -F certificate=<cert.b64 http://localhost:8088/verify
```
The API is a thin shell over `NotaryService.SignBytes` / `VerifyBytes` — no filesystem, key location
chosen by env vars (`NOTARY_KEYVAULT_URI` → `NOTARY_KEY_PATH` → ephemeral dev key).

## CI
`.github/workflows/ci.yml` runs on every push/PR: restore → build (Release) → `dotnet test`, then a
second job builds the Docker image to keep the `Dockerfile` honest.
The `ISigningProvider` interface is the seam: `LocalKeySigningProvider` (PFX on disk) or
`KeyVaultSigningProvider` (key never leaves Azure Key Vault) — `NotaryService` and the verifier
don't change. `verify` only ever needs the public `.cert`, so it's identical no matter where the
private key lived.
`ITimestampAuthority` mirrors that seam for timestamping: `LocalTimestampAuthority` (in-process,
offline) or `HttpTimestampAuthority` (real public TSA) — `NotaryService` doesn't care which.
