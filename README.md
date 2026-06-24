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

## Running locally

> Commands below are **Windows PowerShell**. On macOS/Linux the `dotnet` lines are identical; swap
> `Set-Content`→`echo`/`printf`, and `curl.exe`→`curl`.

### 0. Prerequisites
| Need | Why | Check / get |
|------|-----|-------------|
| **.NET 8 SDK** (8.0.x) | builds & runs everything — **net8 only, not net9** | `dotnet --version` → must print `8.0.x`. Get: <https://dotnet.microsoft.com/download/dotnet/8.0> |
| **Git** | clone the repo | `git --version` |
| Docker Desktop *(optional)* | only for the container path | `docker --version` |
| Azure CLI *(optional)* | only for the Key Vault path | `az --version` |

### 1. Get the code
```powershell
git clone https://github.com/joseriveramorales/notary.git
cd notary
```

### 2. Build & test
```powershell
dotnet build                 # compile all 3 projects + tests (add -c Release to match CI)
dotnet test                  # 11 tests: sign/verify, tamper, untouched, key reload, timestamp, Key Vault, API
```
All 11 should pass. (The live Key Vault test no-ops unless `NOTARY_KEYVAULT_URI` is set.)

### 3. Use the CLI (notarize → verify → tamper)
```powershell
# a document to notarize
"I, Jose Rivera, agree to ship on 2026-06-21." | Set-Content contract.txt -NoNewline

# notarize (first run also creates notary-key.pfx); --timestamp also writes a .tsr proving WHEN
dotnet run --project src/Notary.Cli -- notarize ./contract.txt --timestamp

# verify  ->  [Trusted] ... (exit code 0)
dotnet run --project src/Notary.Cli -- verify ./contract.txt

# tamper: flip one byte, then verify again  ->  [Tampered] (exit code 2)
$b=[IO.File]::ReadAllBytes("contract.txt"); $b[3]=$b[3] -bxor 1; [IO.File]::WriteAllBytes("contract.txt",$b)
dotnet run --project src/Notary.Cli -- verify ./contract.txt
```
- The `--` separates `dotnet`'s arguments from the app's arguments — keep it.
- Outputs land **next to the file**: `contract.txt.sig`, `.cert`, and (with `--timestamp`) `.tsr`. The key is `notary-key.pfx` in the repo root.
- `notary-key.pfx`, the sidecars, and `contract.txt` are **gitignored** — keep the `.pfx` safe and off iCloud.
- `--timestamp` uses an in-process RFC 3161 TSA (offline); `--tsa <url>` uses a real public TSA. `--keyvault <uri> --cert <name>` signs in Azure Key Vault (auth via `DefaultAzureCredential`).

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

## Web API — run locally (no Docker)
```powershell
# bind an explicit URL (there is no launchSettings.json, so always pass --urls)
dotnet run --project src/Notary.Api --urls http://localhost:5080
```
Leave it running, then in a **second** terminal:
```powershell
curl.exe http://localhost:5080/health            # {"status":"ok"}
curl.exe http://localhost:5080/                  # lists the endpoints

# sign -> JSON with base64 signer/signature/certificate/timestamp
$r = curl.exe -s -F "file=@contract.txt" -F "timestamp=true" http://localhost:5080/sign | ConvertFrom-Json
$r.signature   | Set-Content sig.b64  -NoNewline
$r.certificate | Set-Content cert.b64 -NoNewline

# verify -> 200 {status:"Trusted"} ... or 422 {status:"Tampered"}
curl.exe -s -F "file=@contract.txt" -F "signature=<sig.b64" -F "certificate=<cert.b64" http://localhost:5080/verify
```
> Use **`curl.exe`** (ships with Windows), *not* PowerShell's `curl` alias — that's `Invoke-WebRequest` and doesn't accept `-F`.

By default the API uses an **ephemeral key** regenerated each start (sidecars won't verify across restarts).
Point it at a real key with env vars before `dotnet run`: `NOTARY_KEYVAULT_URI` (+`NOTARY_KEYVAULT_CERT`) → Key Vault,
or `NOTARY_KEY_PATH` (+`NOTARY_KEY_PASS`) → a local PFX.

## Web API — Docker
```powershell
docker build -t notary-api .
docker run -p 8088:8080 notary-api               # container listens on 8080 -> mapped to 8088
curl.exe http://localhost:8088/health
# real key: docker run -p 8088:8080 -v C:\keys:/keys -e NOTARY_KEY_PATH=/keys/notary-key.pfx -e NOTARY_KEY_PASS=... notary-api
```

## Troubleshooting
| Symptom | Fix |
|---------|-----|
| `dotnet` not found / `--version` isn't `8.0.x` | Install the **.NET 8** SDK (this repo is net8 only). |
| Build error: `X509CertificateLoader` / missing `System.Security.Cryptography.Pkcs` | You're on a non‑8.0 SDK or skipped restore → use the 8.0 SDK and run `dotnet restore`. |
| `curl` does nothing useful in PowerShell | Use `curl.exe`, not the `curl` alias. |
| `Address already in use` | Pick a free port: change `--urls http://localhost:<port>` or `-p <host>:8080`. |
| API `/verify` returns 500 on a junk certificate | Known hardening item (see [docs/GUIDE.md](docs/GUIDE.md) §4.4) — not a setup problem. |
| `docker build` fails to connect | Start **Docker Desktop** first. |

> Full walkthrough, debugging recipes, and a study guide live in [docs/GUIDE.md](docs/GUIDE.md);
> the maths in [docs/MATH.md](docs/MATH.md).

## CI
`.github/workflows/ci.yml` runs on every push/PR: restore → build (Release) → `dotnet test`, then a
second job builds the Docker image to keep the `Dockerfile` honest.
The `ISigningProvider` interface is the seam: `LocalKeySigningProvider` (PFX on disk) or
`KeyVaultSigningProvider` (key never leaves Azure Key Vault) — `NotaryService` and the verifier
don't change. `verify` only ever needs the public `.cert`, so it's identical no matter where the
private key lived.
`ITimestampAuthority` mirrors that seam for timestamping: `LocalTimestampAuthority` (in-process,
offline) or `HttpTimestampAuthority` (real public TSA) — `NotaryService` doesn't care which.
