# GRC evidence-pack (example)

A read-side example built on the published `witseal` SDK. It turns a folder of
already-generated, signed WitSeal receipts into a **control-mapped evidence
pack** a compliance team can hand to a reviewer or push into a GRC system
(Drata / Vanta) for SOC 2 / ISO 27001 controls.

> This is an **example/prototype**, not part of the SDK's public API and not
> published to PyPI. It uses only the SDK's read-side surface
> (`witseal.verify` / `witseal.inspect`) and **mints no WitSeal artifact**:
> a "pack" is a bundle of report files over receipts generated elsewhere
> (canonical generation is the Rust trust core).

## What a pack contains

```
manifest.json             pack metadata (control, period, counts)
receipt_samples.json      redacted, shareable receipt copies
verification_results.json independent per-receipt verification outcome
control_mapping.json      control -> SOC 2 / ISO 27001 / ISO 42001 references
redaction_report.json     what was redacted, and why
hash_manifest.txt         SHA-256 of every other file (offline integrity)
executive_summary.md      plain-language summary for a reviewer
```

## Quickstart

```bash
# 1. mint sample signed receipts + the matching public key (demo scaffolding)
python -m witseal_grc.samples ./receipts --count 4 --key-out ./pubkey.pem

# 2. build a control-mapped pack and verify the receipts under the public key
python -m witseal_grc evidence pack \
    --source ./receipts --period 2026-06 \
    --control WIT-ENG-001 --public-key ./pubkey.pem

# 3. confirm pack integrity offline (re-hash every file vs the manifest)
python -m witseal_grc evidence verify \
    --pack ./witseal-evidence-WIT-ENG-001-2026-06.zip

# 4. build the GRC export request (dry-run: prints the request, sends nothing)
python -m witseal_grc evidence export \
    --target drata --control-code WIT-ENG-001 \
    --file ./witseal-evidence-WIT-ENG-001-2026-06.zip
```

Every command prints one JSON object (sorted keys); exit code is `0` on
success, `1` on a verification failure, `2` on an input error.

## Controls

The starter catalog covers engineering / change-management controls
(`WIT-ENG-001` … `WIT-ENG-005`) — see `witseal_grc/controls.py`. Framework
references are demo defaults; a real deployment tunes them to the customer's
control set.

## Export targets

| Target | Path | Carrier |
| --- | --- | --- |
| `drata` | Custom Connection record | native JSON |
| `vanta` | document upload | pack `.zip` |

Export is **dry-run by default**: it builds and prints the exact request
(with the API key redacted) and sends nothing. A live send is opt-in
(`--no-dry-run --api-key …` against a real tenant) and operator-run — no
credentials are needed to run or test the example.

## Run the example's tests

```bash
uv run pytest examples/grc-evidence-pack/tests -q
```
