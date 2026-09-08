# Security engineering scripts

> Small utilities for dependency intelligence, Veracode integrations, and security testing.

This repository is a working toolbox rather than a packaged command-line product. The
scripts are intentionally close to the APIs and tools they automate, which makes them
easy to inspect and adapt for a particular environment.

## Start here TEST

| Task | Use | Notes |
| --- | --- | --- |
| Merge Veracode application SBOMs | [`python/merge_sbom_from_veracode.py`](python/merge_sbom_from_veracode.py) | Downloads CycloneDX CLI and writes a dated merged SBOM on Windows. |
| Generate a Veracode HMAC header in Node | [`javascript/veracode_hmac.js`](javascript/veracode_hmac.js) | ES module helper; reads `API_ID` and `API_KEY` from the environment. |
| Generate a Veracode HMAC header in CommonJS | [`javascript/veracode_hmac.cjs`](javascript/veracode_hmac.cjs) | CommonJS variant for older Node integrations. |
| Merge SBOMs from the JavaScript workflow | [`javascript/merge_sbom_from_veracode.js`](javascript/merge_sbom_from_veracode.js) | Uses Axios and the CycloneDX CLI. Review the enabled workflow before running. |
| Add affected-version data to a CVE CSV | [`powershell/get_cve_affected_versions.ps1`](powershell/get_cve_affected_versions.ps1) | Queries MITRE's CVE API and writes a new CSV column. |
| Scan a Maven dependency tree | [`powershell/sca/sca_scan.ps1`](powershell/sca/sca_scan.ps1) | Installs the Veracode SCA helper and runs a `srcclr` Maven scan. |
| Exercise a local test application | [`python/manuel_testing/application.py`](python/manuel_testing/application.py) | Local manual-testing helper; review it before exposing it to a network. |

## Quick start

### Python

Create an isolated environment before installing dependencies:

```sh
cd python
python3 -m venv local_env
. local_env/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

On Windows PowerShell, use `./setup_venv.bat` from the `python` directory or create
the environment manually. The Python SBOM script expects Veracode credentials to be
available to the Veracode signing library and downloads a Windows CycloneDX executable.

### JavaScript

```sh
cd javascript
npm ci
```

The package includes an `sbom` script, but its current command downloads a Windows
CycloneDX executable. Check the URL and output paths before using it on macOS or Linux.

### PowerShell

Run the scripts from PowerShell and inspect their parameters first:

```powershell
Get-Help .\get_cve_affected_versions.ps1 -Detailed
.\get_cve_affected_versions.ps1 `
  -inputpath .\input.csv `
  -outputpath .\output.csv `
  -cvecolumnname CVE `
  -newcolumnname AffectedVersion
```

The SCA helper expects Maven to be available and writes `tree.txt` in its working
directory before piping that dependency tree to `srcclr`.

## Credentials

Do not put Veracode credentials in source files, shell history, or committed CSV/JSON
outputs. The sample file [`python/credentials.sample`](python/credentials.sample)
shows the expected names for a local credentials file, while the JavaScript HMAC
helpers read:

```sh
export API_ID='your-veracode-api-id'
export API_KEY='your-veracode-api-key'
```

Use your platform's secret store in CI. The repository's ignore rules exclude local
Python environments, downloaded executables, SBOM directories, and generated JSON,
but generated files should still be reviewed before they are shared.

## Repository layout

```text
javascript/    Node helpers and Veracode SBOM integration
powershell/    CVE enrichment and Veracode SCA helpers
python/        SBOM merging, credentials sample, and local testing
```

## Operating notes

- Treat downloaded tools and third-party actions as dependencies: pin versions where
  the script is used in CI, and review release changes before upgrading.
- API responses are external input. Check status codes, response shape, and rate-limit
  behavior before using these scripts in an unattended job.
- The CVE enrichment utility calls MITRE once per row. For large files, add caching,
  backoff, and a retry policy before running it as a bulk process.
- The SBOM utilities create temporary files and delete them during cleanup. Run them
  in a dedicated working directory and confirm the output exists before removing the
  downloaded CycloneDX executable.
- These scripts are starting points for engineering workflows, not a substitute for
  validating results against the source system and the deployment's threat model.
