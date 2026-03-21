# Auto-Scan Setup

Enable automated CVE scanning for any Node.js repo, with results reported to the git-steer dashboard.

## Prerequisites

- A Node.js repo with a `package-lock.json`
- Access to the git-steer dashboard at https://git-steer.ry-ops.dev

## Installation

### 1. Copy the workflow

Copy `.github/workflows/cve-scan.yml` from this repo into the target repo:

```
target-repo/
  .github/
    workflows/
      cve-scan.yml
```

### 2. Add repository secrets

In the target repo, go to **Settings > Secrets and variables > Actions** and add:

| Secret | Required | Description |
|--------|----------|-------------|
| `GIT_STEER_TOKEN` | Yes | API token for authenticating with the git-steer dashboard |
| `GIT_STEER_URL` | No | Dashboard URL (defaults to `https://git-steer.ry-ops.dev`) |

### 3. Enable auto-scan via the dashboard

Register the repo for auto-scanning through the dashboard API:

```bash
curl -X POST https://git-steer.ry-ops.dev/api/autoscan/OWNER/REPO \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

Or use the dashboard UI to enable it.

## How It Works

### Schedule

The workflow runs automatically on **weekdays at 8:00 AM UTC**. It can also be triggered manually via GitHub Actions workflow_dispatch.

### Scan Process

1. Checks out the repo and runs `npm audit --json`
2. Parses the audit output into a structured summary (critical/high/medium/low counts)
3. Reports results to the git-steer dashboard via `POST /api/scans/report`
4. Uploads raw audit results as a workflow artifact (retained 30 days)
5. Writes a summary table to the GitHub Actions step summary

### Auto-Fix (opt-in)

When triggering manually, you can enable **auto_fix** to have the workflow:

1. Run `npm audit fix --force`
2. Create a branch (`security/auto-fix-YYYYMMDD`)
3. Open a pull request with the fix and scan summary

This is only available via workflow_dispatch (not on the scheduled runs).

### Dashboard Integration

Scan results are sent to `POST /api/scans/report` with this payload:

```json
{
  "repo": "owner/repo",
  "timestamp": "2026-03-21T08:00:00.000Z",
  "total": 5,
  "critical": 1,
  "high": 2,
  "medium": 1,
  "low": 1,
  "vulnerabilities": [
    {
      "package": "example-pkg",
      "severity": "high",
      "range": ">=1.0.0 <1.2.3",
      "fix_available": true,
      "via": "Prototype Pollution"
    }
  ]
}
```

The dashboard report is best-effort -- if the dashboard is unreachable, the scan still completes and artifacts are uploaded.

## Manual Trigger

Go to the repo's **Actions** tab, select **git-steer CVE Scan**, and click **Run workflow**. You can choose:

- **Minimum severity** to report (CRITICAL, HIGH, MEDIUM, LOW)
- **Auto-fix** toggle to create a fix PR automatically
