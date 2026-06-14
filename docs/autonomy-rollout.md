# git-steer Autonomy Rollout

Event-driven, self-merging dependency & security management across all managed
`ry-ops` repos. Once rolled out, Dependabot opens grouped security/version PRs,
git-steer approves them, and GitHub-native auto-merge lands them when CI is
green — **without bypassing branch protection** (the App's approving review
satisfies the required-review rule; it is not skipped).

## Architecture

```
Dependabot alert ──▶ Dependabot opens (grouped) fix PR        [detect + remediate, event-driven]
                          │
                          ▼
        .github/workflows/dependabot-automerge.yml             [per-repo engine]
          ├─ mint git-steer App token (org secrets)
          ├─ fetch-metadata → semver type
          ├─ patch/minor → approve + `gh pr merge --auto`       [autonomous]
          └─ major        → label needs-human-merge             [escalate]
                          │
                          ▼
        GitHub native auto-merge lands PR once checks pass      [merge, protection intact]
```

git-steer's own `security-fix-worker` / `security-sweep-worker` fill gaps
Dependabot can't (transitive pins, lockfile regen) and now also enable native
auto-merge on block instead of re-firing duplicates.

## Prerequisites (one-time, before `--apply`)

### 1. Org secrets — REQUIRED
Every repo's auto-merge workflow mints an App token from these. Set once at the
org level so all repos inherit (no per-repo secret sprawl):

```bash
# App ID (not sensitive)
gh secret set GIT_STEER_APP_ID --org ry-ops --visibility all --body "<app-id>"

# App private key as PEM. NOTE: the key in Keychain is hex-encoded — decode first:
keytar-get git-steer git-steer-private-key | xxd -r -p > /tmp/gs.pem   # or however you extract it
gh secret set GIT_STEER_APP_PRIVATE_KEY --org ry-ops --visibility all < /tmp/gs.pem
rm -f /tmp/gs.pem
```

Without these, the workflow fails to mint a token on every Dependabot PR.

### 2. App permissions
The git-steer GitHub App installation must grant:
- `contents: write` — commit files / merge
- `pull_requests: write` — open/approve/merge PRs
- `workflows: write` — push the `.github/workflows/` file (else PUT 403s)
- `administration: write` — toggle allow-auto-merge + Dependabot settings

### 3. Branch protection compatibility
The App approval satisfies a generic "require N approvals" rule. It does **not**
satisfy a **CODEOWNERS-required** review. On repos that require code-owner
review, either drop that requirement or add `git-steer` to `CODEOWNERS`.

## Rollout

The rollout is **dry-run by default** and **paced** (3 repos/batch, delay +
rate-limit check between batches — never an all-at-once fan-out, per the
account-safety rule). Re-runnable: deterministic branch + PR reuse means it
never creates duplicate PRs.

```bash
# 1. Preview everything (read-only)
node scripts/rollout-autonomy.mjs

# 2. Pilot a few repos
node scripts/rollout-autonomy.mjs --apply --repos=blog,git-steer-state

# 3. Full rollout
node scripts/rollout-autonomy.mjs --apply
```

Per repo it: detects ecosystems → writes a matched grouped `dependabot.yml` →
deploys the auto-merge workflow → opens (or reuses) a bootstrap PR and tries to
merge it → enables allow-auto-merge, Dependabot alerts, and security updates.

## Rollback

```bash
# Disable autonomy on a repo: remove the workflow + (optionally) dependabot.yml
gh api -X DELETE repos/ry-ops/<repo>/contents/.github/workflows/dependabot-automerge.yml \
  -f message="revert autonomy" -f sha="$(gh api repos/ry-ops/<repo>/contents/.github/workflows/dependabot-automerge.yml --jq .sha)"
# Turn off auto-merge:
gh api -X PATCH repos/ry-ops/<repo> -F allow_auto_merge=false
```

## What stays manual
- **Major version bumps** — flagged `needs-human-merge` (breaking-change risk).
  To make majors autonomous, add the `semver-major` case in the workflow.
- **Anything CI-red** — native auto-merge only lands green PRs.
- **git-steer gap-fill PRs** that can't be self-approved — labeled for a human.
