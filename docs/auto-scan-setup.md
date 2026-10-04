# Auto-Scan Setup (retired)

The per-repo `cve-scan.yml` workflow this page described has been removed
([ADR-008](../adr/ADR-008.yaml)). It ran `npm audit fix` and force-pushed the
result to a `security/auto-fix` branch, which is the kind of automated write
ADR-008 moves out of git-steer.

Instead:

- **Detection and fixes:** Dependabot alerts and Dependabot security updates,
  CodeQL default setup and secret scanning push protection, all enabled
  through org security configurations (ADR-008 Layer 0).
- **Keeping a repo healthy:** a short caller of git-steer's reusable `heal.yml`
  (ADR-008 Layer 1, coming next).

If a repo still has a copy of `cve-scan.yml`, delete it in that repo through
a normal pull request.
