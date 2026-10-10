---
name: 🤖 Hand off to Copilot
about: git-steer opens issues for what Dependabot can't fix (missing or broken CI first), ready to assign to Copilot.
title: "handoff "
labels: git-steer-handoff
---

Finish the title one of these ways:

- `handoff owner/repo`: one repo, written the way it appears in its GitHub address. git-steer opens up to 5 issues there: CI that's missing or broken, upgrades Dependabot hasn't proposed, and packages with no fixed release.
- `handoff ci <owner>` or `handoff ci fleet`: one CI issue in each repo with open Dependabot PRs whose CI is missing or broken, up to 30 repos.

git-steer replies here with links. Open each issue and assign it to Copilot. git-steer never assigns them, and changes nothing else.
