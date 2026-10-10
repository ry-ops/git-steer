---
name: 🩹 Fix a repo (or the fleet)
about: git-steer plans which Dependabot PRs to merge. Nothing is merged until you approve the rollout it opens.
title: "fix "
labels: git-steer-fix
---

Finish the title with what to fix:

- one repo, the way it appears in its GitHub address: the owner, a slash, then the repo name
- one account: just the owner name
- everything: the word fleet

Options, added to the title: +untested includes PRs whose repo has no CI (one repo already does), +major includes major version steps.

git-steer replies here with a plan and opens a rollout issue listing the PRs it may merge. Delete any you don't want, then add the `approved` label there. Nothing is merged before that, and a PR whose checks failed is never merged.
