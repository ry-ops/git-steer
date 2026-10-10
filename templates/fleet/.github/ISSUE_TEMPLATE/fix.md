---
name: 🩹 Fix a repo
about: git-steer plans which Dependabot PRs to merge. Nothing is merged until you approve the rollout it opens.
title: "fix "
labels: git-steer-fix
---

Finish the title with the repo to fix, written the way it appears in its GitHub address: the owner, a slash, then the repo name.

git-steer replies here with a plan: each Dependabot PR, whether its checks passed, and which alerts it closes. It opens a rollout issue listing the PRs it may merge. Delete any you don't want, then add the `approved` label there. Nothing is merged before that.
