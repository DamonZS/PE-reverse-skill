# Issue Tracker: GitHub

Issues and PRDs for this repository are stored in GitHub Issues. Use the `gh` CLI for all tracker operations.

External pull requests are not part of the triage request surface.

## Conventions

- Create an issue: `gh issue create --title "..." --body "..."`
- Read an issue: `gh issue view <number> --comments`
- List issues: `gh issue list --state open --json number,title,body,labels,comments`
- Comment on an issue: `gh issue comment <number> --body "..."`
- Apply a label: `gh issue edit <number> --add-label "..."`
- Remove a label: `gh issue edit <number> --remove-label "..."`
- Close an issue: `gh issue close <number> --comment "..."`

Infer the repository from `git remote -v`; when run inside this clone, `gh` resolves the current repository automatically.

## Skill Terms

- "Publish to the issue tracker" means creating a GitHub issue.
- "Fetch the relevant ticket" means running `gh issue view <number> --comments` and reading its labels and comments.
