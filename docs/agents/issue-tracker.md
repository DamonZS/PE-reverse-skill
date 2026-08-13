# Issue Tracker: GitHub

Issues and specifications for this repository are stored in GitHub Issues. Use the `gh` CLI for tracker operations.

## Conventions

- Create an issue: `gh issue create --title "..." --body "..."`
- Read an issue: `gh issue view <number> --comments`
- List issues: `gh issue list --state open --json number,title,body,labels,comments`
- Comment on an issue: `gh issue comment <number> --body "..."`
- Apply or remove labels: `gh issue edit <number> --add-label "..."` or `--remove-label "..."`
- Close an issue: `gh issue close <number> --comment "..."`

Infer the repository from `git remote -v`; inside this clone, `gh` resolves the current repository automatically.

## Pull Requests As A Request Surface

External pull requests are not a request surface. Do not place them in the issue triage queue.

## Skill Terms

- "Publish to the issue tracker" means creating a GitHub issue.
- "Fetch the relevant ticket" means running `gh issue view <number> --comments` and reading its labels and comments.
