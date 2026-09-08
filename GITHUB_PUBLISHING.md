# Publishing Chromaplex Coding Agent on GitHub

Recommended repository:

`https://github.com/Janus5G/Chromaplex-Coding-Agent`

## Repository settings

- Name: `Chromaplex-Coding-Agent`
- Visibility: Public
- Description: `Open-source secure multi-mode coding agent for Linux, Windows, Web and ChromaPlex CPL/CPA with a built-in editor and fail-closed Secure Compile Gate.`
- License: already included as MIT in the repository; do not ask GitHub to generate another license during repository creation.

Suggested topics:

`chromaplex`, `cpl`, `cpa`, `coding-agent`, `ai-coding`, `linux`, `pyside6`, `compiler`, `ide`, `openai`

## First push

Create the GitHub repository empty: do not initialize it with a README, License or .gitignore.

Open a terminal in the local project root and run:

```bash
git init -b main
git add .
git commit -m "Initial public release: Chromaplex Coding Agent v0.3.0"
git remote add origin https://github.com/Janus5G/Chromaplex-Coding-Agent.git
git push -u origin main
```

If the folder is already a Git repository, skip `git init -b main`. If `origin` already exists, inspect it with `git remote -v` before changing anything.

## First GitHub Release

Create a new GitHub release after the source is pushed.

- Tag: `v0.3.0`
- Title: `Chromaplex Coding Agent v0.3.0 Alpha`
- Mark it as a pre-release / public preview.
- Use the text from `RELEASE_NOTES_v0.3.0.md` as the release description.
- Attach:
  - `chromaplex-coding-agent_0.3.0_all.deb`
  - `Chromaplex-Coding-Agent-v0.3.0-source.zip`
  - `Chromaplex-Coding-Agent-v0.3.0-SHA256SUMS.txt`

GitHub automatically provides repository source archives as well, but the attached source ZIP is the exact tested source snapshot prepared for this release.

## After publishing

Confirm that the GitHub Actions `Security and release tests` workflow is green. Then verify the `.deb` in a real Debian/Ubuntu/Kubuntu/Lubuntu VM before promoting the project beyond Alpha status.
