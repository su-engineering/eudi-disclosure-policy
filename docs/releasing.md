# Releasing

Releases use [Changesets](https://github.com/changesets/changesets), a validated GitHub Actions workflow, and npm trusted publishing (OIDC). No npm token is stored anywhere.

## One-time setup

1. **npm trusted publisher.** In the npm settings for `@su-engineering/eudi-disclosure-policy`, add a GitHub Actions trusted publisher: organization `su-engineering`, repository `eudi-disclosure-policy`, workflow `release.yml`, no environment. Allow `npm publish` (the workflow publishes directly); leave `npm dist-tag` disallowed. Under publishing access, require two-factor authentication and disallow bypass tokens: trusted publishing keeps working, and no token can publish. The package must exist before a trusted publisher can be added, so the first version is published once manually (see below). npm then requires one publish from the workflow within two days to validate the configuration.
2. **Pull requests from Actions.** Repository Settings → Actions → General → enable **Allow GitHub Actions to create and approve pull requests**. The workflow never approves or merges its own pull requests.

## Normal flow

1. Contributors add a changeset for package changes (`pnpm exec changeset`). Behavior changes to rules are at least minor while in 0.x and must update `RULES_VERSION`.
2. On merge to `main`, `Release` runs CI. Changesets opens or updates a **Release: update package version** pull request with the version bump and changelog.
3. The workflow dispatches CI on that branch, because pull requests created with `GITHUB_TOKEN` do not trigger workflows. Check it is green.
4. Merging the version pull request publishes the version with provenance and creates the `vX.Y.Z` tag and GitHub release.

Every version, including 0.x previews, is published under the npm `latest` dist-tag. npm sets `latest` on the first publish and it cannot be removed, so a separate preview tag would leave `npm install` on an old version. The 0.x version number marks the package as a preview. `tools/publish.mjs` skips versions that already exist and fails closed on registry errors.

## Before 1.0

1.0 requires external review from real implementers, a stable API, a published conformance matrix, and an explicit compatibility policy. It is not gated on download or star counts.

## Manual release (emergency or first publish)

Authenticate interactively with npm, check out the validated version commit, run `pnpm install --frozen-lockfile && pnpm check`, then `npm publish --access public`. A manual publish has no provenance statement. Create the tag and GitHub release afterwards. Do not run `tools/publish.mjs` outside GitHub Actions.
