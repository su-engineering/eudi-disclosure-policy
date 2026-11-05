# Releasing

Releases use [Changesets](https://github.com/changesets/changesets), a validated GitHub Actions workflow, and npm trusted publishing (OIDC). No npm token is stored anywhere.

## One-time setup

1. **npm trusted publisher.** In the npm settings for `@su-engineering/eudi-disclosure-policy`, add a GitHub Actions trusted publisher: organization `su-engineering`, repository `eudi-disclosure-policy`, workflow `release.yml`, no environment. The package must exist before a trusted publisher can be added, so the first version is published once manually (see below) or by an npm owner creating the package.
2. **Pull requests from Actions.** Repository Settings → Actions → General → enable **Allow GitHub Actions to create and approve pull requests**. The workflow never approves or merges its own pull requests.

## Normal flow

1. Contributors add a changeset for package changes (`pnpm exec changeset`). Behavior changes to rules are at least minor while in 0.x and must update `RULES_VERSION`.
2. On merge to `main`, `Release` runs CI. Changesets opens or updates a **Release: update package version** pull request with the version bump and changelog.
3. The workflow dispatches CI on that branch, because pull requests created with `GITHUB_TOKEN` do not trigger workflows. Check it is green.
4. Merging the version pull request publishes the version with provenance and creates the `vX.Y.Z` tag and GitHub release.

0.x versions are published under the npm `next` dist-tag; `latest` is reserved for 1.0 and later. `tools/publish.mjs` skips versions that already exist and fails closed on registry errors.

## Before 1.0

1.0 requires external review from real implementers, a stable API, a published conformance matrix, and an explicit compatibility policy. It is not gated on download or star counts.

## Manual release (emergency or first publish)

Authenticate interactively with npm, check out the validated version commit, run `pnpm install --frozen-lockfile && pnpm check`, then `npm publish --access public --tag next`. Create the tag and GitHub release afterwards. Do not run `tools/publish.mjs` outside GitHub Actions.
