---
'@su-engineering/eudi-disclosure-policy': patch
---

Publish every release under the npm `latest` dist-tag, so `npm install` gets the newest version. Document the trusted publisher settings, and fail the package check when `npm publish` would rewrite `package.json`.
