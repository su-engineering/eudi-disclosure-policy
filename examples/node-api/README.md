# Node.js preflight

[preflight.mjs](preflight.mjs) shows the API in a backend: the policy is loaded once, every DCQL query is evaluated before it is sent, and `DENY` or `INDETERMINATE` blocks the request with diagnostics that are safe to log.

```sh
pnpm build
node examples/node-api/preflight.mjs
```

See [integration](../../docs/integration.md) for registration evidence, Next.js, and CI.
