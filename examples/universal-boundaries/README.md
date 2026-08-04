# Universal boundaries

This dependency-free example demonstrates the two Flare Redact 1.4 integration
primitives:

- wrap any SDK method, route handler, queue consumer, webhook, or RPC function
  with `createRedactionMiddleware()`;
- keep reversible model placeholders inside the tool/trust domain that minted
  them with `createScopedToolBoundary()`.

No API key or external service is required.

```bash
npm install
npm start
```
