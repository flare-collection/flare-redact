# FlareFlow agent boundary

A deterministic, model-free demonstration of source-to-sink declassification.
It protects the credential-bearing segment of a database connection string
before model context, blocks the model from transplanting its opaque token into
an HTTP URL, and restores it only at the runtime-approved database argument
path.

No model, API key, network call, or external service is required.

```bash
npm install
npm start
```

The printed report is value-free: it contains the protected token, decision,
budget counters, and audit events, but never the original credential.
