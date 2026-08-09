# FlareFlow technical report

This directory contains the source for **FlareFlow: Capability-Bounded
Declassification for Tool-Using Language Model Agents**.

- [`flareflow-preprint.md`](flareflow-preprint.md) is the reviewable manuscript.
- [`../spec/FLAREFLOW.md`](../spec/FLAREFLOW.md) is the normative implementation
  contract.
- [`../bench/agent-flow-cases.json`](../bench/agent-flow-cases.json) is the public
  evaluation corpus.
- `results/` contains the exact checked-in output cited by the draft.

Reproduce the evaluation from the repository root:

```bash
npm ci
npm run benchmark:agent -- --json --iterations=100000 --samples=9
```

The report is a project technical preprint, not a peer-reviewed publication. Its
claims are deliberately limited to exact protected-value restoration under the
documented trusted-runtime threat model.
