#!/usr/bin/env node
import { main } from '../dist/gateway/cli.js';

// A dedicated binary so a container ENTRYPOINT does not have to carry a
// subcommand, and so `npx flare-gateway --upstream …` is one line.
process.exitCode = await main(process.argv.slice(2));
