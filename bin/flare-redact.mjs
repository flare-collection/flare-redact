#!/usr/bin/env node
import { main } from '../dist/cli.js';

// Setting exitCode lets Node drain piped stdout/stderr before termination.
// process.exit() can truncate JSON and SARIF reports larger than the pipe buffer.
process.exitCode = await main(process.argv.slice(2));
