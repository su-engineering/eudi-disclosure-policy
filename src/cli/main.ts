import { run } from './run.js';

const code = await run(process.argv.slice(2), {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
  stdin: () => process.stdin,
  now: () => new Date(),
});
process.exitCode = code;
