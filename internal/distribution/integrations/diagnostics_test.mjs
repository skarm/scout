import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { summarize } from './assets/shared/runner.mjs';

const fixture = process.env.SCOUT_DIAGNOSTICS_FIXTURE;
await test('scope diagnostics survive the actual Go report wire format', { skip: !fixture && 'Run TestHostDiagnosticsUseTheActualGoReportContract to supply a real Go report' }, async () => {
  const stdout = await readFile(fixture);
  const document = JSON.parse(stdout);
  const diagnostics = document.run.targets[0].analysis.diagnostics;
  assert.ok(diagnostics.some(d => d.affects_scope === true));
  const summary = summarize({ code: 2, stdout }, { profile: 'custom', alias: 'inert', semantic: false }, { reduced: true });
  assert.deepEqual(summary.diagnostics.map(d => d.affects_completeness), diagnostics.map(d => d.affects_scope));
  assert.equal(summary.completeness, 'failed');
  const complete = structuredClone(document);
  complete.run.state = complete.run.targets[0].state = 'complete';
  complete.run.targets[0].analysis.coverage.completeness = 'complete';
  complete.run.problems = [];
  complete.evaluation.decision = 'allow';
  assert.throws(() => summarize({ code: 0, stdout: Buffer.from(JSON.stringify(complete)) }, { profile: 'custom' }, {}), /scope gaps/);
});
