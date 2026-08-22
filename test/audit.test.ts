import { it, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from 'node:assert';
import { findings as coreFindings } from '../audit/compare-core.ts';
import { findings } from '../audit/compare-main.ts';

// Keep these serial: parallel JSBT workers re-import the module and would repeat both complete
// differential matrices once per worker. Each case remains independently visible and red.
// Intentional strict-mode and unknown-field behavior is not an unresolved issue.
for (const [name, finding] of findings) {
  if (finding.kind !== 'legacy') continue;
  it.serial(`main/work serialized interoperability: ${name}`, () => {
    deepStrictEqual(finding.evidence, []);
  });
}

// Fingerprint and already-dispositioned configured differences remain visible in the harness
// output.
// Red cases are unresolved operation differences observed after serialized Core-to-scure handoff.
for (const [name, finding] of coreFindings) {
  if (finding.kind !== 'candidate') continue;
  it.serial(`Core/scure serialized interoperability: ${name}`, () => {
    deepStrictEqual(finding.evidence, [], `Context: ${finding.context}`);
  });
}

should.runWhen(import.meta.url);
