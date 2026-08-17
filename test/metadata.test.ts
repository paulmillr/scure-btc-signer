import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, match } from 'node:assert';
import { readFileSync } from 'node:fs';

const readJson = (path: string): any =>
  JSON.parse(readFileSync(new URL(`../${path}`, import.meta.url), 'utf8'));

describe('Package metadata', () => {
  it('pins signing-critical runtime dependencies in npm and JSR manifests', () => {
    const npm = readJson('package.json');
    const jsr = readJson('jsr.json');
    const jsrPrefixes = {
      '@noble/curves': 'jsr:@noble/curves@',
      '@noble/hashes': 'jsr:@noble/hashes@',
      '@scure/base': 'jsr:@scure/base@',
      'micro-packed': 'jsr:@paulmillr/micro-packed@',
    };
    for (const [name, prefix] of Object.entries(jsrPrefixes)) {
      const version = npm.dependencies[name];
      match(version, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
      deepStrictEqual(jsr.imports[name], `${prefix}${version}`);
    }
  });
});
