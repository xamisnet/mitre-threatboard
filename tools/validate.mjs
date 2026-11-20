#!/usr/bin/env node
/**
 * Validates the data tables embedded in index.html.
 * Exits 1 on any referential-integrity failure, so CI fails loudly
 * rather than the dashboard silently rendering a broken map.
 *
 *   node tools/validate.mjs
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = readFileSync(join(root, 'index.html'), 'utf8');

const START = '/* ============================ TACTICS';
const END = '/* ============================ HELPERS';
const a = html.indexOf(START);
const b = html.indexOf(END);
if (a < 0 || b < 0 || b <= a) {
  console.error('FAIL: could not locate the data block in index.html');
  process.exit(1);
}
const dataBlock = html.slice(a, b);

const checks = `
const errs = [];
const TECH_IDS = new Set(Object.keys(TECHS));
const MIT_IDS  = new Set(Object.keys(MIT));
const TAC_IDS  = new Set(TACTICS.map(t => t.id));

ITEMS.forEach(it => it.tch.forEach(t => {
  if (!TECH_IDS.has(t)) errs.push('item ' + it.id + ': unknown technique ' + t);
}));

Object.entries(TECHS).forEach(([id, m]) => {
  if (!TAC_IDS.has(m.t)) errs.push('technique ' + id + ': unknown tactic ' + m.t);
  if (!TECH_MIT[id]) errs.push('technique ' + id + ': no mitigations mapped');
});

Object.entries(TECH_MIT).forEach(([t, ms]) => {
  if (!TECH_IDS.has(t)) errs.push('TECH_MIT key ' + t + ' is not a known technique');
  ms.forEach(m => { if (!MIT_IDS.has(m)) errs.push('TECH_MIT[' + t + '] -> unknown mitigation ' + m); });
});

ITEMS.forEach(it => it.ctl.forEach(c => {
  (c.match(/M\\d{4}/g) || []).forEach(m => {
    if (!MIT_IDS.has(m)) errs.push('item ' + it.id + ': control prose cites unknown ' + m);
  });
}));

ITEMS.forEach(it => {
  if (it.tch.length < 3) errs.push('item ' + it.id + ': only ' + it.tch.length + ' techniques (min 3)');
  if (!it.ctl.length)    errs.push('item ' + it.id + ': no controls given');
  if (new Set(it.tch).size !== it.tch.length) errs.push('item ' + it.id + ': duplicate technique IDs');
  if (!it.url)           errs.push('item ' + it.id + ': no primary source URL');
});

const ids = ITEMS.map(i => i.id);
if (new Set(ids).size !== ids.length) errs.push('duplicate item IDs');

return {
  errs,
  stats: {
    items: ITEMS.length,
    techniquesReferenced: new Set(ITEMS.flatMap(i => i.tch)).size,
    techniquesDefined: TECH_IDS.size,
    mitigationsDefined: MIT_IDS.size,
    tacticsDefined: TAC_IDS.size
  }
};
`;

const run = new Function(`${dataBlock}\n${checks}`);
const { errs, stats } = run();

for (const [k, v] of Object.entries(stats)) {
  console.log(`  ${k.replace(/([A-Z])/g, ' $1').toLowerCase().padEnd(24)} ${v}`);
}

if (errs.length) {
  console.error(`\nFAIL: ${errs.length} integrity error(s)\n`);
  errs.forEach(e => console.error('  - ' + e));
  process.exit(1);
}

console.log('\nOK: data integrity clean');