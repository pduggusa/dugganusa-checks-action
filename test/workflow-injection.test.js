'use strict';
const test = require('node:test');
const assert = require('node:assert');
const wi = require('../src/workflow-injection');
const p = require('../src/parsers');

const VULN = `name: t
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.event.issue.title }}"
`;
const SAFE = `name: t
on: issues
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: \${{ github.event.issue.title }}
        run: echo "$TITLE"
`;

test('event text pasted into a run script is a BLOCK finding with a workflow-injection label', () => {
  const items = [...wi.fromWorkflowInjection(VULN).values()];
  // WFI-001 (BLOCK) plus WFI-004 (REVIEW: external trigger, no permissions block)
  assert.ok(items.every(i => i.kind === 'finding' && i.ftype === 'workflow injection'));
  assert.equal(items.filter(i => i.verdict === 'BLOCK').length, 1);
  assert.match(items.find(i => i.verdict === 'BLOCK').spec, /^WFI-001/);
});

test('the same text passed through env produces no finding', () => {
  assert.equal(wi.fromWorkflowInjection(SAFE).size, 0);
});

test('fromWorkflow merges the finding and honors the opt-out', () => {
  assert.ok([...p.parse('workflow', VULN, {}).values()].some(i => i.ftype === 'workflow injection'));
  assert.ok(![...p.parse('workflow', VULN, { workflowInjection: false }).values()].some(i => i.ftype === 'workflow injection'));
});

test('an oversize workflow is reported, not silently skipped', () => {
  const big = 'name: t\non: issues\n' + '# pad\n'.repeat(60000);
  const items = [...wi.fromWorkflowInjection(big).values()];
  assert.equal(items.length, 1);
  assert.equal(items[0].kind, 'skip');
});

test('text that is not a workflow yields nothing', () => {
  assert.equal(wi.fromWorkflowInjection('just: a file\n').size, 0);
});
