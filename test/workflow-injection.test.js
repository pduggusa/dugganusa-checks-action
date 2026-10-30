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

test('case and bracket spellings of an event field are still caught', () => {
  for (const expr of ["github.event.issue.TITLE", "github.event.issue['title']", 'github.event.issue["title"]', "GitHub.Event.Pull_Request.Head.Ref"]) {
    const wf = `name: t\non: issues\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo "\${{ ${expr} }}"\n`;
    assert.ok([...wi.fromWorkflowInjection(wf).values()].some(i => i.verdict === 'BLOCK'), expr);
  }
});

test('a second identical vulnerable step is a second finding, not a collapsed key', () => {
  const step = '      - name: x\n        run: echo "${{ github.event.issue.title }}"\n';
  const wf = `name: t\non: issues\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: x\n    steps:\n${step}${step}`;
  assert.equal([...wi.fromWorkflowInjection(wf).values()].filter(i => i.verdict === 'BLOCK').length, 2);
});

test('a steps key with a trailing comment or quotes is still parsed; an unparseable file is surfaced, not passed', () => {
  const c = `name: t\non: issues\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: x\n    steps: # go\n      - run: echo "\${{ github.event.issue.title }}"\n`;
  assert.ok([...wi.fromWorkflowInjection(c).values()].some(i => i.verdict === 'BLOCK'));
  const flow = `name: t\non: issues\npermissions:\n  contents: read\njobs: {a: {runs-on: x, steps: [{run: 'echo \${{ github.event.issue.title }}'}]}}\n`;
  assert.ok([...wi.fromWorkflowInjection(flow).values()].some(i => i.verdict === 'REVIEW' && /WFI-006/.test(i.spec)));
});
