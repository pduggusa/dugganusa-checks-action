'use strict';
// Agent instruction files (2026-10-18). The files an AI coding agent reads as INSTRUCTIONS on every
// run: poisoning one is prompt injection delivered through the agent's own config, invisible in an
// editor and in most rendered diffs, fully visible to the model (TrapDoor, original research Socket).
// Ported from DugganUSA scripts/scan-agent-instructions.js, plus Unicode TAG characters
// (U+E0000-E007F, "ASCII smuggling": each tag char encodes one ASCII char, so a whole hidden
// sentence can ride inside a visible line) and stray variation selectors. Tag runs are DECODED so a
// reviewer sees what the model would read.

const path = require('path');

const AGENT_BASENAMES = new Set(['CLAUDE.md', 'AGENTS.md', 'AGENT.md', 'GEMINI.md', '.cursorrules', '.clinerules',
  '.windsurfrules', '.continuerules', 'system-prompt.md', 'llms.txt', '.aider.conf.yml']);

function isInstructionFile(file) {
  const f = String(file).replace(/\\/g, '/');
  if (/(^|\/)(node_modules|vendor|\.git)\//.test(f)) return false;
  const b = path.posix.basename(f);
  if (AGENT_BASENAMES.has(b)) return true;
  if (/(^|\/)\.github\/copilot-instructions\.md$/.test(f)) return true;
  if (/(^|\/)\.github\/instructions\/[^/]+\.instructions\.md$/.test(f)) return true;
  if (/(^|\/)\.cursor\/rules\/[^/]+\.mdc?$/.test(f)) return true;
  if (/(^|\/)\.claude\/(commands|agents|skills)\/.+\.md$/.test(f)) return true;
  return false;
}

// [name, severity]
const INVISIBLE = new Map([
  [0x200B, ['ZERO WIDTH SPACE', 'high']], [0x200C, ['ZERO WIDTH NON-JOINER', 'high']], [0x200D, ['ZERO WIDTH JOINER', 'context']],
  [0x200E, ['LEFT-TO-RIGHT MARK', 'high']], [0x200F, ['RIGHT-TO-LEFT MARK', 'high']],
  [0x202A, ['LEFT-TO-RIGHT EMBEDDING', 'critical']], [0x202B, ['RIGHT-TO-LEFT EMBEDDING', 'critical']],
  [0x202C, ['POP DIRECTIONAL FORMATTING', 'critical']], [0x202D, ['LEFT-TO-RIGHT OVERRIDE', 'critical']],
  [0x202E, ['RIGHT-TO-LEFT OVERRIDE', 'critical']], [0x2066, ['LEFT-TO-RIGHT ISOLATE', 'critical']],
  [0x2067, ['RIGHT-TO-LEFT ISOLATE', 'critical']], [0x2068, ['FIRST STRONG ISOLATE', 'critical']], [0x2069, ['POP DIRECTIONAL ISOLATE', 'critical']],
  [0x2060, ['WORD JOINER', 'high']], [0x2061, ['FUNCTION APPLICATION', 'high']], [0x2062, ['INVISIBLE TIMES', 'high']],
  [0x2063, ['INVISIBLE SEPARATOR', 'high']], [0x2064, ['INVISIBLE PLUS', 'high']],
  [0x00AD, ['SOFT HYPHEN', 'medium']], [0x061C, ['ARABIC LETTER MARK', 'high']], [0x180E, ['MONGOLIAN VOWEL SEPARATOR', 'high']],
  [0xFEFF, ['ZERO WIDTH NO-BREAK SPACE / BOM', 'context']],
]);
const isEmoji = (cp) => cp !== undefined && ((cp >= 0x1F300 && cp <= 0x1FAFF) || (cp >= 0x2600 && cp <= 0x27BF)
  || (cp >= 0x1F000 && cp <= 0x1F2FF) || cp === 0xFE0F || (cp >= 0x1F1E6 && cp <= 0x1F1FF) || (cp >= 0x1F3FB && cp <= 0x1F3FF));
const isTag = (cp) => cp >= 0xE0000 && cp <= 0xE007F;
const isVS = (cp) => (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);
const show = (s) => String(s).replace(/[\u0000-\u001f\u007f]/g, '?').slice(0, 160);

// Findings: [{ line, column, severity, codepoint, name, decoded? }]
function scanInstructions(text) {
  const out = [];
  const cps = Array.from(String(text));
  let line = 1, col = 1;
  for (let i = 0; i < cps.length; i++) {
    const ch = cps[i];
    const cp = ch.codePointAt(0);
    if (ch === '\n') { line++; col = 1; continue; }
    if (isTag(cp)) {
      // A run of tag characters: decode it (tag char - 0xE0000 = ASCII).
      const startCol = col, startIdx = i; let decoded = '';
      while (i < cps.length && isTag(cps[i].codePointAt(0))) {
        const c = cps[i].codePointAt(0) - 0xE0000;
        if (c >= 0x20 && c < 0x7F) decoded += String.fromCharCode(c);
        i++; col++;
      }
      i--; col--;
      // Emoji flag sequences (subdivision flags) legitimately use tags after U+1F3F4.
      const before = cps[startIdx - 1];
      if (!(before && before.codePointAt(0) === 0x1F3F4 && /^[a-z0-9]{2,7}$/.test(decoded))) {
        out.push({ line, column: startCol, severity: 'critical', codepoint: 'U+E00xx', name: 'UNICODE TAG CHARACTERS (hidden ASCII)', decoded: show(decoded) });
      }
      col++; continue;
    }
    if (isVS(cp)) {
      const prev = cps[i - 1] ? cps[i - 1].codePointAt(0) : undefined;
      if (!(cp === 0xFE0F || cp === 0xFE0E) || !(isEmoji(prev) || (prev >= 0x23 && prev <= 0x39) || prev === 0x2A || (prev >= 0x2000 && prev <= 0x2BFF))) {
        out.push({ line, column: col, severity: 'high', codepoint: 'U+' + cp.toString(16).toUpperCase(), name: 'VARIATION SELECTOR outside an emoji' });
      }
      col++; continue;
    }
    const hit = INVISIBLE.get(cp);
    if (hit) {
      let [name, severity] = hit;
      if (cp === 0x200D) {
        const prev = cps[i - 1] && cps[i - 1].codePointAt(0), next = cps[i + 1] && cps[i + 1].codePointAt(0);
        if (isEmoji(prev) && isEmoji(next)) { col++; continue; }
        severity = 'high';
      }
      if (cp === 0xFEFF) { if (i === 0) { col++; continue; } severity = 'high'; }
      out.push({ line, column: col, severity, codepoint: 'U+' + cp.toString(16).toUpperCase().padStart(4, '0'), name });
    }
    col++;
  }
  return out;
}

// Parser shape for the action: a Map of items. One item per finding; verdict decided locally.
function fromInstructions(text) {
  const m = new Map();
  for (const f of scanInstructions(text)) {
    const verdict = f.severity === 'medium' ? 'REVIEW' : 'BLOCK';
    const reason = f.decoded !== undefined
      ? `hidden text in invisible Unicode tag characters, which the model reads and a reviewer does not see: "${f.decoded}"`
      : `${f.name} (${f.codepoint}): invisible in an editor and most diffs, delivered to the model`;
    m.set(`finding:${f.line}:${f.column}:${f.codepoint}`, { kind: 'finding', verdict, severity: f.severity, spec: `line ${f.line}, column ${f.column}`, where: `line ${f.line}`, reason });
  }
  return m;
}

module.exports = { isInstructionFile, scanInstructions, fromInstructions };
