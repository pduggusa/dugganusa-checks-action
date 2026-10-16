'use strict';
// Minimal GitHub Actions runtime helpers (no @actions/core dependency).

const fs = require('fs');
const os = require('os');

function getInput(name, def = '') {
  const v = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`];
  return v === undefined || v.trim() === '' ? def : v.trim();
}

function getBool(name, def = false) {
  const v = getInput(name, '').toLowerCase();
  if (!v) return def;
  if (['true', 'yes', '1', 'on'].includes(v)) return true;
  if (['false', 'no', '0', 'off'].includes(v)) return false;
  throw new Error(`input ${name} must be true or false, got "${v}"`);
}

// Escape for workflow-command data and properties. Also the injection guard: newlines are
// encoded, so API-supplied text can never start a new "::command::" line.
function escData(s) { return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A'); }
function escProp(s) { return escData(s).replace(/:/g, '%3A').replace(/,/g, '%2C'); }

function inActions() { return process.env.GITHUB_ACTIONS === 'true'; }

function annotate(level, message, { file, line, title } = {}) {
  if (!inActions()) { console.log(`[${level.toUpperCase()}]${file ? ' ' + file + (line ? ':' + line : '') : ''} ${message}`); return; }
  const props = [];
  if (file) props.push(`file=${escProp(file)}`);
  if (line) props.push(`line=${Number(line)}`);
  if (title) props.push(`title=${escProp(title)}`);
  console.log(`::${level}${props.length ? ' ' + props.join(',') : ''}::${escData(message)}`);
}

function mask(secret) { if (secret && inActions()) console.log(`::add-mask::${escData(secret)}`); }

function setOutput(name, value) {
  const f = process.env.GITHUB_OUTPUT;
  if (!f) return;
  const delim = `ghadelim_${Math.random().toString(36).slice(2)}`;
  fs.appendFileSync(f, `${name}<<${delim}${os.EOL}${value}${os.EOL}${delim}${os.EOL}`);
}

function appendSummary(markdown) {
  const f = process.env.GITHUB_STEP_SUMMARY;
  if (!f) return false;
  fs.appendFileSync(f, markdown + os.EOL);
  return true;
}

function group(name) { if (inActions()) console.log(`::group::${escData(name)}`); else console.log(`--- ${name}`); }
function endGroup() { if (inActions()) console.log('::endgroup::'); }

module.exports = { getInput, getBool, escData, escProp, annotate, mask, setOutput, appendSummary, group, endGroup, inActions };
