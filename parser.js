/**
 * CSPM Parser & Normalizer
 * Parses JSON / CSV / YAML uploads into a uniform resource list.
 *
 * Normalized Resource shape:
 * {
 *   id:         string  – unique resource identifier
 *   type:       string  – e.g. "s3_bucket", "iam_policy", "security_group", "ec2_instance"
 *   provider:   string  – "aws" | "azure" | "gcp" | "unknown"
 *   region:     string
 *   name:       string
 *   tags:       object
 *   raw:        object  – original parsed object (reference only, not mutated)
 * }
 */

'use strict';

// ---------------------------------------------------------------------------
// Credential / secret redaction
// ---------------------------------------------------------------------------
const SECRET_PATTERNS = [
  /(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*["']?([^\s"',}{]{6,})["']?/gi,
  /AKIA[0-9A-Z]{16}/g,                          // AWS Access Key
  /(?:[0-9a-zA-Z+/]{40})/g,                     // AWS Secret-like base64-40
  /eyJ[a-zA-Z0-9_-]{10,}/g,                     // JWT
];

/**
 * Redact credential patterns from a raw string before parsing.
 * @param {string} text
 * @returns {string}
 */
function redactSecrets(text) {
  let out = text;
  for (const re of SECRET_PATTERNS) {
    out = out.replace(re, (match) => match.replace(/[^\s:=,"'{}[\]]/g, '*'));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------
/**
 * @param {string} filename
 * @param {string} text
 * @returns {'json'|'csv'|'yaml'}
 */
function detectFormat(filename, text) {
  const ext = (filename || '').split('.').pop().toLowerCase();
  if (ext === 'json') return 'json';
  if (ext === 'csv')  return 'csv';
  if (ext === 'yaml' || ext === 'yml') return 'yaml';

  const trimmed = text.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
  if (/^[a-zA-Z_][a-zA-Z0-9_]*\s*:/m.test(trimmed)) return 'yaml';
  return 'csv';
}

// ---------------------------------------------------------------------------
// Minimal YAML parser (subset sufficient for cloud config exports)
// ---------------------------------------------------------------------------
/**
 * Very small YAML → JS object parser.
 * Supports: mappings, sequences (block & flow), scalars, multi-doc (---)
 * Does NOT support: anchors/aliases, multi-line folded strings, complex tags.
 */
function parseYAML(text) {
  const lines = text.split('\n');
  let pos = 0;

  function peek() { return lines[pos]; }
  function next() { return lines[pos++]; }
  function isDone() { return pos >= lines.length; }

  function indent(line) {
    const m = line.match(/^(\s*)/);
    return m ? m[1].length : 0;
  }

  function parseLine(line) {
    // strip comments
    const noComment = line.replace(/#.*$/, '').trimEnd();
    return noComment;
  }

  function parseValue(valStr) {
    const v = valStr.trim();
    if (v === 'true' || v === 'yes') return true;
    if (v === 'false' || v === 'no') return false;
    if (v === 'null' || v === '~' || v === '') return null;
    if (/^-?\d+$/.test(v)) return parseInt(v, 10);
    if (/^-?\d*\.\d+$/.test(v)) return parseFloat(v);
    // quoted strings
    if ((v.startsWith('"') && v.endsWith('"')) ||
        (v.startsWith("'") && v.endsWith("'"))) {
      return v.slice(1, -1);
    }
    return v;
  }

  function parseBlock(baseIndent) {
    const result = {};
    const items = [];
    let isArray = null;

    while (!isDone()) {
      const raw = peek();
      const cleaned = parseLine(raw);
      if (cleaned.trim() === '---' || cleaned.trim() === '...') { next(); break; }
      if (cleaned.trim() === '') { next(); continue; }

      const ind = indent(raw);
      if (ind < baseIndent) break;

      next(); // consume

      const trimmed = cleaned.trim();

      // sequence item
      if (trimmed.startsWith('- ') || trimmed === '-') {
        isArray = true;
        const val = trimmed.slice(2).trim();
        if (val === '' || val === null) {
          items.push(parseBlock(ind + 2));
        } else if (val.includes(': ')) {
          // inline map
          const obj = {};
          const parts = val.split(/,\s*/);
          for (const part of parts) {
            const ci = part.indexOf(':');
            if (ci > -1) {
              obj[part.slice(0, ci).trim()] = parseValue(part.slice(ci + 1));
            }
          }
          items.push(obj);
        } else {
          items.push(parseValue(val));
        }
        continue;
      }

      // key: value
      const colonIdx = trimmed.indexOf(':');
      if (colonIdx > -1) {
        isArray = false;
        const key = trimmed.slice(0, colonIdx).trim();
        const rest = trimmed.slice(colonIdx + 1).trim();
        if (rest === '' || rest === null) {
          // peek for nested block
          const nextRaw = peek();
          if (!isDone() && nextRaw && indent(nextRaw) > ind) {
            result[key] = parseBlock(indent(nextRaw));
          } else {
            result[key] = null;
          }
        } else if (rest.startsWith('[')) {
          // inline sequence
          result[key] = rest.slice(1, rest.lastIndexOf(']'))
            .split(',').map(s => parseValue(s.trim()));
        } else if (rest.startsWith('{')) {
          // inline mapping
          const inner = rest.slice(1, rest.lastIndexOf('}'));
          const obj = {};
          for (const part of inner.split(',')) {
            const ci = part.indexOf(':');
            if (ci > -1) obj[part.slice(0, ci).trim()] = parseValue(part.slice(ci + 1));
          }
          result[key] = obj;
        } else {
          result[key] = parseValue(rest);
        }
      }
    }

    return isArray ? items : result;
  }

  const docs = [];
  while (!isDone()) {
    const raw = peek();
    if (parseLine(raw).trim() === '---') { next(); continue; }
    const doc = parseBlock(0);
    if (doc && (Array.isArray(doc) ? doc.length : Object.keys(doc).length)) {
      docs.push(doc);
    }
  }
  return docs.length === 1 ? docs[0] : docs.length > 1 ? docs : {};
}

// ---------------------------------------------------------------------------
// CSV parser
// ---------------------------------------------------------------------------
function parseCSV(text) {
  const lines = text.trim().split('\n');
  if (lines.length < 2) return [];
  const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
  return lines.slice(1).map(line => {
    const values = line.split(',').map(v => v.trim().replace(/^"|"$/g, ''));
    const obj = {};
    headers.forEach((h, i) => { obj[h] = values[i] !== undefined ? values[i] : ''; });
    return obj;
  });
}

// ---------------------------------------------------------------------------
// Normalizer  (heuristic type / provider detection)
// ---------------------------------------------------------------------------

const TYPE_HINTS = [
  { pattern: /s3.bucket|blob.container|gcs.bucket|storage/i,    type: 's3_bucket'       },
  { pattern: /security.group|firewall.rule|nsg|network.acl/i,   type: 'security_group'  },
  { pattern: /iam.polic|iam.role|iam.user|managed.polic/i,      type: 'iam_policy'      },
  { pattern: /ec2|vm|instance|compute/i,                         type: 'compute_instance'},
  { pattern: /rds|sql|database|db.instance/i,                   type: 'database'        },
  { pattern: /lambda|function.app|cloud.function/i,             type: 'serverless'      },
  { pattern: /kms|key.vault|cmk|encryption/i,                   type: 'encryption_key'  },
  { pattern: /cloudtrail|stackdriver|audit.log/i,               type: 'audit_log'       },
  { pattern: /elb|load.balancer|alb|nlb/i,                      type: 'load_balancer'   },
  { pattern: /subnet|vpc|vnet|network/i,                        type: 'network'         },
];

const PROVIDER_HINTS = [
  { pattern: /aws|amazon|s3|ec2|iam|arn:/i, provider: 'aws'   },
  { pattern: /azure|microsoft/i,            provider: 'azure' },
  { pattern: /gcp|google|gcs|bigquery/i,    provider: 'gcp'   },
];

function detectType(obj) {
  const probe = JSON.stringify(obj).toLowerCase();
  for (const hint of TYPE_HINTS) {
    if (hint.pattern.test(probe)) return hint.type;
  }
  return 'unknown';
}

function detectProvider(obj) {
  const probe = JSON.stringify(obj).toLowerCase();
  for (const hint of PROVIDER_HINTS) {
    if (hint.pattern.test(probe)) return hint.provider;
  }
  return 'unknown';
}

function extractField(obj, ...keys) {
  for (const key of keys) {
    // exact
    if (obj[key] !== undefined) return obj[key];
    // case-insensitive
    const found = Object.keys(obj).find(k => k.toLowerCase() === key.toLowerCase());
    if (found) return obj[found];
  }
  return undefined;
}

let _idCounter = 0;

/**
 * Normalize a raw parsed object into a Resource.
 * @param {object} raw
 * @param {number} index
 * @returns {object}
 */
function normalizeResource(raw, index) {
  if (typeof raw !== 'object' || raw === null) return null;

  const id =
    extractField(raw, 'id', 'resourceId', 'resource_id', 'arn', 'name', 'BucketName', 'bucket_name') ||
    `resource-${++_idCounter}`;

  const name =
    extractField(raw, 'name', 'Name', 'BucketName', 'bucket_name', 'FunctionName', 'resourceName', 'resource_name') ||
    String(id);

  const region =
    extractField(raw, 'region', 'Region', 'location', 'Location', 'zone') ||
    'global';

  const tags =
    extractField(raw, 'tags', 'Tags', 'labels', 'Labels') || {};

  const type =
    extractField(raw, 'type', 'Type', 'resourceType', 'resource_type', 'service', 'Service') ||
    detectType(raw);

  const provider =
    extractField(raw, 'provider', 'Provider', 'cloud', 'cloudProvider') ||
    detectProvider(raw);

  return { id: String(id), type, provider, region: String(region), name: String(name), tags, raw };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parse raw file text into a list of normalized resources.
 * @param {string} filename
 * @param {string} text  – raw file content
 * @returns {{ resources: object[], errors: string[] }}
 */
function parseFile(filename, text) {
  const errors = [];
  let resources = [];

  // Redact secrets first
  const safeText = redactSecrets(text);

  const fmt = detectFormat(filename, safeText);

  let parsed;
  try {
    if (fmt === 'json') {
      parsed = JSON.parse(safeText);
    } else if (fmt === 'csv') {
      parsed = parseCSV(safeText);
    } else {
      parsed = parseYAML(safeText);
    }
  } catch (e) {
    errors.push(`Parse error (${fmt}): ${e.message}`);
    return { resources: [], errors };
  }

  // Flatten: handle { Resources: [...] }, { resources: [...] }, { items: [...] }, arrays, or single object
  let items = [];
  if (Array.isArray(parsed)) {
    items = parsed;
  } else if (parsed && typeof parsed === 'object') {
    const listKey = ['Resources', 'resources', 'items', 'Items', 'data', 'Data', 'findings', 'results']
      .find(k => Array.isArray(parsed[k]));
    if (listKey) {
      items = parsed[listKey];
    } else {
      items = [parsed];
    }
  }

  _idCounter = 0;
  resources = items
    .map((item, i) => normalizeResource(item, i))
    .filter(Boolean);

  return { resources, errors };
}

// Export for both browser (global) and Node (module.exports)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { parseFile, redactSecrets, detectFormat, parseYAML, parseCSV, normalizeResource };
}
if (typeof window !== 'undefined') {
  window.CSPMParser = { parseFile, redactSecrets, detectFormat, parseYAML, parseCSV, normalizeResource };
}
