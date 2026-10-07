/**
 * CSPM Security Rules Engine
 *
 * Rules:
 *   PUBLIC-STORAGE-001  – public/anonymous storage access
 *   IAM-WILDCARD-001    – wildcard IAM permissions
 *   NETWORK-PUBLIC-001  – unrestricted inbound 0.0.0.0/0 or ::/0
 *   ENCRYPTION-001      – disabled/missing encryption (explicit evidence only)
 *   LOGGING-001         – disabled/missing audit logging (explicit evidence only)
 *
 * Finding shape:
 * {
 *   findingId:    string
 *   ruleId:       string
 *   severity:     'Critical'|'High'|'Medium'|'Low'|'Informational'
 *   category:     string
 *   provider:     string
 *   resource:     string  (resource id)
 *   resourceName: string
 *   region:       string
 *   description:  string
 *   evidence:     string
 *   impact:       string
 *   remediation:  string
 *   status:       'Open'|'Needs Review'|'Resolved'
 * }
 */

'use strict';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let _findingCounter = 0;

function newFindingId() {
  return `FND-${String(++_findingCounter).padStart(5, '0')}`;
}

function resetFindingCounter() {
  _findingCounter = 0;
}

/**
 * Recursively search an object for a key (case-insensitive).
 * Returns all matching values.
 */
function deepFind(obj, keyPattern, maxDepth = 8) {
  const results = [];
  function walk(node, depth) {
    if (depth > maxDepth || node === null || typeof node !== 'object') return;
    for (const [k, v] of Object.entries(node)) {
      if (keyPattern.test(k)) results.push({ key: k, value: v, parent: node });
      walk(v, depth + 1);
    }
  }
  walk(obj, 0);
  return results;
}

function stringify(v) {
  if (typeof v === 'string') return v;
  return JSON.stringify(v);
}

function isTruthy(v) {
  if (v === null || v === undefined) return false;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') return /^(true|yes|1|enabled)$/i.test(v.trim());
  if (typeof v === 'number') return v !== 0;
  return false;
}

function isFalsy(v) {
  if (v === null || v === undefined) return false; // unknown, not falsy
  if (typeof v === 'boolean') return !v;
  if (typeof v === 'string') return /^(false|no|0|disabled|none)$/i.test(v.trim());
  if (typeof v === 'number') return v === 0;
  return false;
}

// ---------------------------------------------------------------------------
// Rule: PUBLIC-STORAGE-001
// ---------------------------------------------------------------------------
const RULE_PUBLIC_STORAGE = {
  id: 'PUBLIC-STORAGE-001',
  name: 'Public Storage Access Detected',
  severity: 'Critical',
  category: 'Public Storage',
  applicableTypes: ['s3_bucket', 'storage', 'blob', 'unknown'],

  check(resource) {
    const raw = resource.raw;
    const findings = [];
    const probe = JSON.stringify(raw).toLowerCase();

    // Must look like a storage resource
    const isStorage = /bucket|blob|storage|container|object/i.test(probe);
    if (!isStorage) return findings;

    // Evidence signals (explicit)
    const publicSignals = [
      /public.?access.?block.*false/i,
      /acl.*public/i,
      /public-read|public-write|public-read-write/i,
      /"AllUsers"|AllUsers/,
      /anonymous.?access.*true/i,
      /block_public_acls.*false/i,
      /block_public_policy.*false/i,
      /restrict_public_buckets.*false/i,
      /allow_public_access.*true/i,
      /public_access.*true/i,
    ];

    const matched = publicSignals.filter(re => re.test(JSON.stringify(raw)));

    if (matched.length === 0) {
      // Check for ambiguous partial evidence → Needs Review
      // Require an explicit "public" value or AllUsers presence — not just any ACL key.
      const ambiguous = /public|AllUsers/i.test(JSON.stringify(raw)) &&
        !/acl.*private|private.*acl|access.*block.*true|block.*true/i.test(JSON.stringify(raw));
      if (ambiguous) {
        findings.push({
          findingId: newFindingId(),
          ruleId: this.id,
          severity: 'Medium',
          category: this.category,
          provider: resource.provider,
          resource: resource.id,
          resourceName: resource.name,
          region: resource.region,
          description: 'Storage resource may allow public access — insufficient evidence to confirm.',
          evidence: 'Partial access-control fields detected but public access not explicitly confirmed.',
          impact: 'If public, unauthorized users could read or list sensitive data.',
          remediation: 'Review ACL, bucket policy, and public-access-block settings explicitly.',
          status: 'Needs Review',
        });
      }
      return findings;
    }

    findings.push({
      findingId: newFindingId(),
      ruleId: this.id,
      severity: this.severity,
      category: this.category,
      provider: resource.provider,
      resource: resource.id,
      resourceName: resource.name,
      region: resource.region,
      description: `Storage resource "${resource.name}" is configured for public/anonymous access.`,
      evidence: matched.map(re => re.toString()).join('; '),
      impact: 'Unauthorized users can read, list, or write objects. Risk of data exfiltration or tampering.',
      remediation: 'Enable block-public-access settings, remove public ACLs, and apply a restrictive bucket policy.',
      status: 'Open',
    });

    return findings;
  },
};

// ---------------------------------------------------------------------------
// Rule: IAM-WILDCARD-001
// ---------------------------------------------------------------------------
const RULE_IAM_WILDCARD = {
  id: 'IAM-WILDCARD-001',
  name: 'Overly Broad IAM Permissions',
  severity: 'High',
  category: 'Excessive IAM Permissions',
  applicableTypes: ['iam_policy', 'iam_role', 'iam_user', 'unknown'],

  check(resource) {
    const raw = resource.raw;
    const findings = [];
    const rawStr = JSON.stringify(raw);

    // Must look like IAM
    const isIAM = /iam|polic|role|permission|statement|principal/i.test(rawStr);
    if (!isIAM) return findings;

    const wildcardAction   = /"Action"\s*:\s*"\*"|action.*:\s*"\*"|actions?.*:\s*\[?\s*"\*"/i.test(rawStr);
    const wildcardResource = /"Resource"\s*:\s*"\*"|resource.*:\s*"\*"/i.test(rawStr);
    const wildcardEffect   = /Effect.*Allow/i.test(rawStr);

    // Full admin: Action:* + Resource:*
    if (wildcardAction && wildcardResource) {
      findings.push({
        findingId: newFindingId(),
        ruleId: this.id,
        severity: 'Critical',
        category: this.category,
        provider: resource.provider,
        resource: resource.id,
        resourceName: resource.name,
        region: resource.region,
        description: `IAM policy "${resource.name}" grants unrestricted full-admin (Action:* + Resource:*).`,
        evidence: 'Action: "*" and Resource: "*" both present in policy statements.',
        impact: 'Full administrative access to all services and resources. Highest privilege escalation risk.',
        remediation: 'Replace wildcard permissions with least-privilege actions scoped to specific resources.',
        status: 'Open',
      });
      return findings;
    }

    // Wildcard action only
    if (wildcardAction && wildcardEffect) {
      findings.push({
        findingId: newFindingId(),
        ruleId: this.id,
        severity: this.severity,
        category: this.category,
        provider: resource.provider,
        resource: resource.id,
        resourceName: resource.name,
        region: resource.region,
        description: `IAM policy "${resource.name}" uses wildcard Action (*) with Allow effect.`,
        evidence: 'Action: "*" found in an Allow statement.',
        impact: 'All actions permitted on scoped resources. Risk of unintended privilege expansion.',
        remediation: 'Enumerate specific required actions instead of using Action: "*".',
        status: 'Open',
      });
    } else if (wildcardAction) {
      findings.push({
        findingId: newFindingId(),
        ruleId: this.id,
        severity: 'Medium',
        category: this.category,
        provider: resource.provider,
        resource: resource.id,
        resourceName: resource.name,
        region: resource.region,
        description: `IAM policy "${resource.name}" contains wildcard Action — effect unclear.`,
        evidence: 'Action: "*" found but Effect not confirmed Allow.',
        impact: 'May grant broad permissions depending on effect.',
        remediation: 'Review policy Effect and restrict Action to required operations.',
        status: 'Needs Review',
      });
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// Rule: NETWORK-PUBLIC-001
// ---------------------------------------------------------------------------
const RULE_NETWORK_PUBLIC = {
  id: 'NETWORK-PUBLIC-001',
  name: 'Unrestricted Inbound Network Access',
  severity: 'High',
  category: 'Public Network Exposure',

  check(resource) {
    const raw = resource.raw;
    const findings = [];
    const rawStr = JSON.stringify(raw);

    // Must look like a network rule
    const isNetwork = /security.group|firewall|nsg|network.acl|inbound|ingress|port|cidr|ip.range/i.test(rawStr);
    if (!isNetwork) return findings;

    const hasWildcard4 = /0\.0\.0\.0\/0/.test(rawStr);
    const hasWildcard6 = /::\/?0/.test(rawStr) || /"::"/.test(rawStr);
    const isInbound = /inbound|ingress|direction.*inbound|direction.*ingress/i.test(rawStr);
    const isAllow   = /allow|ALLOW/i.test(rawStr);

    if ((hasWildcard4 || hasWildcard6) && (isInbound || !rawStr.includes('direction'))) {
      const cidrEvidence = [];
      if (hasWildcard4) cidrEvidence.push('0.0.0.0/0');
      if (hasWildcard6) cidrEvidence.push('::/0');

      // Check for sensitive ports
      const sensitivePorts = [22, 3389, 5432, 3306, 1433, 27017, 6379, 9200, 8080, 443, 80];
      const portMatches = sensitivePorts.filter(p => rawStr.includes(String(p)));

      const severity = portMatches.some(p => [22, 3389, 5432, 3306, 1433].includes(p))
        ? 'Critical' : this.severity;

      findings.push({
        findingId: newFindingId(),
        ruleId: this.id,
        severity,
        category: this.category,
        provider: resource.provider,
        resource: resource.id,
        resourceName: resource.name,
        region: resource.region,
        description: `Security group/firewall rule "${resource.name}" allows unrestricted inbound access from the internet.`,
        evidence: `CIDR: ${cidrEvidence.join(', ')}${portMatches.length ? `; Ports: ${portMatches.join(', ')}` : ''}`,
        impact: 'Any IP address can connect to exposed ports. Enables brute-force, scanning, and exploitation.',
        remediation: 'Restrict source CIDRs to known IP ranges. Close or remove rules allowing 0.0.0.0/0 or ::/0.',
        status: 'Open',
      });
    } else if (hasWildcard4 || hasWildcard6) {
      // Has wildcard CIDR but direction unknown
      findings.push({
        findingId: newFindingId(),
        ruleId: this.id,
        severity: 'Medium',
        category: this.category,
        provider: resource.provider,
        resource: resource.id,
        resourceName: resource.name,
        region: resource.region,
        description: `Network rule "${resource.name}" references 0.0.0.0/0 — direction not explicitly inbound.`,
        evidence: `CIDR 0.0.0.0/0 or ::/0 present; direction field missing or ambiguous.`,
        impact: 'Potential unrestricted access if direction is inbound.',
        remediation: 'Verify rule direction and restrict source CIDRs.',
        status: 'Needs Review',
      });
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// Rule: ENCRYPTION-001
// ---------------------------------------------------------------------------
const RULE_ENCRYPTION = {
  id: 'ENCRYPTION-001',
  name: 'Encryption Disabled or Not Configured',
  severity: 'High',
  category: 'Missing Encryption',

  check(resource) {
    const raw = resource.raw;
    const findings = [];
    const rawStr = JSON.stringify(raw);

    // Must look like an encryptable resource
    const isEncryptable = /bucket|storage|database|disk|volume|ebs|rds|kms|encrypt/i.test(rawStr);
    if (!isEncryptable) return findings;

    // Explicit disabled signals
    const encryptionDisabled = [
      /encrypt.*:\s*(false|no|0|disabled)/i,
      /server.?side.?encrypt.*:\s*(false|no|disabled)/i,
      /encryption.?at.?rest.*:\s*(false|no|disabled)/i,
      /kms.*:\s*null/i,
      /encryption.?enabled.*:\s*(false|no)/i,
    ].some(re => re.test(rawStr));

    // Explicit enabled signals
    const encryptionEnabled = [
      /encrypt.*:\s*(true|yes|1|enabled|AES256|aws:kms)/i,
      /server.?side.?encrypt.*:\s*(true|AES256|aws:kms)/i,
      /encryption.?at.?rest.*:\s*(true|enabled)/i,
      /kms.?key.?id.*:\s*"[^"]{3,}"/i,
    ].some(re => re.test(rawStr));

    if (encryptionDisabled) {
      findings.push({
        findingId: newFindingId(),
        ruleId: this.id,
        severity: this.severity,
        category: this.category,
        provider: resource.provider,
        resource: resource.id,
        resourceName: resource.name,
        region: resource.region,
        description: `Resource "${resource.name}" has encryption explicitly disabled.`,
        evidence: 'Encryption field found with value false/disabled/null.',
        impact: 'Data at rest is unencrypted. Risk of exposure if storage media is compromised.',
        remediation: 'Enable server-side encryption using a managed or customer-managed key.',
        status: 'Open',
      });
    } else if (!encryptionEnabled) {
      // No evidence either way
      findings.push({
        findingId: newFindingId(),
        ruleId: this.id,
        severity: 'Medium',
        category: this.category,
        provider: resource.provider,
        resource: resource.id,
        resourceName: resource.name,
        region: resource.region,
        description: `Resource "${resource.name}" does not have a confirmed encryption configuration.`,
        evidence: 'No explicit encryption field found in resource definition.',
        impact: 'Encryption status unknown. Data may be stored unencrypted.',
        remediation: 'Verify and explicitly configure server-side encryption.',
        status: 'Needs Review',
      });
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// Rule: LOGGING-001
// ---------------------------------------------------------------------------
const RULE_LOGGING = {
  id: 'LOGGING-001',
  name: 'Security/Audit Logging Disabled or Missing',
  severity: 'Medium',
  category: 'Missing Security Logging',

  check(resource) {
    const raw = resource.raw;
    const findings = [];
    const rawStr = JSON.stringify(raw);

    // Must look like a loggable resource
    const isLoggable = /trail|cloudtrail|audit|logging|log|monitoring|access.log/i.test(rawStr);
    if (!isLoggable) return findings;

    // Explicit disabled
    const loggingDisabled = [
      /logging.*:\s*(false|no|0|disabled)/i,
      /enable.*log.*:\s*(false|no)/i,
      /log.?enabled.*:\s*(false|no)/i,
      /audit.*enabled.*:\s*(false|no)/i,
      /cloudtrail.*enabled.*:\s*(false)/i,
      /is.?logging.*:\s*(false)/i,
    ].some(re => re.test(rawStr));

    // Explicit enabled
    const loggingEnabled = [
      /logging.*:\s*(true|yes|1|enabled)/i,
      /log.?enabled.*:\s*(true|yes)/i,
      /audit.*enabled.*:\s*(true)/i,
      /cloudtrail.*enabled.*:\s*(true)/i,
      /is.?logging.*:\s*(true)/i,
    ].some(re => re.test(rawStr));

    if (loggingDisabled) {
      findings.push({
        findingId: newFindingId(),
        ruleId: this.id,
        severity: this.severity,
        category: this.category,
        provider: resource.provider,
        resource: resource.id,
        resourceName: resource.name,
        region: resource.region,
        description: `Resource "${resource.name}" has audit/security logging explicitly disabled.`,
        evidence: 'Logging field found with value false/disabled.',
        impact: 'Security events are not recorded. Incident detection and forensic investigation are impaired.',
        remediation: 'Enable CloudTrail / audit logging for this resource and ensure logs are retained.',
        status: 'Open',
      });
    } else if (!loggingEnabled) {
      findings.push({
        findingId: newFindingId(),
        ruleId: this.id,
        severity: 'Low',
        category: this.category,
        provider: resource.provider,
        resource: resource.id,
        resourceName: resource.name,
        region: resource.region,
        description: `Resource "${resource.name}" does not have a confirmed logging configuration.`,
        evidence: 'Logging keyword present but no explicit enabled/disabled state found.',
        impact: 'Logging status unknown. Security events may not be captured.',
        remediation: 'Verify logging is enabled and review log retention policy.',
        status: 'Needs Review',
      });
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// Rules registry and runner
// ---------------------------------------------------------------------------

const ALL_RULES = [
  RULE_PUBLIC_STORAGE,
  RULE_IAM_WILDCARD,
  RULE_NETWORK_PUBLIC,
  RULE_ENCRYPTION,
  RULE_LOGGING,
];

/**
 * Run all rules against a list of normalized resources.
 * @param {object[]} resources
 * @returns {object[]} findings
 */
function runRules(resources) {
  resetFindingCounter();
  const findings = [];
  for (const resource of resources) {
    for (const rule of ALL_RULES) {
      try {
        const rulefindings = rule.check(resource);
        findings.push(...rulefindings);
      } catch (e) {
        // Rule errors must not crash the audit
        console.warn(`Rule ${rule.id} threw on resource ${resource.id}:`, e.message);
      }
    }
  }
  return findings;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    runRules,
    resetFindingCounter,
    RULE_PUBLIC_STORAGE,
    RULE_IAM_WILDCARD,
    RULE_NETWORK_PUBLIC,
    RULE_ENCRYPTION,
    RULE_LOGGING,
    ALL_RULES,
  };
}
if (typeof window !== 'undefined') {
  window.CSPMRules = {
    runRules,
    resetFindingCounter,
    RULE_PUBLIC_STORAGE,
    RULE_IAM_WILDCARD,
    RULE_NETWORK_PUBLIC,
    RULE_ENCRYPTION,
    RULE_LOGGING,
    ALL_RULES,
  };
}
