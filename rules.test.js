/**
 * CSPM Unit Tests
 * Run with: node tests/rules.test.js
 *
 * No external test framework required — uses a minimal TAP-style runner.
 */

'use strict';

const { parseFile, redactSecrets, detectFormat, parseYAML, parseCSV } = require('../src/parser');
const {
  runRules, resetFindingCounter,
  RULE_PUBLIC_STORAGE, RULE_IAM_WILDCARD, RULE_NETWORK_PUBLIC,
  RULE_ENCRYPTION, RULE_LOGGING,
} = require('../src/rules');

// ---------------------------------------------------------------------------
// Minimal test runner
// ---------------------------------------------------------------------------
let passed = 0, failed = 0, total = 0;
const failures = [];

function assert(condition, message) {
  total++;
  if (condition) {
    passed++;
    process.stdout.write(`  ✓ ${message}\n`);
  } else {
    failed++;
    failures.push(message);
    process.stdout.write(`  ✗ ${message}\n`);
  }
}

function assertEqual(a, b, message) {
  const ok = JSON.stringify(a) === JSON.stringify(b);
  if (!ok) process.stdout.write(`    Expected: ${JSON.stringify(b)}\n    Got:      ${JSON.stringify(a)}\n`);
  assert(ok, message);
}

function describe(name, fn) {
  process.stdout.write(`\n▶ ${name}\n`);
  fn();
}

// ---------------------------------------------------------------------------
// Helper: make a minimal resource
// ---------------------------------------------------------------------------
function makeResource(overrides) {
  return {
    id: 'test-resource',
    type: 'unknown',
    provider: 'aws',
    region: 'us-east-1',
    name: 'test-resource',
    tags: {},
    raw: {},
    ...overrides,
  };
}

// ============================================================================
// Parser tests
// ============================================================================

describe('Parser – redactSecrets', () => {
  assert(
    !redactSecrets('password: "superSecret123"').includes('superSecret123'),
    'Redacts password field values',
  );
  assert(
    !redactSecrets('api_key: "AKIA1234567890ABCDEF"').includes('AKIA1234567890ABCDEF'),
    'Redacts AWS-like access key patterns',
  );
  assert(
    redactSecrets('bucket: "my-bucket"').includes('my-bucket'),
    'Does not redact non-secret fields',
  );
});

describe('Parser – detectFormat', () => {
  assertEqual(detectFormat('test.json', ''), 'json', 'Detects .json by extension');
  assertEqual(detectFormat('test.csv', ''), 'csv', 'Detects .csv by extension');
  assertEqual(detectFormat('test.yaml', ''), 'yaml', 'Detects .yaml by extension');
  assertEqual(detectFormat('test.yml', ''), 'yaml', 'Detects .yml by extension');
  assertEqual(detectFormat('', '[{"a":1}]'), 'json', 'Detects JSON by content');
  assertEqual(detectFormat('', 'key: value'), 'yaml', 'Detects YAML by content');
});

describe('Parser – parseCSV', () => {
  const csv = `name,type,region\nbucket-a,s3_bucket,us-east-1\nbucket-b,s3_bucket,eu-west-1`;
  const { resources } = parseFile('test.csv', csv);
  assertEqual(resources.length, 2, 'Parses 2 CSV rows into 2 resources');
  assertEqual(resources[0].name, 'bucket-a', 'First resource name matches');
  assertEqual(resources[1].region, 'eu-west-1', 'Second resource region matches');
});

describe('Parser – parseJSON (array)', () => {
  const json = JSON.stringify([
    { id: 'r1', type: 's3_bucket', region: 'us-east-1', name: 'my-bucket' },
    { id: 'r2', type: 'security_group', region: 'us-west-2', name: 'my-sg' },
  ]);
  const { resources } = parseFile('data.json', json);
  assertEqual(resources.length, 2, 'Parses JSON array into 2 resources');
  assertEqual(resources[0].id, 'r1', 'First resource ID matches');
});

describe('Parser – parseJSON (wrapped)', () => {
  const json = JSON.stringify({ Resources: [{ id: 'r1', name: 'bucket', type: 's3_bucket' }] });
  const { resources } = parseFile('data.json', json);
  assertEqual(resources.length, 1, 'Unwraps Resources key');
});

describe('Parser – parseYAML (basic)', () => {
  const yaml = `name: test-bucket\ntype: s3_bucket\nregion: us-east-1`;
  const parsed = parseYAML(yaml);
  assertEqual(parsed.name, 'test-bucket', 'YAML scalar string');
  assertEqual(parsed.type, 's3_bucket', 'YAML second key');
});

describe('Parser – parse error handling', () => {
  const { resources, errors } = parseFile('bad.json', '{invalid json{{');
  assertEqual(resources.length, 0, 'Returns empty resources on parse error');
  assert(errors.length > 0, 'Returns error message on parse failure');
});

// ============================================================================
// Rule: PUBLIC-STORAGE-001
// ============================================================================

describe('Rule PUBLIC-STORAGE-001 – positive cases', () => {
  resetFindingCounter();

  const publicBucket = makeResource({
    name: 'public-bucket',
    raw: {
      id: 'public-bucket',
      type: 's3_bucket',
      BucketName: 'public-bucket',
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: false,
        BlockPublicPolicy: false,
        RestrictPublicBuckets: false,
      },
      ACL: 'public-read',
    },
  });

  const findings = RULE_PUBLIC_STORAGE.check(publicBucket);
  assert(findings.length > 0, 'Generates finding for public bucket');
  assertEqual(findings[0].severity, 'Critical', 'Severity is Critical');
  assertEqual(findings[0].status, 'Open', 'Status is Open');
  assertEqual(findings[0].ruleId, 'PUBLIC-STORAGE-001', 'Correct rule ID');
});

describe('Rule PUBLIC-STORAGE-001 – negative: private bucket', () => {
  resetFindingCounter();

  const privateBucket = makeResource({
    name: 'private-bucket',
    raw: {
      id: 'private-bucket',
      type: 's3_bucket',
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        RestrictPublicBuckets: true,
      },
      ACL: 'private',
    },
  });

  const findings = RULE_PUBLIC_STORAGE.check(privateBucket);
  assertEqual(findings.length, 0, 'No finding for private bucket');
});

describe('Rule PUBLIC-STORAGE-001 – non-storage resource ignored', () => {
  resetFindingCounter();
  const sg = makeResource({ name: 'sg-1', raw: { type: 'security_group', port: 22 } });
  const findings = RULE_PUBLIC_STORAGE.check(sg);
  assertEqual(findings.length, 0, 'Skips non-storage resources');
});

// ============================================================================
// Rule: IAM-WILDCARD-001
// ============================================================================

describe('Rule IAM-WILDCARD-001 – full admin (Action:* + Resource:*)', () => {
  resetFindingCounter();

  const adminPolicy = makeResource({
    name: 'AdminPolicy',
    raw: {
      PolicyName: 'AdminPolicy',
      Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
    },
  });

  const findings = RULE_IAM_WILDCARD.check(adminPolicy);
  assert(findings.length > 0, 'Generates finding for Action:* + Resource:*');
  assertEqual(findings[0].severity, 'Critical', 'Severity is Critical for full admin');
});

describe('Rule IAM-WILDCARD-001 – wildcard action only', () => {
  resetFindingCounter();

  const broadPolicy = makeResource({
    name: 'BroadPolicy',
    raw: {
      PolicyName: 'BroadPolicy',
      Statement: [{ Effect: 'Allow', Action: '*', Resource: 'arn:aws:s3:::my-bucket/*' }],
    },
  });

  const findings = RULE_IAM_WILDCARD.check(broadPolicy);
  assert(findings.length > 0, 'Generates finding for wildcard Action with Allow');
  assertEqual(findings[0].severity, 'High', 'Severity is High for wildcard action only');
});

describe('Rule IAM-WILDCARD-001 – least privilege policy, no finding', () => {
  resetFindingCounter();

  const leastPriv = makeResource({
    name: 'ReadOnlyPolicy',
    raw: {
      PolicyName: 'ReadOnlyPolicy',
      Statement: [{ Effect: 'Allow', Action: ['s3:GetObject', 's3:ListBucket'], Resource: 'arn:aws:s3:::my-bucket' }],
    },
  });

  const findings = RULE_IAM_WILDCARD.check(leastPriv);
  assertEqual(findings.length, 0, 'No finding for least-privilege policy');
});

describe('Rule IAM-WILDCARD-001 – non-IAM resource ignored', () => {
  resetFindingCounter();
  const bucket = makeResource({ name: 'bucket', raw: { type: 's3_bucket', public_access: true } });
  const findings = RULE_IAM_WILDCARD.check(bucket);
  assertEqual(findings.length, 0, 'Skips non-IAM resources');
});

// ============================================================================
// Rule: NETWORK-PUBLIC-001
// ============================================================================

describe('Rule NETWORK-PUBLIC-001 – SSH open to internet', () => {
  resetFindingCounter();

  const openSG = makeResource({
    name: 'open-sg',
    raw: {
      GroupName: 'open-sg',
      IpPermissions: [{
        FromPort: 22, ToPort: 22, IpProtocol: 'tcp',
        IpRanges: [{ CidrIp: '0.0.0.0/0', Direction: 'inbound' }],
      }],
    },
  });

  const findings = RULE_NETWORK_PUBLIC.check(openSG);
  assert(findings.length > 0, 'Generates finding for SSH open to 0.0.0.0/0');
  assertEqual(findings[0].severity, 'Critical', 'Critical for SSH port');
  assertEqual(findings[0].status, 'Open', 'Status is Open');
});

describe('Rule NETWORK-PUBLIC-001 – restricted SG, no finding', () => {
  resetFindingCounter();

  const restrictedSG = makeResource({
    name: 'restricted-sg',
    raw: {
      GroupName: 'restricted-sg',
      IpPermissions: [{
        FromPort: 22, ToPort: 22, IpProtocol: 'tcp',
        IpRanges: [{ CidrIp: '10.0.0.0/8', Direction: 'inbound' }],
      }],
    },
  });

  const findings = RULE_NETWORK_PUBLIC.check(restrictedSG);
  assertEqual(findings.length, 0, 'No finding for restricted CIDR');
});

describe('Rule NETWORK-PUBLIC-001 – IPv6 wildcard', () => {
  resetFindingCounter();

  const ipv6SG = makeResource({
    name: 'ipv6-sg',
    raw: {
      GroupName: 'ipv6-sg',
      IpPermissions: [{
        FromPort: 3389, ToPort: 3389, IpProtocol: 'tcp',
        Ipv6Ranges: [{ CidrIpv6: '::/0', Direction: 'inbound' }],
      }],
    },
  });

  const findings = RULE_NETWORK_PUBLIC.check(ipv6SG);
  assert(findings.length > 0, 'Generates finding for ::/0');
});

// ============================================================================
// Rule: ENCRYPTION-001
// ============================================================================

describe('Rule ENCRYPTION-001 – encryption explicitly disabled', () => {
  resetFindingCounter();

  const unencrypted = makeResource({
    name: 'unencrypted-db',
    raw: {
      DBInstanceIdentifier: 'unencrypted-db',
      DBInstanceClass: 'db.t3.micro',
      Engine: 'mysql',
      StorageEncrypted: false,
      encryption_enabled: false,
    },
  });

  const findings = RULE_ENCRYPTION.check(unencrypted);
  assert(findings.length > 0, 'Generates finding for disabled encryption');
  assertEqual(findings[0].severity, 'High', 'Severity is High');
  assertEqual(findings[0].status, 'Open', 'Status is Open');
});

describe('Rule ENCRYPTION-001 – encryption enabled, no finding', () => {
  resetFindingCounter();

  const encrypted = makeResource({
    name: 'encrypted-db',
    raw: {
      DBInstanceIdentifier: 'encrypted-db',
      Engine: 'postgres',
      StorageEncrypted: true,
      KmsKeyId: 'arn:aws:kms:us-east-1:123456789:key/abc',
    },
  });

  const findings = RULE_ENCRYPTION.check(encrypted);
  assertEqual(findings.length, 0, 'No finding for encrypted resource');
});

describe('Rule ENCRYPTION-001 – no encryption evidence → Needs Review', () => {
  resetFindingCounter();

  const ambiguous = makeResource({
    name: 'mystery-bucket',
    raw: { BucketName: 'mystery-bucket', region: 'us-east-1' },
  });

  const findings = RULE_ENCRYPTION.check(ambiguous);
  assert(findings.length > 0, 'Generates Needs Review for missing encryption field');
  assertEqual(findings[0].status, 'Needs Review', 'Status is Needs Review');
});

// ============================================================================
// Rule: LOGGING-001
// ============================================================================

describe('Rule LOGGING-001 – logging explicitly disabled', () => {
  resetFindingCounter();

  const noLogging = makeResource({
    name: 'no-trail',
    raw: {
      TrailName: 'no-trail',
      cloudtrail_enabled: false,
      logging_enabled: false,
      IsLogging: false,
    },
  });

  const findings = RULE_LOGGING.check(noLogging);
  assert(findings.length > 0, 'Generates finding for disabled logging');
  assertEqual(findings[0].severity, 'Medium', 'Severity is Medium');
});

describe('Rule LOGGING-001 – logging enabled, no finding', () => {
  resetFindingCounter();

  const withLogging = makeResource({
    name: 'prod-trail',
    raw: {
      TrailName: 'prod-trail',
      IsLogging: true,
      logging_enabled: true,
    },
  });

  const findings = RULE_LOGGING.check(withLogging);
  assertEqual(findings.length, 0, 'No finding when logging is enabled');
});

describe('Rule LOGGING-001 – ambiguous → Needs Review', () => {
  resetFindingCounter();

  const ambiguous = makeResource({
    name: 'some-trail',
    raw: { TrailName: 'some-trail', audit: 'partial-config', log_group: '/aws/cloudtrail' },
  });

  const findings = RULE_LOGGING.check(ambiguous);
  assert(findings.length > 0, 'Generates Needs Review for ambiguous logging');
  assertEqual(findings[0].status, 'Needs Review', 'Status is Needs Review');
});

// ============================================================================
// Integration: runRules across full resource list
// ============================================================================

describe('Integration – runRules with mixed resources', () => {
  resetFindingCounter();

  const resources = [
    makeResource({
      id: 'public-bucket', name: 'public-bucket', type: 's3_bucket',
      raw: { BucketName: 'public-bucket', ACL: 'public-read', block_public_acls: false },
    }),
    makeResource({
      id: 'admin-role', name: 'AdminRole', type: 'iam_policy',
      raw: { PolicyName: 'AdminRole', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] },
    }),
    makeResource({
      id: 'open-sg', name: 'open-sg', type: 'security_group',
      raw: { GroupName: 'open-sg', inbound: true, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
    }),
    makeResource({
      id: 'secure-bucket', name: 'secure-bucket', type: 's3_bucket',
      raw: { BucketName: 'secure-bucket', ACL: 'private', StorageEncrypted: true, logging_enabled: true },
    }),
  ];

  const findings = runRules(resources);
  assert(findings.length > 0, 'Integration run produces findings');

  const openFindings = findings.filter(f => f.status === 'Open');
  assert(openFindings.length > 0, 'At least some Open findings');

  const ruleIds = new Set(findings.map(f => f.ruleId));
  assert(ruleIds.has('PUBLIC-STORAGE-001'), 'PUBLIC-STORAGE-001 triggered');
  assert(ruleIds.has('IAM-WILDCARD-001'), 'IAM-WILDCARD-001 triggered');
  assert(ruleIds.has('NETWORK-PUBLIC-001'), 'NETWORK-PUBLIC-001 triggered');

  // All findings have required fields
  for (const f of findings) {
    assert(
      f.findingId && f.ruleId && f.severity && f.category && f.resource && f.status,
      `Finding ${f.findingId} has all required fields`,
    );
  }
});

describe('Integration – rule errors do not crash runRules', () => {
  resetFindingCounter();
  // Pass a resource with circular reference in raw (rules use JSON.stringify; should not throw)
  const r = makeResource({ id: 'bad', name: 'bad', raw: {} });
  // runRules should not throw
  let threw = false;
  try { runRules([r]); } catch { threw = true; }
  assert(!threw, 'runRules does not throw on edge-case resources');
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
process.stdout.write(`\n${'─'.repeat(50)}\n`);
process.stdout.write(`Tests: ${total}  Passed: ${passed}  Failed: ${failed}\n`);
if (failures.length) {
  process.stdout.write('\nFailed tests:\n');
  failures.forEach(f => process.stdout.write(`  ✗ ${f}\n`));
  process.exit(1);
} else {
  process.stdout.write('All tests passed ✓\n');
  process.exit(0);
}
