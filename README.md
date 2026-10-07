# CSPM Audit — Cloud Security Posture Manager

> **Read-Only · Defensive · Client-Side Only**

A working Cloud Security Posture Management (CSPM) web application that parses
cloud configuration exports (JSON / CSV / YAML) and detects common security
misconfigurations — entirely in your browser with no server, no cloud
credentials, and no external dependencies.

---

## ⚡ Quick Start

```bash
# Option 1 — open directly (no server needed)
open cspm-app/index.html          # macOS
start cspm-app/index.html         # Windows
xdg-open cspm-app/index.html      # Linux

# Option 2 — serve locally (avoids some browser file restrictions)
cd cspm-app
npx serve .                        # or: python -m http.server 8080
# Then open http://localhost:8080
```

No `npm install`, no build step, no backend. The app is a single self-contained
HTML file.

---

## 🧪 Run Unit Tests

Requires **Node.js ≥ 14** (no other dependencies).

```bash
cd cspm-app
node tests/rules.test.js
```

Expected output:
```
▶ Parser – redactSecrets
  ✓ Redacts password field values
  ...
──────────────────────────────────────────────────
Tests: 42  Passed: 42  Failed: 0
All tests passed ✓
```

---

## 📁 Project Structure

```
cspm-app/
├── index.html               # Full single-file web application (open this)
├── src/
│   ├── parser.js            # File parser + normalizer (JSON/CSV/YAML)
│   └── rules.js             # Security rules engine (5 rules)
├── tests/
│   └── rules.test.js        # Unit tests (Node, no framework)
├── demo-data/
│   ├── demo-aws-resources.json    # Synthetic AWS demo data
│   ├── demo-azure-resources.yaml  # Synthetic Azure demo data
│   └── demo-gcp-resources.csv     # Synthetic GCP demo data
└── README.md
```

The `src/` modules are standalone (usable in Node or browser). The `index.html`
contains inlined copies of the same logic so no build step is needed.

---

## 🔍 Security Rules

| Rule ID | Category | What it detects |
|---|---|---|
| `PUBLIC-STORAGE-001` | Public Storage | Public/anonymous storage access (ACL, block-public-access flags) |
| `IAM-WILDCARD-001` | Excessive IAM Permissions | Wildcard `Action: "*"` or `Resource: "*"` in IAM policies |
| `NETWORK-PUBLIC-001` | Public Network Exposure | Inbound rules allowing `0.0.0.0/0` or `::/0` |
| `ENCRYPTION-001` | Missing Encryption | Explicitly disabled or absent encryption configuration |
| `LOGGING-001` | Missing Security Logging | Explicitly disabled or absent audit/security logging |

### Severity scale

| Severity | Meaning |
|---|---|
| Critical | Immediate risk — e.g. full admin IAM, SSH open to internet |
| High | Serious misconfiguration requiring prompt remediation |
| Medium | Risk present but mitigating factors possible |
| Low | Minor issue or best-practice deviation |
| Informational | Observation only |

### Ambiguity policy

Rules never claim a problem without sufficient evidence:
- If evidence is **explicit** (e.g. `StorageEncrypted: false`) → `Open`
- If evidence is **ambiguous** (field missing, direction unclear) → `Needs Review`
- If **no relevant evidence** → no finding at all

---

## 📥 Supported Input Formats

### JSON
```json
[
  {
    "id": "my-bucket",
    "type": "s3_bucket",
    "provider": "aws",
    "region": "us-east-1",
    "ACL": "public-read",
    "PublicAccessBlockConfiguration": { "BlockPublicAcls": false }
  }
]
```
Also accepts `{ "Resources": [...] }`, `{ "resources": [...] }`, `{ "items": [...] }`,
`{ "data": [...] }` wrapper objects, or a single object.

### CSV
```csv
id,name,type,provider,region,ACL,block_public_acls,encryption_enabled
bucket-1,my-bucket,s3_bucket,aws,us-east-1,public-read,false,false
```
First row is treated as the header.

### YAML
```yaml
resources:
  - id: my-bucket
    type: s3_bucket
    provider: aws
    region: us-east-1
    ACL: public-read
    block_public_acls: false
```

---

## 🧪 Demo Data

Click **"Load Demo Data"** in the app (or **"🧪 Load Synthetic Demo"** on the
Upload page) to run an audit against built-in synthetic data.

The demo data (`demo-data/` folder) can also be uploaded directly. It contains:

| Resource | Issue |
|---|---|
| `demo-public-data-bucket` | Public S3 bucket (ACL + block-public-access disabled) |
| `DemoFullAdminPolicy` | IAM policy with `Action:*` + `Resource:*` |
| `demo-web-sg-open` | Security group allowing SSH+RDP from `0.0.0.0/0` |
| `demo-db-unencrypted` | RDS instance with encryption disabled |
| `demo-trail-disabled` | CloudTrail with logging disabled |
| `demo-secure-bucket` | ✅ Correctly secured bucket (no findings) |
| `demo-internal-sg` | ✅ Internal-only security group (no findings) |
| `DemoReadOnlyPolicy` | ✅ Least-privilege IAM policy (no findings) |
| `demo-trail-active` | ✅ Active CloudTrail (no findings) |

All data is clearly labelled **SYNTHETIC DEMO DATA** and contains no real
cloud account information.

---

## 🔒 Security Guarantees

- **No network requests** — the app makes zero HTTP calls after load.
- **No cloud credentials required** — the app never asks for or stores credentials.
- **Credential redaction** — passwords, tokens, API keys, and AWS access keys
  found in uploaded files are automatically redacted before parsing.
- **No file execution** — uploaded files are read as plain text only.
- **Read-only** — the app has no ability to modify any cloud resource.
- **No persistence** — data lives only in browser memory and is gone on refresh.

---

## 📊 UI Pages

| Page | Description |
|---|---|
| **Dashboard** | Total resources, findings, severity counts, bar charts by category/provider/rule |
| **Upload** | Drop zone for JSON/CSV/YAML files; shows file queue, runs audit |
| **Findings** | Filterable/sortable table; click any row for full details; export CSV |
| **Report** | Executive summary, rules summary, all findings; export JSON or print to PDF |

---

## 📤 Exports

- **CSV export** — filtered findings table as a spreadsheet
- **JSON export** — full findings list with metadata
- **Print/PDF** — use browser print dialog from the Report page

---

## Architecture

```
Upload (file text)
  └─ parser.js::parseFile()
       ├─ redactSecrets()        — strip credentials
       ├─ detectFormat()         — json | csv | yaml
       ├─ parse*(text)           — format-specific parser
       └─ normalizeResource()    — uniform {id,type,provider,region,name,tags,raw}
            └─ rules.js::runRules(resources)
                 ├─ PUBLIC-STORAGE-001.check(resource)
                 ├─ IAM-WILDCARD-001.check(resource)
                 ├─ NETWORK-PUBLIC-001.check(resource)
                 ├─ ENCRYPTION-001.check(resource)
                 └─ LOGGING-001.check(resource)
                      └─ [{findingId, ruleId, severity, category,
                            provider, resource, resourceName, region,
                            description, evidence, impact, remediation, status}]
```
