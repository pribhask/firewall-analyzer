# firewall-analyzer

Production-grade GitHub App that analyzes Terraform pull requests for AWS Network Firewall rule changes, performs semantic diffing, risk scoring, and posts structured security review comments.

---

## Project Structure

```
.
├── cmd/
│   └── server/
│       └── main.go                    # HTTP server entry point
├── internal/
│   ├── auth/
│   │   ├── jwt.go                     # RSA JWT signing for GitHub App auth
│   │   └── installation.go            # Installation access token exchange + cache
│   ├── webhook/
│   │   └── verify.go                  # HMAC-SHA256 signature verification + routing
│   ├── github/
│   │   ├── client.go                  # GitHub REST API client
│   │   └── util.go                    # Internal helpers
│   ├── terraform/
│   │   ├── models.go                  # Data structures for firewall resources
│   │   ├── parser.go                  # HCL v2 parser (hclsyntax, no regex)
│   │   ├── diff.go                    # Semantic diff engine + CIDR analysis
│   │   └── suricata.go                # Suricata rule parser + indexing
│   └── analyzer/
│       ├── analyzer.go                # PR orchestration pipeline
│       ├── risk.go                    # Risk scoring engine (0–10)
│       └── report.go                  # Markdown PR comment generator
├── Dockerfile
├── go.mod
└── README.md
```

---

## Prerequisites

- **Go 1.22+**
- A registered **GitHub App** with:
  - `Pull requests: Read & Write` permission
  - `Contents: Read` permission
  - Subscribed to `Pull request` webhook events
  - An RSA private key generated via GitHub App settings

---

## Build

```bash
# Clone and enter directory
git clone https://github.com/your-org/firewall-analyzer
cd firewall-analyzer

# Download dependencies
go mod tidy

# Build binary
go build -o firewall-analyzer ./cmd/server

# Or build with Docker
docker build -t firewall-analyzer:latest .
```

---

## Environment Variables

| Variable                  | Required | Description                                             |
| ------------------------- | -------- | ------------------------------------------------------- |
| `GITHUB_APP_ID`           | ✅       | Numeric GitHub App ID (from App settings page)          |
| `GITHUB_PRIVATE_KEY_PATH` | ✅       | Absolute path to the App's RSA `.pem` private key       |
| `GITHUB_WEBHOOK_SECRET`   | ✅       | Shared secret configured in GitHub App webhook settings |
| `PORT`                    | ❌       | HTTP listen port (default: `8080`)                      |

---

## Running Locally

```bash
export GITHUB_APP_ID=123456
export GITHUB_PRIVATE_KEY_PATH=/path/to/private-key.pem
export GITHUB_WEBHOOK_SECRET=your-webhook-secret
export PORT=8080

./firewall-analyzer
```

For local development with webhook delivery, use [smee.io](https://smee.io) or `ngrok`:

```bash
# Install smee client
npm install -g smee-client

# Forward webhooks to local server
smee --url https://smee.io/YOUR_CHANNEL --target http://localhost:8080/webhook
```

---

## Docker

```bash
docker run \
  -e GITHUB_APP_ID=123456 \
  -e GITHUB_PRIVATE_KEY_PATH=/secrets/private-key.pem \
  -e GITHUB_WEBHOOK_SECRET=your-webhook-secret \
  -v /host/path/to/keys:/secrets:ro \
  -p 8080:8080 \
  firewall-analyzer:latest
```

---

## Example curl Webhook Test

```bash
# Compute HMAC signature
PAYLOAD='{"action":"opened","number":42,"installation":{"id":987654},"pull_request":{"number":42,"head":{"sha":"abc123def456","repo":{"full_name":"org/repo","name":"repo","owner":{"login":"org"}}},"base":{"sha":"000111222333","repo":{"full_name":"org/repo","name":"repo","owner":{"login":"org"}}}},"repository":{"full_name":"org/repo","name":"repo","owner":{"login":"org"}}}'

SECRET="your-webhook-secret"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print "sha256="$2}')

curl -X POST http://localhost:8080/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -H "X-Hub-Signature-256: ${SIGNATURE}" \
  -H "X-GitHub-Delivery: test-delivery-$(uuidgen)" \
  -d "$PAYLOAD"
```

---

## Example Terraform File (Triggers Analysis)

```hcl
resource "aws_networkfirewall_rule_group" "example" {
  name        = "example-stateful-rules"
  description = "Example stateful rule group"
  capacity    = 100
  type        = "STATEFUL"

  rule_group {
    rules_source {
      stateful_rule {
        action = "PASS"
        header {
          protocol         = "TCP"
          source           = "0.0.0.0/0"
          source_port      = "ANY"
          direction        = "FORWARD"
          destination      = "10.0.0.0/16"
          destination_port = "443"
        }
        rule_option {
          keyword  = "sid"
          settings = ["1"]
        }
      }
    }
  }
}
```

---

## Example PR Comment Output

```markdown
## 🔎 Terraform AWS Network Firewall Analysis

> **Automated security analysis of AWS Network Firewall Terraform changes.**

### 🚨 Overall Risk Score: 8.3/10 🔴 CRITICAL

---

### 📌 Changes Detected

#### 📄 `modules/network/firewall.tf` — Risk: 8.3/10 🔴 CRITICAL

- 🟡 **[new_resource]** New rule group "example-stateful-rules" added
  - Value: `type=STATEFUL capacity=100`
- 🔴 **[any_source_added]** Rule allows traffic from any source (0.0.0.0/0 or ANY)
  - Value: `0.0.0.0/0`
- 🔴 **[action_changed]** Stateful rule action changed for rule (proto=TCP src=ANY dst=10.0.0.0/16)
  - Before: `DROP`
  - After: `PASS`

---

### 🔐 Security Impact

- **⚠️ Unrestricted Source Traffic:** A rule allows traffic from `0.0.0.0/0` or `ANY`. This exposes the network segment to all internet traffic. Confirm this is intentional and that downstream controls exist (security groups, NACLs).
- **🔀 Rule Action Changed:** A firewall rule's action was modified. Changing from DROP/REJECT to PASS/ALLOW permits previously blocked traffic. Validate that this aligns with the security policy and that the traffic is inspected at another control point.
- **🆕 New Rule Group:** A new `aws_networkfirewall_rule_group` resource was introduced. New rule groups must be reviewed in the context of the complete firewall policy to ensure priority ordering does not conflict with existing rules.

---

### 📋 Reviewer Checklist

- [ ] Confirm that this change was reviewed and approved by a security engineer
- [ ] Verify the change is documented in your change management system (ticket/RFC)
- [ ] Confirm new rule group is attached to the correct firewall policy with correct priority
- [ ] Confirm that allowing traffic from `0.0.0.0/0` is intentional and additional controls exist
- [ ] Confirm the rule action change is aligned with the current threat model and security policy
- [ ] Run `terraform plan` output was reviewed and matches this PR diff
- [ ] Confirm this change has been tested in a non-production environment
- [ ] Ensure firewall rule priorities are correctly ordered (earlier rules take precedence)
- [ ] **HIGH RISK:** Escalate to Security Lead for explicit approval before merging
- [ ] **CRITICAL RISK:** This change requires CISO sign-off before merging

---

_Generated by [firewall-analyzer](https://github.com/firewall-analyzer) GitHub App_
```

---

## Risk Scoring Model

| Condition                        | Risk Contribution |
| -------------------------------- | ----------------- |
| 0.0.0.0/0 or ANY source          | +4.0              |
| Source CIDR widened              | +3.0              |
| Suricata `drop` → `pass`         | +4.0              |
| Stateful rule `DROP` → `PASS`    | +4.0              |
| New stateful PASS rule           | +3.0              |
| FQDN wildcard (`*.domain`) added | +3.0              |
| New rule group                   | +2.0              |
| FQDN entry added                 | +1.5              |
| Suricata `drop` → `alert`        | +2.0              |
| Rule group type changed          | +1.5              |

Raw scores are normalized via `log1p` to a 0–10 scale with diminishing returns at high values.

| Score      | Level       |
| ---------- | ----------- |
| 0.0 – 2.9  | 🟢 LOW      |
| 3.0 – 5.9  | 🟡 MEDIUM   |
| 6.0 – 7.9  | 🟠 HIGH     |
| 8.0 – 10.0 | 🔴 CRITICAL |

---

## Endpoints

| Path       | Method | Description                              |
| ---------- | ------ | ---------------------------------------- |
| `/webhook` | POST   | GitHub App webhook receiver              |
| `/health`  | GET    | Health check (returns `{"status":"ok"}`) |

---

## Security Notes

- Webhook signatures are verified via HMAC-SHA256 before any processing occurs.
- GitHub App JWTs are signed with RS256 using the private key file — the key never leaves the process.
- Installation tokens are cached per-installation and refreshed 5 minutes before expiry.
- All outbound HTTP calls use a 30-second timeout.
- Webhook body is read with a 10MB limit to prevent DoS.
- No global mutable state; all dependencies injected at construction time.

# firewall-analyzer
