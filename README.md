# Bug Bounty Scope Builder API

This backend tool helps generate bug bounty program scopes by retrieving technical data such as subdomains, IPs, mobile apps and API endpoints. It integrates with AI (OpenAI) to provide intelligent recommendations.

---

## 📦 Requirements

Install the following manually before running:

### 🧰 subfinder
Used for finding subdomains.

Install using Go (must be pre-installed):

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
