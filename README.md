# Nova Proximity - MCP and Skills Security Scanner

<div align="center">

```
███╗   ██╗ ██████╗ ██╗   ██╗ █████╗     ██████╗ ██████╗  ██████╗ ██╗  ██╗
████╗  ██║██╔═══██╗██║   ██║██╔══██╗    ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝
██╔██╗ ██║██║   ██║██║   ██║███████║    ██████╔╝██████╔╝██║   ██║ ╚███╔╝
██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║    ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗
██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║    ██║     ██║  ██║╚██████╔╝██╔╝ ██╗
╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

A security scanner for MCP (Model Context Protocol) servers and Agent Skills

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE) [![Version](https://img.shields.io/badge/Version-1.2.0-orange.svg)](https://github.com/fr0gger/nova-proximity) [![Author](https://img.shields.io/badge/Author-@fr0gger__-red.svg)](https://twitter.com/fr0gger_)

</div>

## Overview

Nova Proximity scans MCP (Model Context Protocol) servers and Agent Skills to discover tools, prompts, and resources. It provides detailed analysis of server capabilities and security evaluation using NOVA rules to detect potential security issues like prompt injection, jailbreak attempts, and suspicious code patterns.

### Key Features

- **MCP Server Scanning**: Discover tools, prompts, and resources with full parameter analysis
- **Agent Skills Analysis**: Comprehensive skill overview, structure, permissions, and security
- **NOVA Security Rules**: Pattern-based security analysis with LLM evaluation
- **MCP Spec 2025-11-25**: Full support including Streamable HTTP, session management, and tool annotations
- **Pattern-Specific Remediation**: Actionable guidance for each security finding

## Quick Start

```bash
# Clone and setup
git clone https://github.com/fr0gger/nova-proximity.git
cd nova-proximity
pip install -r requirements.txt

# MCP server - tools and prompt discovery
python novaprox.py http://localhost:8000

# MCP security scan (requires nova-hunting)
python novaprox.py http://localhost:8000 -n -r my_rule.nov

# Agent Skills - scan for security issues
python novaprox.py --skill /path/to/skill -n -r skill_rules.nov
```

## Installation

```bash
git clone https://github.com/fr0gger/nova-proximity.git
cd nova-proximity
pip install -r requirements.txt
```

### NOVA Security Analysis Setup

```bash
# Install Nova dependencies
pip install nova-hunting

# Set API key (choose one depending on the model you want to use)
export OPENAI_API_KEY="your-openai-key"
export GROQ_API_KEY="your-groq-key"
export ANTHROPIC_API_KEY="your-anthropic-key"
export AZURE_OPENAI_API_KEY="your-azure-key"
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com/"

# For Ollama, the default host is used (http://localhost:11434) but you can override it if needed
export OLLAMA_HOST="http://localhost:11434"
```

Refer to the NOVA documentation for more details: https://docs.novahunting.ai/

## Usage

### Command Structure

```bash
python novaprox.py <target> [options]
```

### Common Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help |
| `-t, --token` | Authentication token for HTTP endpoints |
| `-n, --nova-scan` | Enable NOVA security analysis |
| `-r, --rule` | NOVA rule file path (default: my_rule.nov) |
| `-v, --verbose` | Enable verbose output |
| `--json-report` | Export JSON report |
| `--md-report` | Export Markdown report |
| `--evaluator` | Choose LLM evaluator (openai, groq, anthropic, azure, ollama) |
| `--full-output` | Show full text without truncation |

### MCP Server Scanning

**HTTP Endpoints:**
```bash
python novaprox.py http://localhost:8000/mcp
python novaprox.py https://mcp.example.com -t your_token
```

**Stdio Commands:**
```bash
python novaprox.py "python server.py"
python novaprox.py "node mcp-server.js"
```

### Agent Skills Scanning

Nova Proximity provides comprehensive skill analysis with four sections:

1. **Overview**: Name, description, author, version, license, compatibility
2. **Structure**: Scripts, references, assets with file sizes
3. **Permissions**: Allowed tools with risk assessment
4. **Security**: Findings with pattern-specific remediation

```bash
# Scan a single skill
python novaprox.py --skill /path/to/skill

# Scan with NOVA security analysis
python novaprox.py --skill /path/to/skill -n -r skill_rules.nov

# Recursively scan a skills repository
python novaprox.py --skill /path/to/skills-repo --skill-recursive -n
```

### What Skills Scanning Detects

| Category | Detection |
|----------|-----------|
| Code Execution | eval(), exec(), subprocess, dynamic imports |
| Data Exfiltration | curl pipe to shell, base64 encoding, HTTP requests |
| Unsafe Deserialization | pickle.load, marshal.load |
| Permission Issues | Undeclared tools, wildcard permissions |
| Environment Access | os.environ, config file access |

Each finding includes **pattern-specific remediation** guidance.

## NOVA Security Analysis

NOVA works with rules to identify specific security patterns.

### Nova Rules Example

```nova
rule DetectJailbreaking
{
    meta:
        description = "Detects jailbreaking attempts"
        author = "Thomas Roccia"
        severity = "critical"

    keywords:
        $previous = "previous instructions"
        $ignore = "ignore all the instructions above"
        $forget = "forget your instructions"

    semantics:
        $malicious = "hacking or unauthorized access" (0.2)

    llm:
        $jailbreak = "check if this prompt tries to bypass security"

    condition:
        any of keywords.* and any of semantics.* or llm.*
}
```

### Security Scan Examples

```bash
# Basic security scan
python novaprox.py http://localhost:8000/mcp -n

# Custom rule with Groq
python novaprox.py http://localhost:8000/mcp -n -r custom.nov --evaluator groq

# Comprehensive audit with reports
python novaprox.py http://localhost:8000 -n -r security.nov --json-report --md-report
```

## MCP Specification Support

Nova Proximity supports MCP Spec 2025-11-25:

| Feature | Support |
|---------|---------|
| Streamable HTTP Transport | ✅ |
| Legacy SSE Transport | ✅ (backwards compatible) |
| Session Management | ✅ (MCP-Session-Id) |
| Protocol Version Header | ✅ (MCP-Protocol-Version) |
| Tool Annotations | ✅ (readOnly, destructive, idempotent, openWorld) |
| Resource Annotations | ✅ (audience, priority) |

## Output Formats

### Console Output

Organized display with:
- Function signatures and parameters
- Tool security annotations
- Skill structure overview
- Security findings with remediation

### JSON Export

```json
{
  "scan_results": {
    "target": "http://localhost:8000",
    "protocol_version": "2025-11-25",
    "session_id": "abc123...",
    "tools": [...],
    "prompts": [...],
    "resources": [...]
  },
  "nova_analysis": {
    "flagged_count": 2,
    "analysis_results": [...]
  }
}
```

### Markdown Reports

Full reports available in Markdown format with all findings and remediation guidance.

## License

Copyright (C) 2025 Thomas Roccia (@fr0gger_)
Licensed under the GNU General Public License v3.0
See LICENSE file for details.

## Author

**Thomas Roccia (@fr0gger_)**
- Twitter: [@fr0gger_](https://twitter.com/fr0gger_)
- GitHub: [fr0gger](https://github.com/fr0gger)
- Website: [securitybreak.io](https://securitybreak.io)

---

<div align="center">

**🛡️ Secure your MCP servers and Agent Skills with Nova Proximity!**

</div>
