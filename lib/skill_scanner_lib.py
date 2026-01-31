#!/usr/bin/env python3
"""
Skill Scanner Library
A library for scanning and analyzing Agent Skills (agentskills.io).

Agent Skills are folder-based capability packages containing:
- SKILL.md file with YAML frontmatter and markdown instructions
- Optional scripts/ directory with executable scripts
- Optional references/ directory with documentation
- Optional assets/ directory with supporting files

Author: Thomas Roccia (@fr0gger_)
Version: 1.0.0
License: MIT
Repository: https://github.com/fr0gger/nova-proximity
"""

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

__version__ = "1.1.0"
__author__ = "Thomas Roccia (@fr0gger_)"

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# Dangerous tool patterns that indicate excessive permissions
DANGEROUS_TOOL_PATTERNS = [
    r"Bash\s*\(\s*\*\s*\)",      # Bash(*)
    r"Bash\s*:\s*\*",            # Bash:*
    r"Write\s*\(\s*\*\s*\)",     # Write(*)
    r"Write\s*:\s*\*",           # Write:*
    r"Edit\s*\(\s*\*\s*\)",      # Edit(*)
    r"Edit\s*:\s*\*",            # Edit:*
    r"Read\s*\(\s*\*\s*\)",      # Read(*)
    r"Read\s*:\s*\*",            # Read:*
    r"Execute\s*\(\s*\*\s*\)",   # Execute(*)
    r"Execute\s*:\s*\*",         # Execute:*
]

# Suspicious patterns in scripts
SUSPICIOUS_SCRIPT_PATTERNS = [
    (r"eval\s*\(", "eval() - Dynamic code execution"),
    (r"exec\s*\(", "exec() - Dynamic code execution"),
    (r"curl\s+[^|]*\|\s*(bash|sh)", "Curl pipe to shell"),
    (r"wget\s+[^|]*\|\s*(bash|sh)", "Wget pipe to shell"),
    (r"os\.environ", "Environment variable access"),
    (r"base64\s+(-d|--decode)", "Base64 decode (potential obfuscation)"),
    (r"subprocess\.(call|run|Popen)", "Subprocess execution"),
    (r"__import__\s*\(", "Dynamic import"),
    (r"socket\.(socket|connect)", "Network socket operations"),
    (r"requests\.(get|post)\s*\([^)]*http", "HTTP requests to external URLs"),
    (r"urllib\.request", "URL fetching"),
    (r"paramiko|fabric|ssh", "SSH/remote execution libraries"),
    (r"\.encode\s*\(\s*['\"]base64['\"]", "Base64 encoding"),
    (r"pickle\.(load|loads)", "Pickle deserialization (security risk)"),
    (r"marshal\.(load|loads)", "Marshal deserialization"),
]

# Pattern-specific remediation for SUSPICIOUS_SCRIPT_PATTERNS
SCRIPT_PATTERN_REMEDIATION = {
    r"eval\s*\(": "Remove eval(). Use ast.literal_eval() for safe literal parsing, or json.loads() for JSON data.",
    r"exec\s*\(": "Remove exec(). Refactor to use specific functions instead of dynamic code execution.",
    r"curl\s+[^|]*\|\s*(bash|sh)": "Never pipe curl to shell. Download file first, verify integrity (checksum), then execute.",
    r"wget\s+[^|]*\|\s*(bash|sh)": "Never pipe wget to shell. Download file first, verify integrity (checksum), then execute.",
    r"os\.environ": "Avoid os.environ in skills. Use skill parameters or config files instead. If env access is required, declare it explicitly.",
    r"base64\s+(-d|--decode)": "Review base64 decode usage. Ensure input is from trusted sources only. Consider using explicit encoding instead.",
    r"subprocess\.(call|run|Popen)": "Subprocess requires Bash permission. Add 'Bash' to allowed-tools or use safer alternatives like specific API calls.",
    r"__import__\s*\(": "Remove dynamic imports. Use explicit import statements for security auditability.",
    r"socket\.(socket|connect)": "Raw sockets require network permission. Consider using higher-level HTTP libraries like requests.",
    r"requests\.(get|post)\s*\([^)]*http": "HTTP requests require WebFetch permission. Add 'WebFetch' to allowed-tools.",
    r"urllib\.request": "URL fetching requires WebFetch permission. Add 'WebFetch' to allowed-tools.",
    r"paramiko|fabric|ssh": "SSH libraries enable remote execution. Ensure this is intended and add appropriate permissions.",
    r"\.encode\s*\(\s*['\"]base64['\"]": "Review base64 encoding. May indicate data exfiltration if sent externally.",
    r"pickle\.(load|loads)": "CRITICAL: Pickle deserialization executes arbitrary code. Use json.loads() or other safe formats instead.",
    r"marshal\.(load|loads)": "CRITICAL: Marshal deserialization is unsafe. Use json.loads() or other safe formats instead.",
}

# Suspicious packages that should be flagged when imported
SUSPICIOUS_PACKAGES = {
    "requests": "HTTP requests library - potential data exfiltration",
    "urllib": "URL handling - potential data exfiltration",
    "urllib3": "HTTP client - potential data exfiltration",
    "socket": "Raw socket operations - network access",
    "paramiko": "SSH library - remote execution",
    "fabric": "SSH automation - remote execution",
    "subprocess": "Command execution",
    "os": "System operations",
    "shutil": "File operations",
    "tempfile": "Temporary file creation",
}

# Package-specific remediation for SUSPICIOUS_PACKAGES
PACKAGE_REMEDIATION = {
    "requests": "HTTP library detected. Add 'WebFetch' to allowed-tools if external API access is intended.",
    "urllib": "URL library detected. Add 'WebFetch' to allowed-tools if external access is needed.",
    "urllib3": "HTTP client detected. Add 'WebFetch' to allowed-tools if external access is needed.",
    "socket": "Raw socket access detected. Add network permissions or use higher-level HTTP libraries.",
    "paramiko": "SSH library enables remote execution. Ensure this is authorized and documented.",
    "fabric": "SSH automation detected. Ensure remote execution is authorized and documented.",
    "subprocess": "Command execution detected. Add 'Bash' to allowed-tools if shell access is intended.",
    "os": "System operations detected. Review for file/process operations and add appropriate permissions.",
    "shutil": "File operations detected. Add 'Write' to allowed-tools if file modification is intended.",
    "tempfile": "Temporary file creation. Generally safe, but review for sensitive data handling.",
}

# Required frontmatter fields for skill validation
REQUIRED_MANIFEST_FIELDS = ["name", "description"]

# Recommended frontmatter fields
RECOMMENDED_MANIFEST_FIELDS = ["author", "version", "license"]

# Mapping of code patterns to required tool permissions
CODE_TO_TOOL_MAP = {
    r"subprocess|os\.system|os\.popen": "Bash",
    r"open\s*\([^)]*['\"][wa]['\"]": "Write",
    r"requests\.(get|post|put|delete)|urllib\.request": "WebFetch",
    r"open\s*\([^)]*['\"]r['\"]": "Read",
}

# Remediation guidance for security flags
REMEDIATION_GUIDANCE = {
    "dangerous_permissions": "Remove wildcard permissions. Use specific tool:action patterns instead of Bash(*) or Write(*). Define minimum required permissions.",
    "suspicious_script": "Review flagged code patterns. Remove eval(), exec(), or use safer alternatives. Avoid dynamic code execution.",
    "env_access": "Avoid accessing environment variables directly in skills. Use configuration files or skill parameters instead.",
    "suspicious_import": "Review the imported package. If network access or system operations are required, ensure they are declared in allowed-tools.",
    "missing_field": "Add the missing required field to the SKILL.md frontmatter for proper skill identification.",
    "recommended_field": "Consider adding this recommended field to improve skill documentation and discoverability.",
    "undeclared_tool": "The code uses capabilities not declared in allowed-tools. Add the required tool to allowed-tools or remove the code.",
}


class SkillScanner:
    """Agent Skills scanner and analyzer."""

    def __init__(self, target_path: str, verbose: bool = False,
                 spinner_callback: Optional[callable] = None,
                 recursive: bool = False):
        """
        Initialize Skill scanner.

        Args:
            target_path: Path to skill directory or parent directory
            verbose: Enable verbose logging
            spinner_callback: Optional callback for spinner updates
            recursive: Scan subdirectories for skills
        """
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML not available. Install with: pip install pyyaml")

        self.target_path = os.path.abspath(target_path)
        self.verbose = verbose
        self.spinner_callback = spinner_callback
        self.recursive = recursive

        self.results = {
            "target": target_path,
            "timestamp": datetime.now().isoformat(),
            "skills": [],
            "total_skills": 0,
            "security_flags": [],
            "errors": []
        }

    def log(self, message: str):
        """Simple logging."""
        if self.spinner_callback:
            self.spinner_callback(f" {message}")
        elif self.verbose:
            print(f"[*] {message}")

    def discover_skills(self) -> List[str]:
        """
        Find all SKILL.md files in target directory.

        Returns:
            List of paths to skill directories containing SKILL.md
        """
        skill_dirs = []
        target = Path(self.target_path)

        if not target.exists():
            self.results["errors"].append(f"Target path does not exist: {self.target_path}")
            return skill_dirs

        # Check if target itself is a skill directory
        skill_md = target / "SKILL.md"
        if skill_md.exists():
            self.log(f"Found skill at: {target}")
            skill_dirs.append(str(target))

        # If recursive, search subdirectories
        if self.recursive:
            self.log(f"Recursively searching for skills in: {target}")
            for skill_md_path in target.rglob("SKILL.md"):
                skill_dir = str(skill_md_path.parent)
                if skill_dir not in skill_dirs:
                    self.log(f"Found skill at: {skill_dir}")
                    skill_dirs.append(skill_dir)

        self.log(f"Discovered {len(skill_dirs)} skill(s)")
        return skill_dirs

    def _parse_yaml_frontmatter(self, content: str) -> tuple[Dict[str, Any], str]:
        """
        Extract YAML frontmatter and body content from SKILL.md.

        Args:
            content: Full SKILL.md file content

        Returns:
            Tuple of (frontmatter dict, body content string)
        """
        frontmatter = {}
        body = content

        # Match YAML frontmatter between --- markers
        frontmatter_pattern = r'^---\s*\n(.*?)\n---\s*\n(.*)$'
        match = re.match(frontmatter_pattern, content, re.DOTALL)

        if match:
            yaml_content = match.group(1)
            body = match.group(2)

            try:
                frontmatter = yaml.safe_load(yaml_content) or {}
            except yaml.YAMLError as e:
                self.log(f"Warning: Failed to parse YAML frontmatter: {e}")
                frontmatter = {"_parse_error": str(e)}

        return frontmatter, body

    def _scan_scripts_directory(self, skill_dir: str) -> List[Dict[str, Any]]:
        """
        Scan scripts/ directory for executable scripts.

        Args:
            skill_dir: Path to skill directory

        Returns:
            List of script info dicts with content and metadata
        """
        scripts = []
        scripts_dir = Path(skill_dir) / "scripts"

        if not scripts_dir.exists():
            return scripts

        for script_path in scripts_dir.iterdir():
            if script_path.is_file():
                try:
                    content = script_path.read_text(encoding='utf-8', errors='replace')
                    lines = content.splitlines()

                    # Check for suspicious patterns with line numbers
                    suspicious_findings = []
                    for i, line in enumerate(lines, 1):
                        for pattern, description in SUSPICIOUS_SCRIPT_PATTERNS:
                            if re.search(pattern, line, re.IGNORECASE):
                                # Use pattern-specific remediation if available, fallback to generic
                                remediation = SCRIPT_PATTERN_REMEDIATION.get(
                                    pattern,
                                    REMEDIATION_GUIDANCE.get("suspicious_script", "")
                                )
                                suspicious_findings.append({
                                    "pattern": description,
                                    "line_number": i,
                                    "line_content": line.strip()[:100],
                                    "severity": "high",
                                    "remediation": remediation
                                })

                    # Extract and analyze imports
                    imports = self._extract_imports(content)
                    suspicious_imports = self._check_suspicious_imports(imports)

                    scripts.append({
                        "name": script_path.name,
                        "path": str(script_path),
                        "size": script_path.stat().st_size,
                        "extension": script_path.suffix,
                        "content": content,
                        "line_count": len(lines),
                        "suspicious_patterns": suspicious_findings,
                        "imports": imports,
                        "suspicious_imports": suspicious_imports
                    })
                except Exception as e:
                    scripts.append({
                        "name": script_path.name,
                        "path": str(script_path),
                        "error": str(e)
                    })

        return scripts

    def _extract_imports(self, content: str) -> List[str]:
        """
        Extract import statements from Python code.

        Args:
            content: Python source code content

        Returns:
            List of imported package names
        """
        imports = []
        import_pattern = r'^(?:from\s+(\S+)|import\s+(\S+))'

        for match in re.finditer(import_pattern, content, re.MULTILINE):
            pkg = match.group(1) or match.group(2)
            if pkg:
                # Get the base package name (before any dots)
                base_pkg = pkg.split('.')[0]
                if base_pkg and base_pkg not in imports:
                    imports.append(base_pkg)

        return imports

    def _check_suspicious_imports(self, imports: List[str]) -> List[Dict[str, Any]]:
        """
        Check imports against suspicious packages list.

        Args:
            imports: List of imported package names

        Returns:
            List of suspicious import findings
        """
        suspicious = []
        for pkg in imports:
            if pkg in SUSPICIOUS_PACKAGES:
                # Use package-specific remediation if available, fallback to generic
                remediation = PACKAGE_REMEDIATION.get(
                    pkg,
                    REMEDIATION_GUIDANCE.get("suspicious_import", "")
                )
                suspicious.append({
                    "package": pkg,
                    "reason": SUSPICIOUS_PACKAGES[pkg],
                    "severity": "medium",
                    "remediation": remediation
                })
        return suspicious

    def _scan_references_directory(self, skill_dir: str) -> List[Dict[str, Any]]:
        """
        Scan references/ directory for documentation files.

        Args:
            skill_dir: Path to skill directory

        Returns:
            List of reference file info dicts
        """
        references = []
        refs_dir = Path(skill_dir) / "references"

        if not refs_dir.exists():
            return references

        # Common text/doc extensions
        text_extensions = {'.md', '.txt', '.rst', '.yaml', '.yml', '.json', '.xml', '.html'}

        for ref_path in refs_dir.rglob("*"):
            if ref_path.is_file():
                try:
                    # Only read text-based files
                    if ref_path.suffix.lower() in text_extensions:
                        content = ref_path.read_text(encoding='utf-8', errors='replace')
                    else:
                        content = f"[Binary file: {ref_path.suffix}]"

                    references.append({
                        "name": ref_path.name,
                        "path": str(ref_path),
                        "relative_path": str(ref_path.relative_to(refs_dir)),
                        "size": ref_path.stat().st_size,
                        "extension": ref_path.suffix,
                        "content": content if len(content) < 100000 else content[:100000] + "\n[TRUNCATED]"
                    })
                except Exception as e:
                    references.append({
                        "name": ref_path.name,
                        "path": str(ref_path),
                        "error": str(e)
                    })

        return references

    def _scan_assets_directory(self, skill_dir: str) -> List[Dict[str, Any]]:
        """
        Scan assets/ directory for supporting files.

        Args:
            skill_dir: Path to skill directory

        Returns:
            List of asset file info dicts (metadata only, no content)
        """
        assets = []
        assets_dir = Path(skill_dir) / "assets"

        if not assets_dir.exists():
            return assets

        for asset_path in assets_dir.rglob("*"):
            if asset_path.is_file():
                assets.append({
                    "name": asset_path.name,
                    "path": str(asset_path),
                    "relative_path": str(asset_path.relative_to(assets_dir)),
                    "size": asset_path.stat().st_size,
                    "extension": asset_path.suffix
                })

        return assets

    def _validate_manifest(self, frontmatter: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Validate manifest has required and recommended fields.

        Args:
            frontmatter: Parsed YAML frontmatter dictionary

        Returns:
            List of validation issues found
        """
        issues = []

        # Check required fields
        for field in REQUIRED_MANIFEST_FIELDS:
            if not frontmatter.get(field):
                issues.append({
                    "type": "missing_field",
                    "severity": "medium",
                    "field": field,
                    "required": True,
                    "remediation": f"Add '{field}' to SKILL.md frontmatter. {REMEDIATION_GUIDANCE.get('missing_field', '')}"
                })

        # Check recommended fields
        for field in RECOMMENDED_MANIFEST_FIELDS:
            if not frontmatter.get(field):
                issues.append({
                    "type": "missing_field",
                    "severity": "low",
                    "field": field,
                    "required": False,
                    "remediation": f"Consider adding '{field}' to improve skill documentation. {REMEDIATION_GUIDANCE.get('recommended_field', '')}"
                })

        return issues

    def _check_undeclared_tools(self, skill_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check if code uses capabilities not declared in allowed-tools.

        Args:
            skill_info: Skill information dictionary

        Returns:
            List of undeclared tool usage findings
        """
        issues = []

        # Get allowed tools
        allowed_tools_analysis = skill_info.get("allowed_tools_analysis", {})
        raw_value = allowed_tools_analysis.get("raw_value", [])

        # Normalize allowed tools to a set
        if isinstance(raw_value, str):
            allowed_set = {raw_value}
        elif isinstance(raw_value, list):
            allowed_set = set(str(t).split('(')[0].split(':')[0].strip() for t in raw_value)
        else:
            allowed_set = set()

        # Check each script for undeclared tool usage
        for script in skill_info.get("scripts", []):
            content = script.get("content", "")
            if not content:
                continue

            for pattern, required_tool in CODE_TO_TOOL_MAP.items():
                if re.search(pattern, content, re.IGNORECASE):
                    # Check if the tool is declared
                    if required_tool not in allowed_set and "*" not in str(raw_value):
                        issues.append({
                            "type": "undeclared_tool",
                            "severity": "high",
                            "source": script["name"],
                            "required_tool": required_tool,
                            "pattern_matched": pattern,
                            "remediation": f"Add '{required_tool}' to allowed-tools or remove the code that requires it. {REMEDIATION_GUIDANCE.get('undeclared_tool', '')}"
                        })

        return issues

    def _analyze_allowed_tools(self, allowed_tools: Any) -> Dict[str, Any]:
        """
        Analyze allowed-tools field for dangerous permissions.

        Args:
            allowed_tools: The allowed-tools field value (string or list)

        Returns:
            Dict with analysis results
        """
        analysis = {
            "raw_value": allowed_tools,
            "tool_count": 0,
            "dangerous_patterns": [],
            "risk_level": "low"
        }

        if not allowed_tools:
            return analysis

        # Convert to list if string
        tools_list = allowed_tools if isinstance(allowed_tools, list) else [str(allowed_tools)]
        analysis["tool_count"] = len(tools_list)

        # Check for dangerous patterns
        tools_str = " ".join(str(t) for t in tools_list)

        for pattern in DANGEROUS_TOOL_PATTERNS:
            if re.search(pattern, tools_str, re.IGNORECASE):
                analysis["dangerous_patterns"].append(pattern)

        # Determine risk level
        if analysis["dangerous_patterns"]:
            analysis["risk_level"] = "critical" if len(analysis["dangerous_patterns"]) > 2 else "high"
        elif analysis["tool_count"] > 10:
            analysis["risk_level"] = "medium"

        return analysis

    def parse_skill(self, skill_dir: str) -> Dict[str, Any]:
        """
        Parse a single skill directory.

        Args:
            skill_dir: Path to skill directory

        Returns:
            Dict containing all skill information
        """
        skill_path = Path(skill_dir)
        skill_md_path = skill_path / "SKILL.md"

        skill_info = {
            "name": skill_path.name,
            "path": str(skill_path),
            "skill_md_exists": skill_md_path.exists(),
            "frontmatter": {},
            "body_content": "",
            "scripts": [],
            "references": [],
            "assets": [],
            "allowed_tools_analysis": {},
            "security_flags": [],
            "manifest_issues": [],
            "parse_errors": []
        }

        if not skill_md_path.exists():
            skill_info["parse_errors"].append("SKILL.md not found")
            return skill_info

        try:
            content = skill_md_path.read_text(encoding='utf-8')
            frontmatter, body = self._parse_yaml_frontmatter(content)

            skill_info["frontmatter"] = frontmatter
            skill_info["body_content"] = body

            # Extract common frontmatter fields
            skill_info["description"] = frontmatter.get("description", "")
            skill_info["name"] = frontmatter.get("name", skill_path.name)
            skill_info["license"] = frontmatter.get("license", "")
            skill_info["compatibility"] = frontmatter.get("compatibility", "")

            # Author and version can be top-level or in metadata (per agentskills.io spec)
            metadata = frontmatter.get("metadata", {})
            skill_info["author"] = frontmatter.get("author", "") or metadata.get("author", "")
            skill_info["version"] = frontmatter.get("version", "") or metadata.get("version", "")

            # Store full metadata for reference
            skill_info["metadata"] = metadata

            # Validate manifest fields
            manifest_issues = self._validate_manifest(frontmatter)
            skill_info["manifest_issues"] = manifest_issues

            # Add security flags for missing required fields
            for issue in manifest_issues:
                if issue.get("required", False):
                    skill_info["security_flags"].append({
                        "type": "missing_field",
                        "severity": issue["severity"],
                        "field": issue["field"],
                        "details": f"Missing required field: {issue['field']}",
                        "remediation": issue["remediation"]
                    })

            # Analyze allowed-tools
            allowed_tools = frontmatter.get("allowed-tools") or frontmatter.get("allowed_tools")
            if allowed_tools:
                skill_info["allowed_tools_analysis"] = self._analyze_allowed_tools(allowed_tools)

                # Add security flag if dangerous patterns found
                if skill_info["allowed_tools_analysis"]["dangerous_patterns"]:
                    skill_info["security_flags"].append({
                        "type": "dangerous_permissions",
                        "severity": skill_info["allowed_tools_analysis"]["risk_level"],
                        "details": f"Dangerous tool patterns: {skill_info['allowed_tools_analysis']['dangerous_patterns']}",
                        "remediation": REMEDIATION_GUIDANCE.get("dangerous_permissions", "")
                    })

        except Exception as e:
            skill_info["parse_errors"].append(f"Failed to parse SKILL.md: {e}")

        # Scan subdirectories
        self.log(f"Scanning scripts directory...")
        skill_info["scripts"] = self._scan_scripts_directory(skill_dir)

        # Add security flags for suspicious scripts (with line numbers)
        for script in skill_info["scripts"]:
            suspicious_patterns = script.get("suspicious_patterns", [])
            if suspicious_patterns:
                for finding in suspicious_patterns:
                    skill_info["security_flags"].append({
                        "type": "suspicious_script",
                        "severity": finding.get("severity", "high"),
                        "source": script["name"],
                        "line_number": finding.get("line_number"),
                        "line_content": finding.get("line_content"),
                        "details": f"Pattern: {finding['pattern']}",
                        "remediation": finding.get("remediation", REMEDIATION_GUIDANCE.get("suspicious_script", ""))
                    })

            # Add security flags for suspicious imports
            suspicious_imports = script.get("suspicious_imports", [])
            for imp in suspicious_imports:
                skill_info["security_flags"].append({
                    "type": "suspicious_import",
                    "severity": imp.get("severity", "medium"),
                    "source": script["name"],
                    "package": imp["package"],
                    "details": f"Suspicious import: {imp['package']} - {imp['reason']}",
                    "remediation": imp.get("remediation", REMEDIATION_GUIDANCE.get("suspicious_import", ""))
                })

        # Check for undeclared tool usage
        undeclared_tools = self._check_undeclared_tools(skill_info)
        for issue in undeclared_tools:
            skill_info["security_flags"].append({
                "type": "undeclared_tool",
                "severity": issue["severity"],
                "source": issue["source"],
                "required_tool": issue["required_tool"],
                "details": f"Code uses {issue['required_tool']} but it's not in allowed-tools",
                "remediation": issue["remediation"]
            })

        self.log(f"Scanning references directory...")
        skill_info["references"] = self._scan_references_directory(skill_dir)

        self.log(f"Scanning assets directory...")
        skill_info["assets"] = self._scan_assets_directory(skill_dir)

        return skill_info

    async def scan(self) -> Dict[str, Any]:
        """
        Main scanning function.

        Returns:
            Dict containing all scan results
        """
        self.log(f"Starting skill scan of {self.target_path}")

        # Discover skills
        skill_dirs = self.discover_skills()

        if not skill_dirs:
            self.results["errors"].append("No skills found in target path")
            return self.results

        # Parse each skill
        for skill_dir in skill_dirs:
            self.log(f"Parsing skill: {skill_dir}")
            skill_info = self.parse_skill(skill_dir)
            self.results["skills"].append(skill_info)

            # Aggregate security flags
            self.results["security_flags"].extend(skill_info.get("security_flags", []))

        self.results["total_skills"] = len(self.results["skills"])
        self.log(f"Scan complete: {self.results['total_skills']} skill(s) analyzed")

        return self.results


async def scan_skills(target_path: str, verbose: bool = False,
                     spinner_callback: Optional[callable] = None,
                     recursive: bool = False) -> Dict[str, Any]:
    """
    Convenience function to scan Agent Skills.

    Args:
        target_path: Path to skill directory or parent directory
        verbose: Enable verbose logging
        spinner_callback: Optional callback for spinner updates
        recursive: Scan subdirectories for skills

    Returns:
        dict: Scan results
    """
    scanner = SkillScanner(
        target_path=target_path,
        verbose=verbose,
        spinner_callback=spinner_callback,
        recursive=recursive
    )
    return await scanner.scan()
