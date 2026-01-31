#!/usr/bin/env python3
"""
Nova Proximity - MCP and Skills Security Scanner
A security scanner for MCP (Model Context Protocol) servers and Agent Skills with NOVA-powered analysis.

Author: Thomas Roccia (@fr0gger_)
Version: 1.2.0
License: MIT
Repository: https://github.com/fr0gger/nova-proximity

Nova Proximity is a security-focused scanner that provides:
- MCP server discovery and analysis
- Agent Skills (agentskills.io) security scanning
- Tools, prompts, and resources enumeration
- Function signature analysis and documentation
- NOVA-based security evaluation
- Multiple output formats (console, JSON, markdown)
- Support for stdio, SSE, and HTTP transports

Usage:
    python novaprox.py <target> [options]
    python novaprox.py --skill <path> [options]

Examples:
    # Basic MCP scan
    python novaprox.py http://localhost:8000

    # Security scan with Nova rules
    python novaprox.py http://localhost:8000 --nova-scan -r my_rule.nov

    # Scan Agent Skills directory
    python novaprox.py --skill /path/to/skill -n -r skill_rules.nov

    # Recursively scan skills repository
    python novaprox.py --skill /path/to/skills-repo --skill-recursive -n

    # Export detailed reports
    python novaprox.py "python server.py" --json-report --md-report
"""

import argparse
import asyncio
import json
import sys
import os
from datetime import datetime
from typing import Optional

from lib.mcp_scanner_lib import scan_mcp_server
from lib.skill_scanner_lib import scan_skills, YAML_AVAILABLE
from lib.nova_evaluator_lib import NovaEvaluator, MCPNovaAnalyzer, SkillNovaAnalyzer, NOVA_AVAILABLE
from yaspin import yaspin

TOOL_NAME = "Nova Proximity"
TOOL_VERSION = "1.2.0"
TOOL_AUTHOR = "Thomas Roccia (@fr0gger_)"
TOOL_DESCRIPTION = "MCP and Skills Security Scanner"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class ProximityReporter:
    """Reporter for generating output reports."""

    def __init__(self, results: dict, nova_analysis: Optional[dict] = None,
                 scan_mode: str = "mcp", full_output: bool = False):
        self.results = results
        self.nova_analysis = nova_analysis
        self.scan_mode = scan_mode  # "mcp" or "skill"
        self.full_output = full_output
    
    def display_console_report(self):
        """Display a nice terminal report."""
        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        print(f"{BOLD}{GREEN} {TOOL_NAME} v{TOOL_VERSION} - {TOOL_DESCRIPTION}{RESET}")
        print(f"{BOLD}{CYAN}{'='*60}{RESET}")

        print(f"{CYAN}Target:{RESET} {self.results['target']}")
        scan_time = self.results['timestamp'][:19].replace('T', ' ')
        print(f"{CYAN}Scan Time:{RESET} {scan_time}")
        # MCP Protocol Version (MCP Spec 2025-11-25)
        if self.results.get('protocol_version'):
            print(f"{CYAN}Protocol Version:{RESET} {self.results['protocol_version']}")
        print(f"{CYAN}Endpoints:{RESET} {len(self.results['endpoints'])}")
        transport_types = ', '.join(self.results['transport_types'])
        print(f"{CYAN}Transport Types:{RESET} {transport_types}")
        # Session ID (MCP Spec 2025-11-25)
        if self.results.get('session_id'):
            session_display = self.results['session_id'][:24] + "..." if len(self.results['session_id']) > 24 else self.results['session_id']
            print(f"{CYAN}Session ID:{RESET} {session_display}")

        caps = self.results["capabilities"]
        print(f"\n{BOLD}{YELLOW}[CONFIG] Server Capabilities:{RESET}")
        tools_status = f"{GREEN}[+] YES{RESET}" if caps.get('tools') else f"{RED}[-] NO{RESET}"
        prompts_status = f"{GREEN}[+] YES{RESET}" if caps.get('prompts') else f"{RED}[-] NO{RESET}"
        resources_status = f"{GREEN}[+] YES{RESET}" if caps.get('resources') else f"{RED}[-] NO{RESET}"

        print(f"  {CYAN}Tools:{RESET} {tools_status}")
        print(f"  {CYAN}Prompts:{RESET} {prompts_status}")
        print(f"  {CYAN}Resources:{RESET} {resources_status}")

        if self.results["tools"]:
            tool_count = len(self.results['tools'])
            print(f"\n{BOLD}{BLUE}[TOOLS] Tools Discovered ({tool_count}){RESET}")
            print(f"{BLUE}{'-' * 50}{RESET}")
            for i, tool in enumerate(self.results["tools"], 1):
                param_count = len(tool["parameters"])
                required_count = len([p for p in tool["parameters"]
                                     if p["required"]])

                print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{tool['name']}{RESET}")
                if tool.get("title"):  # MCP Spec 2025-11-25
                    print(f"   {CYAN}Title:{RESET} {tool['title']}")
                print(f"   {CYAN}Description:{RESET} {tool['description']}")
                print(f"   {CYAN}Parameters:{RESET} {param_count} total "
                      f"({required_count} required)")
                complexity = tool['complexity'].title()
                if complexity == "Simple":
                    complexity_color = GREEN
                elif complexity == "Moderate":
                    complexity_color = YELLOW
                else:
                    complexity_color = RED
                print(f"   {CYAN}Complexity:{RESET} {complexity_color}{complexity}{RESET}")

                if tool["parameters"]:
                    print(f"   {CYAN}Function Parameters:{RESET}")
                    for param in tool["parameters"]:
                        marker = f"{RED}*{RESET}" if param["required"] else " "
                        print(f"     {marker} {BOLD}{param['name']}{RESET}: "
                              f"{param['type']}")
                        if param['description'] != "No description":
                            print(f"       {CYAN}Description:{RESET} "
                                  f"{param['description']}")

                    print(f"   {CYAN}Function Signature:{RESET} "
                          f"{BOLD}{tool['function_signature']}{RESET}")

                # Display security annotations if present (MCP Spec 2025-11-25)
                if tool.get("annotations"):
                    annotations = tool["annotations"]
                    hints = []
                    if annotations.get("readOnlyHint"):
                        hints.append(f"{GREEN}read-only{RESET}")
                    if annotations.get("destructiveHint"):
                        hints.append(f"{RED}destructive{RESET}")
                    if not annotations.get("idempotentHint"):
                        hints.append(f"{YELLOW}non-idempotent{RESET}")
                    if annotations.get("openWorldHint"):
                        hints.append(f"{CYAN}external-access{RESET}")
                    if hints:
                        print(f"   {CYAN}Security Hints:{RESET} {', '.join(hints)}")

                    if tool["example_usage"]:
                        print(f"   {CYAN}Example Usage:{RESET}")
                        for param, value in tool["example_usage"].items():
                            print(f"     {param}: \"{value}\"")

        if self.results["prompts"]:
            prompt_count = len(self.results['prompts'])
            print(f"\n{BOLD}{BLUE}[PROMPTS] Prompts Discovered ({prompt_count}){RESET}")
            print(f"{BLUE}{'-' * 50}{RESET}")
            for i, prompt in enumerate(self.results["prompts"], 1):
                arg_count = len(prompt["arguments"])
                required_count = len([a for a in prompt["arguments"]
                                     if a["required"]])

                print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{prompt['name']}{RESET}")
                if prompt.get("title"):  # MCP Spec 2025-11-25
                    print(f"   {CYAN}Title:{RESET} {prompt['title']}")
                print(f"   {CYAN}Description:{RESET} {prompt['description']}")
                print(f"   {CYAN}Arguments:{RESET} {arg_count} total "
                      f"({required_count} required)")

                if prompt["arguments"]:
                    print(f"   {CYAN}Parameters:{RESET}")
                    for arg in prompt["arguments"]:
                        marker = f"{RED}*{RESET}" if arg["required"] else " "
                        print(f"     {marker} {BOLD}{arg['name']}{RESET}: "
                              f"{arg['description']}")

                #full prompt content
                if (prompt["full_content"] and
                        prompt["full_content"]["messages"]):
                    print(f"   {CYAN}Full Prompt Content:{RESET}")
                    for msg_idx, msg in enumerate(
                            prompt["full_content"]["messages"], 1):
                        role = msg.get("role", "unknown")
                        print(f"     {YELLOW}Message {msg_idx} ({role}):{RESET}")

                        for content_item in msg.get("content", []):
                            if content_item["type"] == "text":
                                text = content_item["text"]
                                # Show first 3 lines for console
                                lines = text.split('\n')[:3]
                                for line in lines:
                                    print(f"       {line}")
                                if len(text.split('\n')) > 3:
                                    remaining_lines = (len(text.split('\n'))
                                                      - 3)
                                    print(f"       {YELLOW}... ({remaining_lines} "
                                          f"more lines){RESET}")

        if self.results["resources"]:
            resource_count = len(self.results['resources'])
            print(f"\n{BOLD}{BLUE}[RESOURCES] Resources Discovered ({resource_count}){RESET}")
            print(f"{BLUE}{'-' * 50}{RESET}")
            for i, resource in enumerate(self.results["resources"], 1):
                print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{resource['uri']}{RESET}")
                if resource.get("name"):
                    print(f"   {CYAN}Name:{RESET} {resource['name']}")
                if resource.get("title"):  # MCP Spec 2025-11-25
                    print(f"   {CYAN}Title:{RESET} {resource['title']}")
                if resource.get("description") and resource["description"] != "No description":
                    print(f"   {CYAN}Description:{RESET} {resource['description']}")
                if resource.get("mime_type"):
                    print(f"   {CYAN}MIME Type:{RESET} {resource['mime_type']}")
                if resource.get("size"):  # MCP Spec 2025-11-25
                    print(f"   {CYAN}Size:{RESET} {resource['size']} bytes")
                # Display resource annotations if present (MCP Spec 2025-11-25)
                if resource.get("annotations"):
                    annotations = resource["annotations"]
                    if annotations.get("audience"):
                        print(f"   {CYAN}Audience:{RESET} {', '.join(annotations['audience'])}")
                    if annotations.get("priority") is not None:
                        print(f"   {CYAN}Priority:{RESET} {annotations['priority']}")

        if self.nova_analysis:
            self._display_nova_analysis()

        if self.results["errors"]:
            error_count = len(self.results['errors'])
            print(f"\n{BOLD}{RED}[ERROR] Errors Encountered ({error_count}){RESET}")
            print(f"{RED}{'-' * 50}{RESET}")
            for i, error in enumerate(self.results["errors"], 1):
                print(f"   {YELLOW}[{i}]{RESET} {RED}{error}{RESET}")

        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        summary_parts = []
        if self.results["tools"]:
            summary_parts.append(f"{len(self.results['tools'])} tools")
        if self.results["prompts"]:
            summary_parts.append(f"{len(self.results['prompts'])} prompts")
        if self.results["resources"]:
            summary_parts.append(f"{len(self.results['resources'])} "
                                "resources")

        summary = (", ".join(summary_parts) if summary_parts
                   else "No capabilities")
        print(f"{BOLD}{GREEN}[SUMMARY]{RESET} Discovery: {GREEN}{summary}{RESET}")

        if self.nova_analysis:
            flagged = self.nova_analysis["flagged_count"]
            total = self.nova_analysis["total_texts_analyzed"]
            rule_count = self.nova_analysis["rule_info"]["rule_count"]
            
            # Unique rules that matched
            matched_rules_set = set()
            for result in self.nova_analysis["analysis_results"]:
                if result["nova_evaluation"].get("matched", False):
                    matched_rules = result["nova_evaluation"].get("matched_rules", [])
                    primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")
                    if matched_rules:
                        matched_rules_set.update(matched_rules)
                    else:
                        matched_rules_set.add(primary_rule)
            
            matched_rule_count = len(matched_rules_set)
            
            print(f"{BOLD}{GREEN}[SECURITY]{RESET} Analysis: {flagged}/{total} items flagged")
            if matched_rule_count > 0:
                print(f"{BOLD}{GREEN}[NOVA]{RESET} {matched_rule_count} rule{'s' if matched_rule_count > 1 else ''} matched")

        print(f"{BOLD}{CYAN}{'='*60}{RESET}")

    def display_skill_report(self):
        """Display a nice terminal report for skill scan results."""
        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        print(f"{BOLD}{GREEN} {TOOL_NAME} v{TOOL_VERSION} - Skills Scanner{RESET}")
        print(f"{BOLD}{CYAN}{'='*60}{RESET}")

        print(f"{CYAN}Target:{RESET} {self.results['target']}")
        scan_time = self.results['timestamp'][:19].replace('T', ' ')
        print(f"{CYAN}Scan Time:{RESET} {scan_time}")
        print(f"{CYAN}Skills Found:{RESET} {self.results['total_skills']}")

        # Display each skill
        for i, skill in enumerate(self.results.get("skills", []), 1):
            print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
            print(f"{BOLD}{BLUE}[SKILL {i}] {skill['name']}{RESET}")
            print(f"{BOLD}{BLUE}{'='*60}{RESET}")

            # ═══════════════════════════════════════════════════════════
            # SECTION 1: SKILL OVERVIEW
            # ═══════════════════════════════════════════════════════════
            print(f"\n{BOLD}{CYAN}[OVERVIEW] Skill Information{RESET}")
            print(f"{CYAN}{'-' * 50}{RESET}")

            # Description (full, formatted)
            if skill.get("description"):
                desc = skill.get('description', '')
                if len(desc) > 500 and not self.full_output:
                    desc = desc[:500] + f"... [+{len(skill['description'])-500}]"
                print(f"   {CYAN}Description:{RESET}")
                # Word wrap description for readability
                import textwrap
                wrapped = textwrap.fill(desc, width=55, initial_indent="      ", subsequent_indent="      ")
                print(wrapped)

            # Metadata section
            print(f"\n   {CYAN}Metadata:{RESET}")
            if skill.get("author"):
                print(f"      Author: {skill['author']}")
            else:
                print(f"      Author: {YELLOW}Not specified{RESET}")

            if skill.get("version"):
                print(f"      Version: {skill['version']}")
            else:
                print(f"      Version: {YELLOW}Not specified{RESET}")

            if skill.get("license"):
                print(f"      License: {skill['license']}")
            else:
                print(f"      License: {YELLOW}Not specified{RESET}")

            if skill.get("compatibility"):
                print(f"      Compatibility: {skill['compatibility']}")

            # ═══════════════════════════════════════════════════════════
            # SECTION 2: SKILL STRUCTURE
            # ═══════════════════════════════════════════════════════════
            print(f"\n{BOLD}{CYAN}[STRUCTURE] Skill Contents{RESET}")
            print(f"{CYAN}{'-' * 50}{RESET}")

            # Scripts
            scripts = skill.get("scripts", [])
            if scripts:
                suspicious_count = sum(1 for s in scripts if s.get("suspicious_patterns"))
                print(f"   {CYAN}📜 Scripts:{RESET} {len(scripts)} file(s)")
                for script in scripts:
                    status_icon = f"{RED}⚠{RESET}" if script.get("suspicious_patterns") else f"{GREEN}✓{RESET}"
                    size_kb = script.get("size", 0) / 1024
                    print(f"      {status_icon} {script['name']} ({size_kb:.1f} KB, {script.get('line_count', 0)} lines)")
            else:
                print(f"   {CYAN}📜 Scripts:{RESET} None")

            # References
            refs = skill.get("references", [])
            if refs:
                print(f"   {CYAN}📚 References:{RESET} {len(refs)} file(s)")
                for ref in refs[:5]:  # Show first 5
                    size_kb = ref.get("size", 0) / 1024
                    print(f"      • {ref.get('relative_path', ref['name'])} ({size_kb:.1f} KB)")
                if len(refs) > 5:
                    print(f"      ... and {len(refs) - 5} more")
            else:
                print(f"   {CYAN}📚 References:{RESET} None")

            # Assets
            assets = skill.get("assets", [])
            if assets:
                print(f"   {CYAN}📦 Assets:{RESET} {len(assets)} file(s)")
                for asset in assets[:5]:  # Show first 5
                    size_kb = asset.get("size", 0) / 1024
                    print(f"      • {asset.get('relative_path', asset['name'])} ({size_kb:.1f} KB)")
                if len(assets) > 5:
                    print(f"      ... and {len(assets) - 5} more")
            else:
                print(f"   {CYAN}📦 Assets:{RESET} None")

            # ═══════════════════════════════════════════════════════════
            # SECTION 3: PERMISSIONS
            # ═══════════════════════════════════════════════════════════
            tools_analysis = skill.get("allowed_tools_analysis", {})
            raw_tools = tools_analysis.get("raw_value", [])

            print(f"\n{BOLD}{CYAN}[PERMISSIONS] Allowed Tools{RESET}")
            print(f"{CYAN}{'-' * 50}{RESET}")

            if tools_analysis and tools_analysis.get("tool_count", 0) > 0:
                risk_level = tools_analysis.get("risk_level", "low")
                if risk_level == "critical":
                    risk_color = RED
                    risk_icon = "🔴"
                elif risk_level == "high":
                    risk_color = RED
                    risk_icon = "🟠"
                elif risk_level == "medium":
                    risk_color = YELLOW
                    risk_icon = "🟡"
                else:
                    risk_color = GREEN
                    risk_icon = "🟢"

                print(f"   {CYAN}Tool Count:{RESET} {tools_analysis['tool_count']}")
                print(f"   {CYAN}Risk Level:{RESET} {risk_icon} {risk_color}{risk_level.upper()}{RESET}")

                # Show actual tools
                if isinstance(raw_tools, list):
                    print(f"   {CYAN}Declared Tools:{RESET}")
                    for tool in raw_tools:
                        # Check if this is a dangerous pattern
                        dangerous = any(p in str(tool) for p in ['*', 'Bash(*)', 'Write(*)', 'Edit(*)'])
                        icon = f"{RED}⚠{RESET}" if dangerous else f"{GREEN}✓{RESET}"
                        print(f"      {icon} {tool}")
                elif raw_tools:
                    print(f"   {CYAN}Declared Tools:{RESET} {raw_tools}")

                if tools_analysis.get("dangerous_patterns"):
                    print(f"   {RED}Dangerous Patterns:{RESET} {', '.join(tools_analysis['dangerous_patterns'])}")
            else:
                print(f"   {CYAN}Allowed Tools:{RESET} {YELLOW}None declared{RESET}")
                print(f"   {YELLOW}Note: Skills without declared tools may request permissions at runtime{RESET}")

            # ═══════════════════════════════════════════════════════════
            # SECTION 4: SECURITY ANALYSIS
            # ═══════════════════════════════════════════════════════════
            security_flags = skill.get("security_flags", [])
            print(f"\n{BOLD}{RED if security_flags else GREEN}[SECURITY] Security Analysis{RESET}")
            print(f"{RED if security_flags else GREEN}{'-' * 50}{RESET}")

            if security_flags:
                # Group by severity
                critical_high = [f for f in security_flags if f.get("severity") in ["critical", "high"]]
                medium = [f for f in security_flags if f.get("severity") == "medium"]
                low = [f for f in security_flags if f.get("severity") == "low"]

                print(f"   {CYAN}Total Flags:{RESET} {len(security_flags)}")
                print(f"      {RED}Critical/High:{RESET} {len(critical_high)}")
                print(f"      {YELLOW}Medium:{RESET} {len(medium)}")
                print(f"      {GREEN}Low:{RESET} {len(low)}")

                print(f"\n   {BOLD}{RED}Security Findings:{RESET}")
                for flag in security_flags:
                    severity = flag.get("severity", "unknown")
                    if severity in ["critical", "high"]:
                        sev_color = RED
                        sev_icon = "🔴"
                    elif severity == "medium":
                        sev_color = YELLOW
                        sev_icon = "🟡"
                    else:
                        sev_color = GREEN
                        sev_icon = "🟢"

                    print(f"\n      {sev_icon} {sev_color}[{severity.upper()}]{RESET} {flag['type']}")

                    if flag.get("source"):
                        source_info = flag['source']
                        if flag.get("line_number"):
                            source_info += f":{flag['line_number']}"
                        print(f"         📍 Source: {source_info}")

                    if flag.get("line_content"):
                        line_content = flag.get('line_content', '')
                        if len(line_content) > 120 and not self.full_output:
                            line_content = line_content[:120] + f"... [+{len(flag['line_content'])-120}]"
                        print(f"         📝 Code: {CYAN}{line_content}{RESET}")

                    if flag.get("package"):
                        print(f"         📦 Package: {flag['package']}")

                    if flag.get("required_tool"):
                        print(f"         🔧 Required Tool: {flag['required_tool']}")

                    if flag.get("details"):
                        details = flag.get('details', '')
                        if len(details) > 150 and not self.full_output:
                            details = details[:150] + f"... [+{len(flag['details'])-150}]"
                        print(f"         ℹ️  Details: {details}")

                    if flag.get("remediation"):
                        print(f"         {GREEN}✅ Remediation:{RESET} {flag['remediation']}")
            else:
                print(f"   {GREEN}✅ No security issues detected{RESET}")

            # Parse errors
            parse_errors = skill.get("parse_errors", [])
            if parse_errors:
                print(f"\n   {BOLD}{YELLOW}[!] Parse Errors:{RESET}")
                for error in parse_errors:
                    print(f"      ⚠️  {YELLOW}{error}{RESET}")

        # Display Nova analysis if available
        if self.nova_analysis:
            self._display_nova_analysis()

        # Display errors
        if self.results.get("errors"):
            error_count = len(self.results['errors'])
            print(f"\n{BOLD}{RED}[ERROR] Errors Encountered ({error_count}){RESET}")
            print(f"{RED}{'-' * 50}{RESET}")
            for i, error in enumerate(self.results["errors"], 1):
                print(f"   {YELLOW}[{i}]{RESET} {RED}{error}{RESET}")

        # Summary
        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        total_skills = self.results["total_skills"]
        total_flags = len(self.results.get("security_flags", []))

        print(f"{BOLD}{GREEN}[SUMMARY]{RESET} Skills: {GREEN}{total_skills}{RESET}, "
              f"Security Flags: {RED if total_flags > 0 else GREEN}{total_flags}{RESET}")

        if self.nova_analysis:
            flagged = self.nova_analysis["flagged_count"]
            total = self.nova_analysis["total_texts_analyzed"]

            matched_rules_set = set()
            for result in self.nova_analysis["analysis_results"]:
                if result["nova_evaluation"].get("matched", False):
                    matched_rules = result["nova_evaluation"].get("matched_rules", [])
                    primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")
                    if matched_rules:
                        matched_rules_set.update(matched_rules)
                    else:
                        matched_rules_set.add(primary_rule)

            matched_rule_count = len(matched_rules_set)

            print(f"{BOLD}{GREEN}[NOVA]{RESET} Analysis: {flagged}/{total} items flagged")
            if matched_rule_count > 0:
                print(f"{BOLD}{GREEN}[NOVA]{RESET} {matched_rule_count} rule{'s' if matched_rule_count > 1 else ''} matched")

        print(f"{BOLD}{CYAN}{'='*60}{RESET}")

    def _display_nova_analysis(self):
        """Display Nova security analysis results."""
        print(f"\n{BOLD}{GREEN}[NOVA] NOVA Analysis Results{RESET}")
        print(f"{GREEN}{'-' * 50}{RESET}")

        rule_info = self.nova_analysis["rule_info"]
        
        if rule_info['rule_count'] > 1:
            rules_str = ', '.join(rule_info['rule_names'])
            print(f"{CYAN}Rules:{RESET} {rules_str} ({rule_info['rule_count']} total)")
        else:
            print(f"{CYAN}Rule:{RESET} {rule_info['name']}")
        
        print(f"{CYAN}Evaluator:{RESET} {rule_info['evaluator_type']}")
        total_analyzed = self.nova_analysis['total_texts_analyzed']
        print(f"{CYAN}Total Items Analyzed:{RESET} {total_analyzed}")
        print(f"{CYAN}Flagged Items:{RESET} {self.nova_analysis['flagged_count']}")

        if self.nova_analysis["flagged_count"] > 0:
            print(f"\n{BOLD}{RED}[!] Security Alerts:{RESET}")
            
            alerts_by_rule = {}
            for result in self.nova_analysis["analysis_results"]:
                if result["nova_evaluation"].get("matched", False):

                    matched_rules = result["nova_evaluation"].get("matched_rules", [])
                    primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")
                    
                    if not matched_rules:
                        matched_rules = [primary_rule]
                    
                    # Add this result to each rule it matches
                    for rule_name in matched_rules:
                        if rule_name not in alerts_by_rule:
                            alerts_by_rule[rule_name] = []
                        alerts_by_rule[rule_name].append(result)
            
            # alerts grouped by rule
            for rule_name, alerts in alerts_by_rule.items():
                print(f"\n{BOLD}{RED}▌ Rule: {rule_name} ({len(alerts)} alert{'s' if len(alerts) > 1 else ''}){RESET}")
                print(f"{RED}{'─' * 50}{RESET}")
                
                for i, result in enumerate(alerts, 1):
                    nova_result = result["nova_evaluation"]
                    
                    print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{result['source']}{RESET}")
                    print(f"    {CYAN}Type:{RESET} {result['type']}")
                    print(f"    {CYAN}Content:{RESET} {result['text_preview']}")
                    
                    # matched keywords specific to this rule
                    per_rule_keywords = nova_result.get("per_rule_keywords", {})
                    
                    # keywords for the current rule displaying
                    if per_rule_keywords and rule_name in per_rule_keywords:
                        keywords_to_show = per_rule_keywords[rule_name]
                    else:
                        keywords_to_show = nova_result.get("matching_keywords", {})
                    
                    if keywords_to_show:
                        if isinstance(keywords_to_show, dict):
                            keyword_list = [f"'{k}'" for k, v in keywords_to_show.items() if v]
                        else:
                            keyword_list = [str(keywords_to_show)]
                        
                        if keyword_list:
                            keywords_str = ", ".join(keyword_list)
                            print(f"    {CYAN}Triggered Keywords:{RESET} {keywords_str}")
                    
                    matched_rules = nova_result.get("matched_rules", [])
                    if matched_rules and len(matched_rules) > 1:
                        other_rules = [r for r in matched_rules if r != rule_name]
                        if other_rules:
                            print(f"    {CYAN}Also Matches:{RESET} {', '.join(other_rules)}")
        else:
            print(f"\n{GREEN}[+] No security issues detected!{RESET}")
    
    def export_json_report(self, filename: str):
        """Export detailed JSON report."""
        report = {
            "scan_results": self.results,
            "nova_analysis": self.nova_analysis,
            "export_timestamp": datetime.now().isoformat()
        }
        
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"{GREEN}[+] JSON report exported to: {filename}{RESET}")

    def export_markdown_report(self, filename: str):
        """Export markdown report."""
        md_content = []

        # Header
        header = f"# {TOOL_NAME} v{TOOL_VERSION} - MCP Scan Report\n\n"
        md_content.append(header)
        md_content.append(f"**Target:** {self.results['target']}\n")
        md_content.append(f"**Scan Date:** {self.results['timestamp']}\n")
        if self.results.get('protocol_version'):
            md_content.append(f"**Protocol Version:** {self.results['protocol_version']}\n")
        md_content.append(f"**Endpoints:** {len(self.results['endpoints'])}\n")
        transport_types = ', '.join(self.results['transport_types'])
        md_content.append(f"**Transport Types:** {transport_types}\n")
        if self.results.get('session_id'):
            md_content.append(f"**Session ID:** {self.results['session_id']}\n")
        md_content.append("\n")

        # Capabilities
        caps = self.results["capabilities"]
        md_content.append("## Server Capabilities\n\n")
        tools_status = '✅ Available' if caps.get('tools') else '❌ Not Available'
        prompts_status = ('✅ Available' if caps.get('prompts')
                         else '❌ Not Available')
        resources_status = ('✅ Available' if caps.get('resources')
                           else '❌ Not Available')
        md_content.append(f"- **Tools:** {tools_status}\n")
        md_content.append(f"- **Prompts:** {prompts_status}\n")
        md_content.append(f"- **Resources:** {resources_status}\n\n")
        
        # Tools
        if self.results["tools"]:
            tool_count = len(self.results['tools'])
            md_content.append(f"## Tools Analysis ({tool_count} found)\n\n")
            for tool in self.results["tools"]:
                md_content.append(f"### {tool['name']}\n\n")
                md_content.append(f"**Description:** {tool['description']}\n\n")
                complexity = tool['complexity'].title()
                md_content.append(f"**Complexity:** {complexity}\n")
                param_count = len(tool['parameters'])
                md_content.append(f"**Parameters:** {param_count} total\n\n")

                if tool["parameters"]:
                    md_content.append("**Function Parameters:**\n")
                    for param in tool["parameters"]:
                        status = "Required" if param["required"] else "Optional"
                        param_desc = param['description']
                        md_content.append(f"- `{param['name']}` "
                                        f"({param['type']}, {status}): "
                                        f"{param_desc}\n")
                    md_content.append("\n")
                    signature = tool['function_signature']
                    md_content.append(f"**Function Signature:**\n"
                                    f"```\n{signature}\n```\n\n")

        # Prompts
        if self.results["prompts"]:
            prompt_count = len(self.results['prompts'])
            md_content.append(f"## Prompts Analysis ({prompt_count} found)\n\n")
            for prompt in self.results["prompts"]:
                md_content.append(f"### {prompt['name']}\n\n")
                md_content.append(f"**Description:** {prompt['description']}\n\n")

                if prompt["arguments"]:
                    md_content.append("**Arguments:**\n")
                    for arg in prompt["arguments"]:
                        status = "Required" if arg["required"] else "Optional"
                        md_content.append(f"- `{arg['name']}` ({status}): "
                                        f"{arg['description']}\n")
                    md_content.append("\n")

                if (prompt["full_content"] and
                        prompt["full_content"]["messages"]):
                    md_content.append("**Full Prompt Content:**\n")
                    for msg_idx, msg in enumerate(
                            prompt["full_content"]["messages"], 1):
                        role = msg.get("role", "unknown")
                        md_content.append(f"**Message {msg_idx} ({role}):**\n")
                        for content_item in msg.get("content", []):
                            if content_item["type"] == "text":
                                text = content_item['text']
                                md_content.append(f"```\n{text}\n```\n\n")

        # Resources
        if self.results["resources"]:
            resource_count = len(self.results['resources'])
            md_content.append(f"## Resources Analysis "
                            f"({resource_count} found)\n\n")
            for resource in self.results["resources"]:
                md_content.append(f"### {resource['uri']}\n\n")
                if resource["name"]:
                    md_content.append(f"**Name:** {resource['name']}\n")
                md_content.append(f"**Description:** "
                                f"{resource['description']}\n")
                if resource["mime_type"]:
                    md_content.append(f"**MIME Type:** "
                                    f"{resource['mime_type']}\n")
                md_content.append("\n")

        # Nova analysis
        if self.nova_analysis:
            md_content.append("## Security Analysis\n\n")
            rule_info = self.nova_analysis["rule_info"]
            
            # Show all rules if multiple rules are loaded
            if rule_info['rule_count'] > 1:
                rules_str = ', '.join(rule_info['rule_names'])
                md_content.append(f"**Rules:** {rules_str} ({rule_info['rule_count']} total)\n")
            else:
                md_content.append(f"**Rule:** {rule_info['name']}\n")
            
            md_content.append(f"**Evaluator:** "
                            f"{rule_info['evaluator_type']}\n")
            total_analyzed = self.nova_analysis['total_texts_analyzed']
            md_content.append(f"**Items Analyzed:** {total_analyzed}\n")
            flagged_count = self.nova_analysis['flagged_count']
            md_content.append(f"**Flagged Items:** {flagged_count}\n\n")

            if self.nova_analysis["flagged_count"] > 0:
                md_content.append("### Security Alerts\n\n")
                
                alerts_by_rule = {}
                for result in self.nova_analysis["analysis_results"]:
                    if result["nova_evaluation"].get("matched", False):
                        matched_rules = result["nova_evaluation"].get("matched_rules", [])
                        primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")
                        
                        if not matched_rules:
                            matched_rules = [primary_rule]
                        
                        for rule_name in matched_rules:
                            if rule_name not in alerts_by_rule:
                                alerts_by_rule[rule_name] = []
                            alerts_by_rule[rule_name].append(result)
                
                for rule_name, alerts in alerts_by_rule.items():
                    alert_count = len(alerts)
                    md_content.append(f"#### Rule: {rule_name} ({alert_count} alert{'s' if alert_count > 1 else ''})\n\n")
                    
                    for i, result in enumerate(alerts, 1):
                        nova_result = result["nova_evaluation"]
                        
                        md_content.append(f"**[{i}] {result['source']}**\n\n")
                        md_content.append(f"- **Type:** {result['type']}\n")
                        md_content.append(f"- **Content:** {result['text_preview']}\n")
                        
                        per_rule_keywords = nova_result.get("per_rule_keywords", {})
                        
                        if per_rule_keywords and rule_name in per_rule_keywords:
                            keywords_to_show = per_rule_keywords[rule_name]
                        else:
                            keywords_to_show = nova_result.get("matching_keywords", {})
                        
                        if keywords_to_show:
                            if isinstance(keywords_to_show, dict):
                                keyword_list = [f"'{k}'" for k, v in keywords_to_show.items() if v]
                            else:
                                keyword_list = [str(keywords_to_show)]
                            
                            if keyword_list:
                                keywords_str = ", ".join(keyword_list)
                                md_content.append(f"- **Triggered Keywords:** {keywords_str}\n")
                        
                        # Show additional matched rules if multiple rules matched
                        matched_rules = nova_result.get("matched_rules", [])
                        if matched_rules and len(matched_rules) > 1:
                            other_rules = [r for r in matched_rules if r != rule_name]
                            if other_rules:
                                md_content.append(f"- **Also Matches:** {', '.join(other_rules)}\n")
                        
                        md_content.append("\n")

        # Errors
        if self.results["errors"]:
            md_content.append("## Errors\n\n")
            for error in self.results["errors"]:
                md_content.append(f"- {error}\n")
            md_content.append("\n")

        # Write to file
        with open(filename, "w") as f:
            f.write("".join(md_content))

        print(f"{GREEN}[+] Markdown report exported to: {filename}{RESET}")

    def export_skill_json_report(self, filename: str):
        """Export detailed JSON report for skill scan."""
        report = {
            "scan_type": "skill",
            "scan_results": self.results,
            "nova_analysis": self.nova_analysis,
            "export_timestamp": datetime.now().isoformat()
        }

        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"{GREEN}[+] JSON report exported to: {filename}{RESET}")

    def export_skill_markdown_report(self, filename: str):
        """Export markdown report for skill scan."""
        md_content = []

        # Header
        header = f"# {TOOL_NAME} v{TOOL_VERSION} - Skills Scan Report\n\n"
        md_content.append(header)
        md_content.append(f"**Target:** {self.results['target']}\n")
        md_content.append(f"**Scan Date:** {self.results['timestamp']}\n")
        md_content.append(f"**Skills Found:** {self.results['total_skills']}\n")
        total_flags = len(self.results.get("security_flags", []))
        md_content.append(f"**Security Flags:** {total_flags}\n\n")

        # Skills
        for i, skill in enumerate(self.results.get("skills", []), 1):
            md_content.append(f"## Skill {i}: {skill['name']}\n\n")

            if skill.get("description"):
                md_content.append(f"**Description:** {skill['description']}\n\n")

            if skill.get("author"):
                md_content.append(f"**Author:** {skill['author']}\n")

            if skill.get("version"):
                md_content.append(f"**Version:** {skill['version']}\n")

            if skill.get("license"):
                md_content.append(f"**License:** {skill['license']}\n")

            md_content.append("\n")

            # Scripts
            scripts = skill.get("scripts", [])
            if scripts:
                md_content.append(f"### Scripts ({len(scripts)} files)\n\n")
                for script in scripts:
                    suspicious = script.get("suspicious_patterns", [])
                    status = " (SUSPICIOUS)" if suspicious else ""
                    md_content.append(f"- `{script['name']}`{status}\n")
                    if suspicious:
                        for pattern in suspicious:
                            md_content.append(f"  - {pattern}\n")
                md_content.append("\n")

            # References
            refs = skill.get("references", [])
            if refs:
                md_content.append(f"### References ({len(refs)} files)\n\n")
                for ref in refs:
                    md_content.append(f"- `{ref.get('relative_path', ref['name'])}`\n")
                md_content.append("\n")

            # Allowed Tools Analysis
            tools_analysis = skill.get("allowed_tools_analysis", {})
            if tools_analysis and tools_analysis.get("tool_count", 0) > 0:
                md_content.append("### Tool Permissions Analysis\n\n")
                md_content.append(f"**Tool Count:** {tools_analysis['tool_count']}\n")
                md_content.append(f"**Risk Level:** {tools_analysis['risk_level'].upper()}\n")
                if tools_analysis.get("dangerous_patterns"):
                    md_content.append(f"**Dangerous Patterns:** {', '.join(tools_analysis['dangerous_patterns'])}\n")
                md_content.append("\n")

            # Security Flags
            security_flags = skill.get("security_flags", [])
            if security_flags:
                md_content.append("### Security Flags\n\n")
                for flag in security_flags:
                    severity = flag.get("severity", "unknown").upper()
                    md_content.append(f"- **[{severity}]** {flag['type']}\n")
                    if flag.get("source"):
                        source_info = flag['source']
                        if flag.get("line_number"):
                            source_info += f":{flag['line_number']}"
                        md_content.append(f"  - Source: `{source_info}`\n")
                    if flag.get("line_content"):
                        md_content.append(f"  - Line: `{flag['line_content']}`\n")
                    if flag.get("package"):
                        md_content.append(f"  - Package: `{flag['package']}`\n")
                    if flag.get("required_tool"):
                        md_content.append(f"  - Required Tool: `{flag['required_tool']}`\n")
                    if flag.get("details"):
                        md_content.append(f"  - Details: {flag['details']}\n")
                    if flag.get("remediation"):
                        md_content.append(f"  - **Remediation:** {flag['remediation']}\n")
                md_content.append("\n")

        # Nova analysis
        if self.nova_analysis:
            md_content.append("## NOVA Security Analysis\n\n")
            rule_info = self.nova_analysis["rule_info"]

            if rule_info['rule_count'] > 1:
                rules_str = ', '.join(rule_info['rule_names'])
                md_content.append(f"**Rules:** {rules_str} ({rule_info['rule_count']} total)\n")
            else:
                md_content.append(f"**Rule:** {rule_info['name']}\n")

            md_content.append(f"**Evaluator:** {rule_info['evaluator_type']}\n")
            total_analyzed = self.nova_analysis['total_texts_analyzed']
            md_content.append(f"**Items Analyzed:** {total_analyzed}\n")
            flagged_count = self.nova_analysis['flagged_count']
            md_content.append(f"**Flagged Items:** {flagged_count}\n\n")

            if self.nova_analysis["flagged_count"] > 0:
                md_content.append("### Security Alerts\n\n")

                alerts_by_rule = {}
                for result in self.nova_analysis["analysis_results"]:
                    if result["nova_evaluation"].get("matched", False):
                        matched_rules = result["nova_evaluation"].get("matched_rules", [])
                        primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")

                        if not matched_rules:
                            matched_rules = [primary_rule]

                        for rule_name in matched_rules:
                            if rule_name not in alerts_by_rule:
                                alerts_by_rule[rule_name] = []
                            alerts_by_rule[rule_name].append(result)

                for rule_name, alerts in alerts_by_rule.items():
                    alert_count = len(alerts)
                    md_content.append(f"#### Rule: {rule_name} ({alert_count} alert{'s' if alert_count > 1 else ''})\n\n")

                    for i, result in enumerate(alerts, 1):
                        nova_result = result["nova_evaluation"]

                        md_content.append(f"**[{i}] {result['source']}**\n\n")
                        md_content.append(f"- **Type:** {result['type']}\n")
                        md_content.append(f"- **Content:** {result['text_preview']}\n")

                        per_rule_keywords = nova_result.get("per_rule_keywords", {})

                        if per_rule_keywords and rule_name in per_rule_keywords:
                            keywords_to_show = per_rule_keywords[rule_name]
                        else:
                            keywords_to_show = nova_result.get("matching_keywords", {})

                        if keywords_to_show:
                            if isinstance(keywords_to_show, dict):
                                keyword_list = [f"'{k}'" for k, v in keywords_to_show.items() if v]
                            else:
                                keyword_list = [str(keywords_to_show)]

                            if keyword_list:
                                keywords_str = ", ".join(keyword_list)
                                md_content.append(f"- **Triggered Keywords:** {keywords_str}\n")

                        matched_rules_list = nova_result.get("matched_rules", [])
                        if matched_rules_list and len(matched_rules_list) > 1:
                            other_rules = [r for r in matched_rules_list if r != rule_name]
                            if other_rules:
                                md_content.append(f"- **Also Matches:** {', '.join(other_rules)}\n")

                        md_content.append("\n")

        # Errors
        if self.results.get("errors"):
            md_content.append("## Errors\n\n")
            for error in self.results["errors"]:
                md_content.append(f"- {error}\n")
            md_content.append("\n")

        # Write to file
        with open(filename, "w") as f:
            f.write("".join(md_content))

        print(f"{GREEN}[+] Markdown report exported to: {filename}{RESET}")


def print_ascii_art():
    """Print fun ASCII art for help display."""
    art = """
    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗     ██████╗ ██████╗  ██████╗ ██╗  ██╗
    ████╗  ██║██╔═══██╗██║   ██║██╔══██╗    ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝
    ██╔██╗ ██║██║   ██║██║   ██║███████║    ██████╔╝██████╔╝██║   ██║ ╚███╔╝
    ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║    ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗
    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║    ██║     ██║  ██║╚██████╔╝██╔╝ ██╗
    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝

    🛡️  {} v{} - {}
    🔍 Discover • 🔧 Analyze • 🛡️  Secure
    by {}
    """.format(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, TOOL_AUTHOR)
    print(art)


class CustomHelpAction(argparse._HelpAction):
    """Custom help action that shows ASCII art."""
    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest, default, help)

    def __call__(self, parser, namespace, values, option_string=None):
        _ = namespace, values, option_string
        print_ascii_art()
        parser.print_help()
        parser.exit()


async def main():
    """Main function for Nova Proximity scanner."""
    parser = argparse.ArgumentParser(
        description="Nova Proximity - MCP and Skills Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog="""
Examples:
  # Basic MCP scan
  python novaprox.py http://localhost:8000

  # Scan with authentication
  python novaprox.py http://localhost:8000 -t your_token

  # Scan stdio server
  python novaprox.py "python server.py"

  # Security scan with Nova rules
  python novaprox.py http://localhost:8000 -n -r my_rule.nov

  # Scan Agent Skills directory
  python novaprox.py --skill /path/to/skill -n -r skill_rules.nov

  # Recursively scan skills repository
  python novaprox.py --skill /path/to/skills-repo --skill-recursive -n

  # Export reports
  python novaprox.py http://localhost:8000 --json-report --md-report
        """
    )

    parser.add_argument('-h', '--help', action=CustomHelpAction,
                        help='show this help message and exit')

    # MCP target (optional when using --skill)
    parser.add_argument("target", nargs="?", default=None,
                        help="MCP server target (HTTP URL or stdio command)")

    # Skill scanning options
    skill_group = parser.add_argument_group("Skill Scanning")
    skill_group.add_argument("-s", "--skill", metavar="PATH",
                             help="Scan Agent Skills directory for security issues")
    skill_group.add_argument("--skill-recursive", action="store_true",
                             help="Recursively scan for skills in subdirectories")

    # MCP options
    mcp_group = parser.add_argument_group("MCP Options")
    mcp_group.add_argument("-t", "--token",
                           help="Authentication token for HTTP endpoints")
    mcp_group.add_argument("--timeout", type=float, default=10.0,
                           help="Connection timeout in seconds (default: 10)")

    # Common options
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output during scanning")

    # Nova security scanning
    nova_group = parser.add_argument_group("Nova Security Scanning")
    nova_group.add_argument("-n", "--nova-scan", action="store_true",
                            help="Enable Nova security analysis")
    nova_group.add_argument("-r", "--rule", default=None,
                            help="Nova rule file path (default: my_rule.nov for MCP, skill_rules.nov for skills)")
    nova_group.add_argument("--evaluator", choices=["openai", "groq"],
                            default="openai",
                            help="LLM evaluator type (default: openai)")
    nova_group.add_argument("--model",
                            help="LLM model to use (optional)")
    nova_group.add_argument("--api-key",
                            help="API key for LLM evaluator (optional)")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--json-report", action="store_true",
                              help="Export detailed JSON report")
    output_group.add_argument("--md-report", action="store_true",
                              help="Export markdown report")
    output_group.add_argument("--output-prefix", default=None,
                              help="Prefix for output files (default: novaprox_scan or skill_scan)")
    output_group.add_argument("--full-output", action="store_true",
                              help="Show full text without truncation (remediation, details, etc.)")

    args = parser.parse_args()

    # Determine scan mode
    scan_mode = "skill" if args.skill else "mcp"

    # Validate arguments
    if scan_mode == "mcp" and not args.target:
        parser.error("target is required for MCP scanning (or use --skill for skill scanning)")

    if scan_mode == "skill" and not YAML_AVAILABLE:
        print(f"{RED}[-] Error: PyYAML not available for skill scanning.{RESET}")
        print("Install with: pip install pyyaml")
        sys.exit(1)

    # Set default rule file based on mode
    if args.rule is None:
        args.rule = "skill_rules.nov" if scan_mode == "skill" else "my_rule.nov"

    # Set default output prefix based on mode
    if args.output_prefix is None:
        args.output_prefix = "skill_scan" if scan_mode == "skill" else "novaprox_scan"
    
    # Validate Nova requirements
    if args.nova_scan and not NOVA_AVAILABLE:
        print(f"{RED}[-] Error: Nova library not available for security scanning.{RESET}")
        print("Install with: pip install nova-hunting")
        sys.exit(1)

    if args.nova_scan and not os.path.exists(args.rule):
        print(f"{RED}[-] Error: Nova rule file not found: {args.rule}{RESET}")
        sys.exit(1)

    # Display header based on mode
    if scan_mode == "skill":
        print(f"\n--==[{BOLD}{GREEN} {TOOL_NAME} v{TOOL_VERSION} - Skills Scanner{RESET} - {CYAN}by {TOOL_AUTHOR}{RESET}]==--")
        print(f"\n🎯 {CYAN}Target: {args.skill}{RESET}")
        if args.skill_recursive:
            print(f"📁 {CYAN}Recursive: Enabled{RESET}")
    else:
        print(f"\n--==[{BOLD}{GREEN} {TOOL_NAME} v{TOOL_VERSION} - MCP Scanner{RESET} - {CYAN}by {TOOL_AUTHOR}{RESET}]==--")
        print(f"\n🎯 {CYAN}Target: {args.target}{RESET}")

    if args.nova_scan:
        print(f"🛡️ {YELLOW} NOVA Analysis: Enabled ({args.rule}){RESET}")
    print()

    try:
        if scan_mode == "skill":
            # Skill scanning mode
            with yaspin(text=" Scanning Agent Skills...", color="cyan") as spinner:
                await asyncio.sleep(0.1)
                verbose_mode = args.verbose or args.nova_scan

                def update_spinner(message):
                    spinner.text = message

                scan_results = await scan_skills(
                    target_path=args.skill,
                    verbose=verbose_mode,
                    spinner_callback=update_spinner,
                    recursive=args.skill_recursive
                )

                await asyncio.sleep(0.1)
                spinner.ok("[+]")

            if args.verbose:
                print(f"{CYAN}[DEBUG] Scan results summary:{RESET}")
                print(f"  Skills: {scan_results.get('total_skills', 0)}")
                print(f"  Security Flags: {len(scan_results.get('security_flags', []))}")

            nova_analysis = None

            if args.nova_scan:
                with yaspin(text=" Running NOVA analysis...",
                           color="yellow") as spinner:
                    try:
                        nova_evaluator = NovaEvaluator(
                            rule_file_path=args.rule,
                            evaluator_type=args.evaluator,
                            model=args.model,
                            api_key=args.api_key
                        )

                        analyzer = SkillNovaAnalyzer(nova_evaluator)

                        def progress_callback(current, total, item):
                            spinner.text = (f" Analyzing {current}/{total}: "
                                           f"{item[:30]}...")

                        nova_analysis = analyzer.analyze_skill_results(
                            scan_results,
                            progress_callback=progress_callback
                        )

                        flagged = nova_analysis['flagged_count']
                        total = nova_analysis['total_texts_analyzed']
                        spinner.ok(f"[+] NOVA analysis complete: "
                                  f"{flagged}/{total} items flagged")

                    except Exception as e:
                        spinner.fail(f"[-] NOVA analysis failed: {e}")
                        nova_analysis = None

            reporter = ProximityReporter(scan_results, nova_analysis, scan_mode="skill",
                                         full_output=args.full_output)
            reporter.display_skill_report()

            if args.json_report or args.md_report:
                with yaspin(text=" Generating reports...",
                           color="green") as spinner:

                    if args.json_report:
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        json_filename = f"{args.output_prefix}_{timestamp}.json"
                        reporter.export_skill_json_report(json_filename)

                    if args.md_report:
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        md_filename = f"{args.output_prefix}_{timestamp}.md"
                        reporter.export_skill_markdown_report(md_filename)

                    spinner.ok("[+]")

        else:
            # MCP scanning mode (original behavior)
            with yaspin(text=" Scanning MCP server...", color="cyan") as spinner:
                await asyncio.sleep(0.1)
                verbose_mode = args.verbose or args.nova_scan

                def update_spinner(message):
                    spinner.text = message

                scan_results = await scan_mcp_server(
                    target=args.target,
                    token=args.token,
                    timeout=args.timeout,
                    verbose=verbose_mode,
                    spinner_callback=update_spinner
                )

                await asyncio.sleep(0.1)
                spinner.ok("[+]")

            if args.verbose:
                print(f"{CYAN}[DEBUG] Scan results summary:{RESET}")
                print(f"  Tools: {len(scan_results.get('tools', []))}")
                print(f"  Prompts: {len(scan_results.get('prompts', []))}")
                print(f"  Resources: {len(scan_results.get('resources', []))}")
                print(f"  Capabilities: {scan_results.get('capabilities', {})}")

            nova_analysis = None

            if args.nova_scan:
                with yaspin(text=" Running NOVA analysis...",
                           color="yellow") as spinner:
                    try:
                        nova_evaluator = NovaEvaluator(
                            rule_file_path=args.rule,
                            evaluator_type=args.evaluator,
                            model=args.model,
                            api_key=args.api_key
                        )

                        analyzer = MCPNovaAnalyzer(nova_evaluator)

                        def progress_callback(current, total, item):
                            spinner.text = (f" Analyzing {current}/{total}: "
                                           f"{item[:30]}...")

                        nova_analysis = analyzer.analyze_mcp_results(
                            scan_results,
                            progress_callback=progress_callback
                        )

                        flagged = nova_analysis['flagged_count']
                        total = nova_analysis['total_texts_analyzed']
                        spinner.ok(f"[+] NOVA analysis complete: "
                                  f"{flagged}/{total} items flagged")

                    except Exception as e:
                        spinner.fail(f"[-] NOVA analysis failed: {e}")
                        nova_analysis = None

            reporter = ProximityReporter(scan_results, nova_analysis, scan_mode="mcp",
                                         full_output=args.full_output)
            reporter.display_console_report()

            if args.json_report or args.md_report:
                with yaspin(text=" Generating reports...",
                           color="green") as spinner:

                    if args.json_report:
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        json_filename = f"{args.output_prefix}_{timestamp}.json"
                        reporter.export_json_report(json_filename)

                    if args.md_report:
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        md_filename = f"{args.output_prefix}_{timestamp}.md"
                        reporter.export_markdown_report(md_filename)

                    spinner.ok("[+]")

        print(f"\n{GREEN}[+] {TOOL_NAME} scan completed successfully!{RESET}")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}[-] Scan failed: {e}{RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())