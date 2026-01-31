#!/usr/bin/env python3
"""
Nova Evaluator Library
Library for evaluating prompts against Nova security rules.

Author: Thomas Roccia (@fr0gger_)
Version: 1.0.0
License: GPL-3.0
Repository: https://github.com/fr0gger/nova-proximity
"""

from typing import Dict, List, Optional, Any
import os

__version__ = "1.0.0"
__author__ = "Thomas Roccia (@fr0gger_)"

try:
    from nova.core.parser import NovaParser
    from nova.core.matcher import NovaMatcher
    from nova.evaluators.llm import OpenAIEvaluator, GroqEvaluator
    NOVA_AVAILABLE = True
except ImportError:
    NOVA_AVAILABLE = False


class NovaEvaluator:
    """Nova rule evaluator for prompt security testing."""
    
    def __init__(self, rule_file_path: str, evaluator_type: str = "openai", 
                 model: Optional[str] = None, api_key: Optional[str] = None):
        """
        Initialize Nova evaluator.
        
        Args:
            rule_file_path: Path to the .nov rule file
            evaluator_type: Type of evaluator ("openai" or "groq")
            model: Model to use (optional, defaults will be used)
            api_key: API key for the evaluator (optional, uses env vars)
        """
        if not NOVA_AVAILABLE:
            raise ImportError("Nova library not available. Install nova-python package.")
        
        self.rule_file_path = rule_file_path
        self.evaluator_type = evaluator_type.lower()
        self.model = model
        self.api_key = api_key
        self.rules = []  # Changed to support multiple rules
        self.matchers = []  # Multiple matchers for multiple rules
        
        self._load_rules()
        self._setup_evaluators()
    
    def _load_rules(self):
        """Load and parse all Nova rules from the file."""
        try:
            with open(self.rule_file_path, 'r') as f:
                rule_content = f.read()
            
            # Parse individual rules from the file
            self.rules = self._parse_multiple_rules(rule_content)
            
            if not self.rules:
                raise ValueError("No valid rules found in the rule file")
                
        except FileNotFoundError:
            raise FileNotFoundError(f"Rule file not found: {self.rule_file_path}")
        except Exception as e:
            raise ValueError(f"Failed to parse rule file: {e}")
    
    def _parse_multiple_rules(self, content: str) -> List[Any]:
        """Parse multiple rules from rule file content."""
        import re
        
        rules = []
        parser = NovaParser()
        
        rule_pattern = r'rule\s+(\w+)\s*\{'
        matches = list(re.finditer(rule_pattern, content))
        
        if not matches:
            # Try parsing as single rule
            try:
                rule = parser.parse(content)
                if rule:
                    rules.append(rule)
            except Exception:
                pass
        else:
            # Extract each rule individually
            for i, match in enumerate(matches):
                start_pos = match.start()
                
                # Find the end of this rule (start of next rule or end of content)
                if i + 1 < len(matches):
                    end_pos = matches[i + 1].start()
                else:
                    end_pos = len(content)
                
                rule_text = content[start_pos:end_pos].strip()
                
                try:
                    rule = parser.parse(rule_text)
                    if rule:
                        rules.append(rule)
                except Exception as e:
                    print(f"Warning: Failed to parse rule {match.group(1)}: {e}")
                    continue
        
        return rules
    
    def _setup_evaluators(self):
        """Setup LLM evaluators for all rules."""
        self.matchers = []
        
        for rule in self.rules:
            if self.evaluator_type == "openai":
                model = self.model or "gpt-4o-mini"
                
                if self.api_key:
                    evaluator = OpenAIEvaluator(api_key=self.api_key, model=model)
                else:
                    evaluator = OpenAIEvaluator(model=model)
            
            elif self.evaluator_type == "groq":
                model = self.model or "llama-3.3-70b-versatile"
                
                if self.api_key:
                    evaluator = GroqEvaluator(api_key=self.api_key, model=model)
                else:
                    evaluator = GroqEvaluator(model=model)
            
            else:
                raise ValueError(f"Unsupported evaluator type: {self.evaluator_type}")
            
            matcher = NovaMatcher(rule, llm_evaluator=evaluator)
            self.matchers.append({
                'rule': rule,
                'matcher': matcher,
                'rule_name': getattr(rule, 'name', 'Unknown')
            })
    
    def evaluate_prompt(self, prompt: str) -> Dict[str, Any]:
        """
        Evaluate a single prompt against all Nova rules.
        
        Args:
            prompt: The prompt text to evaluate
        
        Returns:
            dict: Evaluation result with information about all matched rules
        """
        all_results = []
        matched_rules = []
        overall_matched = False
        all_keywords = {}
        
        for matcher_info in self.matchers:
            rule = matcher_info['rule']
            matcher = matcher_info['matcher']
            rule_name = matcher_info['rule_name']
            
            try:
                result = matcher.check_prompt(prompt)
                
                # Enhanced result with rule information
                rule_result = {
                    'matched': result['matched'],
                    'matching_keywords': result.get('matching_keywords', []),
                    'rule_name': rule_name,
                    'rule_file': self.rule_file_path,
                    'evaluator': f"{self.evaluator_type}:{self.model}",
                    'prompt': prompt,
                    'raw_result': result,
                    'error': None
                }
                
                all_results.append(rule_result)
                
                if result['matched']:
                    overall_matched = True
                    matched_rules.append(rule_name)
                    if result.get('matching_keywords'):
                        all_keywords.update(result['matching_keywords'])
                
            except Exception as e:
                error_result = {
                    'matched': False,
                    'error': f"Evaluation failed: {str(e)}",
                    'rule_name': rule_name,
                    'rule_file': self.rule_file_path,
                    'evaluator': f"{self.evaluator_type}:{self.model}",
                    'prompt': prompt
                }
                all_results.append(error_result)
        
        # Return combined result
        if overall_matched:
            # Return the first matched rule as primary, but include all info
            primary_match = next(r for r in all_results if r['matched'])
            
            # Create per-rule keyword mapping
            per_rule_keywords = {}
            for result in all_results:
                if result['matched']:
                    rule_name = result['rule_name']
                    per_rule_keywords[rule_name] = result.get('matching_keywords', {})
            
            # Clean up result to avoid circular references
            clean_result = {
                'matched': primary_match['matched'],
                'matching_keywords': primary_match.get('matching_keywords', []),
                'rule_name': primary_match['rule_name'],
                'rule_file': self.rule_file_path,
                'evaluator': f"{self.evaluator_type}:{self.model}",
                'prompt': prompt,
                'matched_rules': matched_rules,
                'all_matching_keywords': all_keywords,
                'per_rule_keywords': per_rule_keywords,
                'error': None
            }
            return clean_result
        else:
            # Return result indicating no matches but include all attempts
            return {
                'matched': False,
                'matching_keywords': {},
                'rule_name': f"No matches ({len(self.rules)} rules checked)",
                'rule_file': self.rule_file_path,
                'evaluator': f"{self.evaluator_type}:{self.model}",
                'prompt': prompt,
                'matched_rules': [],
                'error': None
            }
    
    def evaluate_batch(self, prompts: List[str], 
                      progress_callback: Optional[callable] = None) -> List[Dict[str, Any]]:
        """
        Evaluate multiple prompts against the Nova rule.
        
        Args:
            prompts: List of prompt strings to evaluate
            progress_callback: Optional callback function for progress updates
        
        Returns:
            list: List of evaluation results
        """
        results = []
        
        for i, prompt in enumerate(prompts):
            if progress_callback:
                progress_callback(i + 1, len(prompts), prompt)
            
            result = self.evaluate_prompt(prompt)
            results.append(result)
        
        return results
    
    def get_rule_info(self) -> Dict[str, Any]:
        """Get information about all loaded rules."""
        rule_names = [getattr(rule, 'name', 'Unknown') for rule in self.rules]
        primary_rule_name = rule_names[0] if rule_names else 'Unknown'
        
        return {
            'name': primary_rule_name,  # Keep backward compatibility
            'rule_names': rule_names,   # All rule names
            'rule_count': len(self.rules),
            'file_path': self.rule_file_path,
            'evaluator_type': self.evaluator_type,
            'model': self.model
        }


class MCPNovaAnalyzer:
    """Analyzer for combining MCP scan results with Nova security evaluation."""
    
    def __init__(self, nova_evaluator: NovaEvaluator):
        """
        Initialize MCP Nova analyzer.
        
        Args:
            nova_evaluator: Configured NovaEvaluator instance
        """
        self.nova_evaluator = nova_evaluator
        self.analysis_results = {
            "rule_info": nova_evaluator.get_rule_info(),
            "total_texts_analyzed": 0,
            "flagged_count": 0,
            "analysis_results": []
        }
    
    def extract_texts_from_mcp_results(self, mcp_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Extract all analyzable text content from MCP scan results.
        
        Args:
            mcp_results: Results from MCP scanner
        
        Returns:
            list: List of text items to analyze
        """
        texts_to_analyze = []
        
        if not mcp_results:
            return texts_to_analyze
        
        # Extract tool descriptions
        for tool in mcp_results.get("tools", []):
            if tool.get("description") and tool["description"] != "No description":
                texts_to_analyze.append({
                    "type": "tool_description",
                    "source": f"Tool: {tool['name']}",
                    "text": tool["description"],
                    "metadata": {"tool_name": tool["name"]}
                })
        
        # Extract prompt descriptions
        for prompt in mcp_results.get("prompts", []):
            if prompt.get("description") and prompt["description"] != "No description":
                texts_to_analyze.append({
                    "type": "prompt_description", 
                    "source": f"Prompt: {prompt['name']}",
                    "text": prompt["description"],
                    "metadata": {"prompt_name": prompt["name"]}
                })
            
            if prompt.get("full_content") and prompt["full_content"].get("messages"):
                for msg_idx, message in enumerate(prompt["full_content"]["messages"]):
                    for content_item in message.get("content", []):
                        if content_item.get("type") == "text" and content_item.get("text"):
                            text_content = content_item["text"].strip()
                            if len(text_content) > 20:  # Only substantial content
                                texts_to_analyze.append({
                                    "type": "prompt_content",
                                    "source": f"Prompt: {prompt['name']} (Message {msg_idx + 1})",
                                    "text": text_content,
                                    "metadata": {
                                        "prompt_name": prompt["name"], 
                                        "message_index": msg_idx + 1
                                    }
                                })
        
        # Extract resource descriptions
        for resource in mcp_results.get("resources", []):
            if resource.get("description") and resource["description"] != "No description":
                texts_to_analyze.append({
                    "type": "resource_description",
                    "source": f"Resource: {resource['uri']}",
                    "text": resource["description"],
                    "metadata": {"resource_uri": resource["uri"]}
                })
        
        return texts_to_analyze
    
    def analyze_mcp_results(self, mcp_results: Dict[str, Any], 
                           progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        Analyze MCP results with Nova security evaluation.
        
        Args:
            mcp_results: Results from MCP scanner
            progress_callback: Optional progress callback
        
        Returns:
            dict: Combined analysis results
        """
        texts_to_analyze = self.extract_texts_from_mcp_results(mcp_results)
        self.analysis_results["total_texts_analyzed"] = len(texts_to_analyze)
        
        if not texts_to_analyze:
            return self.analysis_results
        
        flagged_count = 0
        
        for i, text_item in enumerate(texts_to_analyze):
            if progress_callback:
                progress_callback(i + 1, len(texts_to_analyze), text_item["source"])
            
            # Evaluate with Nova
            nova_result = self.nova_evaluator.evaluate_prompt(text_item["text"])
            
            # Store analysis result
            analysis_result = {
                "index": i + 1,
                "type": text_item["type"],
                "source": text_item["source"],
                "text_preview": text_item["text"][:100] + "..." if len(text_item["text"]) > 100 else text_item["text"],
                "full_text": text_item["text"],
                "metadata": text_item.get("metadata", {}),
                "nova_evaluation": nova_result
            }
            
            self.analysis_results["analysis_results"].append(analysis_result)
            
            if nova_result.get("matched", False):
                flagged_count += 1
        
        self.analysis_results["flagged_count"] = flagged_count
        return self.analysis_results
    
    def get_flagged_items(self) -> List[Dict[str, Any]]:
        """Get only the items that were flagged by Nova."""
        return [
            result for result in self.analysis_results["analysis_results"]
            if result["nova_evaluation"].get("matched", False)
        ]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the analysis."""
        flagged_items = self.get_flagged_items()
        
        return {
            "total_analyzed": self.analysis_results["total_texts_analyzed"],
            "flagged_count": self.analysis_results["flagged_count"],
            "rule_name": self.analysis_results["rule_info"]["name"],
            "flagged_sources": [item["source"] for item in flagged_items],
            "flagged_types": list(set(item["type"] for item in flagged_items))
        }


class SkillNovaAnalyzer:
    """Analyzer for combining Skill scan results with Nova security evaluation."""

    def __init__(self, nova_evaluator: NovaEvaluator):
        """
        Initialize Skill Nova analyzer.

        Args:
            nova_evaluator: Configured NovaEvaluator instance
        """
        self.nova_evaluator = nova_evaluator
        self.analysis_results = {
            "rule_info": nova_evaluator.get_rule_info(),
            "total_texts_analyzed": 0,
            "flagged_count": 0,
            "analysis_results": []
        }

    def extract_texts_from_skill_results(self, skill_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Extract all analyzable text content from skill scan results.

        Args:
            skill_results: Results from SkillScanner

        Returns:
            list: List of text items to analyze
        """
        texts_to_analyze = []

        if not skill_results:
            return texts_to_analyze

        for skill in skill_results.get("skills", []):
            skill_name = skill.get("name", "Unknown")

            # Extract description from frontmatter
            description = skill.get("description", "")
            if description and len(description) > 10:
                texts_to_analyze.append({
                    "type": "skill_description",
                    "source": f"Skill: {skill_name} (description)",
                    "text": description,
                    "metadata": {"skill_name": skill_name, "field": "description"}
                })

            # Extract body content (markdown instructions)
            body_content = skill.get("body_content", "")
            if body_content and len(body_content) > 20:
                texts_to_analyze.append({
                    "type": "skill_instructions",
                    "source": f"Skill: {skill_name} (instructions)",
                    "text": body_content,
                    "metadata": {"skill_name": skill_name, "field": "body_content"}
                })

            # Extract compatibility field
            compatibility = skill.get("compatibility", "")
            if compatibility and len(str(compatibility)) > 10:
                texts_to_analyze.append({
                    "type": "skill_compatibility",
                    "source": f"Skill: {skill_name} (compatibility)",
                    "text": str(compatibility),
                    "metadata": {"skill_name": skill_name, "field": "compatibility"}
                })

            # Extract allowed-tools for analysis
            frontmatter = skill.get("frontmatter", {})
            allowed_tools = frontmatter.get("allowed-tools") or frontmatter.get("allowed_tools")
            if allowed_tools:
                tools_text = str(allowed_tools) if not isinstance(allowed_tools, str) else allowed_tools
                if len(tools_text) > 5:
                    texts_to_analyze.append({
                        "type": "allowed_tools",
                        "source": f"Skill: {skill_name} (allowed-tools)",
                        "text": tools_text,
                        "metadata": {"skill_name": skill_name, "field": "allowed-tools"}
                    })

            # NOTE: Script contents are NOT sent to NOVA for LLM analysis.
            # Script security analysis (eval, exec, subprocess, imports, etc.)
            # is handled by skill_scanner_lib.py using regex-based pattern matching.
            # NOVA is designed for prompt/instruction analysis, not code analysis.

            # Extract reference file contents
            for ref in skill.get("references", []):
                if ref.get("content") and not ref.get("error"):
                    # Skip binary file placeholders
                    if not ref["content"].startswith("[Binary file:"):
                        texts_to_analyze.append({
                            "type": "reference_content",
                            "source": f"Skill: {skill_name} / references/{ref.get('relative_path', ref['name'])}",
                            "text": ref["content"],
                            "metadata": {
                                "skill_name": skill_name,
                                "reference_name": ref["name"],
                                "reference_path": ref.get("path", "")
                            }
                        })

        return texts_to_analyze

    def analyze_skill_results(self, skill_results: Dict[str, Any],
                              progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        Analyze skill results with Nova security evaluation.

        Args:
            skill_results: Results from SkillScanner
            progress_callback: Optional progress callback

        Returns:
            dict: Combined analysis results
        """
        texts_to_analyze = self.extract_texts_from_skill_results(skill_results)
        self.analysis_results["total_texts_analyzed"] = len(texts_to_analyze)

        if not texts_to_analyze:
            return self.analysis_results

        flagged_count = 0

        for i, text_item in enumerate(texts_to_analyze):
            if progress_callback:
                progress_callback(i + 1, len(texts_to_analyze), text_item["source"])

            # Evaluate with Nova
            nova_result = self.nova_evaluator.evaluate_prompt(text_item["text"])

            # Store analysis result
            text_preview = text_item["text"][:100] + "..." if len(text_item["text"]) > 100 else text_item["text"]
            analysis_result = {
                "index": i + 1,
                "type": text_item["type"],
                "source": text_item["source"],
                "text_preview": text_preview,
                "full_text": text_item["text"],
                "metadata": text_item.get("metadata", {}),
                "nova_evaluation": nova_result
            }

            self.analysis_results["analysis_results"].append(analysis_result)

            if nova_result.get("matched", False):
                flagged_count += 1

        self.analysis_results["flagged_count"] = flagged_count
        return self.analysis_results

    def get_flagged_items(self) -> List[Dict[str, Any]]:
        """Get only the items that were flagged by Nova."""
        return [
            result for result in self.analysis_results["analysis_results"]
            if result["nova_evaluation"].get("matched", False)
        ]

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the analysis."""
        flagged_items = self.get_flagged_items()

        return {
            "total_analyzed": self.analysis_results["total_texts_analyzed"],
            "flagged_count": self.analysis_results["flagged_count"],
            "rule_name": self.analysis_results["rule_info"]["name"],
            "flagged_sources": [item["source"] for item in flagged_items],
            "flagged_types": list(set(item["type"] for item in flagged_items))
        }


def evaluate_prompt_with_nova_rule(prompt: str, rule_file_path: str,
                                  evaluator_type: str = "openai",
                                  model: Optional[str] = None,
                                  api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to evaluate a single prompt against a Nova rule.
    
    Args:
        prompt: The prompt text to evaluate
        rule_file_path: Path to the .nov rule file
        evaluator_type: Type of evaluator ("openai" or "groq")
        model: Model to use (optional)
        api_key: API key for the evaluator (optional)
    
    Returns:
        dict: Evaluation result
    """
    try:
        evaluator = NovaEvaluator(
            rule_file_path=rule_file_path,
            evaluator_type=evaluator_type,
            model=model,
            api_key=api_key
        )
        return evaluator.evaluate_prompt(prompt)
    except Exception as e:
        return {
            'matched': False,
            'error': f"Setup failed: {str(e)}",
            'prompt': prompt
        }