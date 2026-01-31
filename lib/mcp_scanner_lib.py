#!/usr/bin/env python3
"""
MCP Scanner Library
A library for scanning and analyzing MCP (Model Context Protocol) servers.

Author: Thomas Roccia (@fr0gger_)
Version: 1.0.0
License: GPL
Repository: https://github.com/fr0gger/nova-proximity
"""

import asyncio
import json
import sys
import requests
import urllib3
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

__version__ = "1.1.0"
__author__ = "Thomas Roccia (@fr0gger_)"

# MCP Protocol version (spec 2025-11-25)
MCP_PROTOCOL_VERSION = "2025-11-25"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError as e:
    raise ImportError(f"MCP client library not found: {e}. Install with: pip install mcp")

try:
    from mcp.client.sse import sse_client
    SSE_AVAILABLE = True
except ImportError:
    SSE_AVAILABLE = False

try:
    from mcp.client.streamable_http import streamablehttp_client
    STREAMABLE_HTTP_AVAILABLE = True
except ImportError:
    STREAMABLE_HTTP_AVAILABLE = False


class MCPScanner:
    """MCP server scanner and analyzer."""

    def __init__(self, target: str, token: Optional[str] = None,
                 timeout: float = 10.0, verbose: bool = False,
                 spinner_callback: Optional[callable] = None):
        self.target = target.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.verbose = verbose
        self.spinner_callback = spinner_callback
        self.session: ClientSession | None = None
        self.mcp_session_id: Optional[str] = None  # MCP Spec 2025-11-25 session management
        self.protocol_version: str = MCP_PROTOCOL_VERSION  # Negotiated protocol version

        self.results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "protocol_version": MCP_PROTOCOL_VERSION,  # MCP Spec 2025-11-25
            "endpoints": [],
            "transport_types": [],
            "session_id": None,  # MCP Spec 2025-11-25 session management
            "capabilities": {},
            "tools": [],
            "prompts": [],
            "resources": [],
            "errors": []
        }

    def log(self, message: str):
        """Simple logging."""
        if self.spinner_callback:
            # Update spinner text instead of printing
            self.spinner_callback(f" {message}")
        elif self.verbose:
            print(f"[*] {message}")

    def discover_endpoints(self) -> List[str]:
        """Discover MCP endpoints."""
        if not self.target.startswith("http"):
            self.results["transport_types"].append("stdio")
            return [self.target]
        
        base = self.target
        parsed = urlparse(base)
        
        candidates = [
            base,
            f"{base}/sse",
            f"{base}/mcp",
            f"{base}/api/sse", 
            f"{base}/api/mcp",
            f"{parsed.scheme}://{parsed.netloc}/sse",
            f"{parsed.scheme}://{parsed.netloc}/mcp",
        ]
        candidates = list(set(candidates))
        
        discovered = []
        self.log(f"Discovering endpoints on {base}")
        
        for url in candidates:
            endpoint_type = self.probe_endpoint(url)
            if endpoint_type:
                self.log(f"Found {endpoint_type} endpoint: {url}")
                discovered.append(url)
                self.results["endpoints"].append({
                    "url": url, 
                    "type": endpoint_type
                })
                if endpoint_type not in self.results["transport_types"]:
                    self.results["transport_types"].append(endpoint_type)
        
        if not discovered:
            self.log("No MCP endpoints found")
        
        return discovered

    def probe_endpoint(self, url: str) -> Optional[str]:
        """
        Probe endpoint to determine transport type.

        Follows MCP Spec 2025-11-25 backwards compatibility:
        1. Try POST first (new Streamable HTTP transport)
        2. If 400/404/405, fall back to GET for SSE (old HTTP+SSE transport)
        """
        # Headers for new Streamable HTTP transport (MCP Spec 2025-11-25)
        headers = {
            "User-Agent": "MCP-Scanner/1.1.0",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.mcp_session_id:
            headers["MCP-Session-Id"] = self.mcp_session_id

        # Step 1: Try POST (new Streamable HTTP transport)
        try:
            # Send a minimal JSON-RPC request to probe
            probe_body = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "MCP-Scanner", "version": "1.1.0"}
                }
            })

            r = requests.post(
                url,
                data=probe_body,
                timeout=self.timeout,
                headers=headers,
                verify=False,
                allow_redirects=True
            )

            content_type = r.headers.get("Content-Type", "").lower()

            # Check for session ID in response (MCP Spec 2025-11-25)
            session_id = r.headers.get("MCP-Session-Id")
            if session_id:
                self.mcp_session_id = session_id
                self.results["session_id"] = session_id

            # Streamable HTTP returns JSON or SSE stream
            if r.status_code == 200:
                if "application/json" in content_type:
                    return "streamable_http"
                elif "text/event-stream" in content_type:
                    return "streamable_http"  # SSE stream from Streamable HTTP

            # Step 2: If POST fails with 400/404/405, try legacy SSE transport
            if r.status_code in [400, 404, 405]:
                return self._probe_legacy_sse(url)

        except requests.exceptions.RequestException:
            # Connection failed, try legacy SSE
            pass

        # Step 3: Fallback - try legacy SSE transport
        return self._probe_legacy_sse(url)

    def _probe_legacy_sse(self, url: str) -> Optional[str]:
        """
        Probe for legacy HTTP+SSE transport (protocol version 2024-11-05).

        Per MCP Spec 2025-11-25 backwards compatibility:
        Issue GET request expecting SSE stream with 'endpoint' event.
        """
        headers = {
            "User-Agent": "MCP-Scanner/1.1.0",
            "Accept": "text/event-stream",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            r = requests.get(
                url,
                timeout=self.timeout,
                headers=headers,
                verify=False,
                stream=True,
                allow_redirects=True
            )

            content_type = r.headers.get("Content-Type", "").lower()

            if "text/event-stream" in content_type:
                # This is a legacy SSE endpoint
                self.log(f"Detected legacy SSE transport at {url}")
                return "sse"
            elif r.status_code == 200 and "application/json" in content_type:
                # Might be a REST endpoint that could support MCP
                return "streamable_http"

        except requests.exceptions.RequestException:
            pass

        return None

    async def connect_and_analyze(self, target: str,
                                transport_type: str = None):
        """
        Connect to MCP server and analyze capabilities.

        Implements MCP Spec 2025-11-25 backwards compatibility:
        - Try Streamable HTTP first
        - Fall back to legacy SSE if Streamable HTTP fails
        """
        if target.startswith("http"):
            if not transport_type:
                transport_type = self.determine_transport_type(target)

            if transport_type == "sse":
                await self._connect_sse(target)
            elif transport_type == "streamable_http":
                try:
                    await self._connect_streamable_http(target)
                except Exception as e:
                    # MCP Spec 2025-11-25: Fall back to legacy SSE
                    error_str = str(e).lower()
                    if any(code in error_str for code in ["400", "404", "405"]):
                        self.log(f"Streamable HTTP not supported, trying legacy SSE...")
                        await self._connect_sse(target)
                    else:
                        raise
        else:
            await self._connect_stdio(target)

    def determine_transport_type(self, url: str) -> str:
        """
        Determine transport type from URL.

        MCP Spec 2025-11-25: Prefer Streamable HTTP, fall back to legacy SSE.
        """
        # Check if we already probed this endpoint
        for endpoint in self.results["endpoints"]:
            if endpoint["url"] == url:
                return endpoint["type"]

        # URL-based heuristics
        if "/sse" in url:
            # Explicit SSE path suggests legacy transport
            return "sse"
        elif "/mcp" in url:
            # /mcp path suggests new Streamable HTTP
            return "streamable_http"
        else:
            # Default to Streamable HTTP (MCP Spec 2025-11-25 recommended)
            return "streamable_http"

    async def _connect_stdio(self, command: str):
        """Connect using stdio transport."""
        self.log(f"Connecting via stdio: {command}")
        
        parts = command.split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        server_params = StdioServerParameters(command=cmd, args=args)
        
        try:
            async with stdio_client(server_params) as (read_stream, write_stream):
                await self._run_session(read_stream, write_stream)
        except Exception as e:
            error_msg = f"stdio connection failed: {e}"
            self.log(error_msg)
            self.results["errors"].append(error_msg)

    async def _connect_sse(self, url: str):
        """
        Connect using legacy SSE transport (protocol version 2024-11-05).

        This transport is deprecated but maintained for backwards compatibility.
        """
        if not SSE_AVAILABLE:
            error_msg = "SSE transport not available"
            self.log(error_msg)
            raise Exception(error_msg)

        self.log(f"Connecting via legacy SSE: {url}")

        headers = {
            "Accept": "text/event-stream",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            async with sse_client(url=url, headers=headers) as (read_stream, write_stream):
                await self._run_session(read_stream, write_stream)
        except Exception as e:
            error_msg = f"SSE connection failed: {e}"
            self.log(error_msg)
            self.results["errors"].append(error_msg)

    async def _connect_streamable_http(self, url: str):
        """
        Connect using Streamable HTTP transport (MCP Spec 2025-11-25).

        This is the recommended transport for HTTP-based MCP servers.
        Supports session management, protocol versioning, and SSE streaming.
        """
        if not STREAMABLE_HTTP_AVAILABLE:
            error_msg = "Streamable HTTP transport not available"
            self.log(error_msg)
            raise Exception(error_msg)

        self.log(f"Connecting via Streamable HTTP: {url}")

        # Build headers for Streamable HTTP (MCP Spec 2025-11-25)
        headers = {
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.mcp_session_id:
            headers["MCP-Session-Id"] = self.mcp_session_id

        try:
            async with streamablehttp_client(url, headers=headers) as (read_stream, write_stream, get_session_id):
                # Capture session ID if provided (MCP Spec 2025-11-25)
                session_id = get_session_id()
                if session_id:
                    self.mcp_session_id = session_id
                    self.results["session_id"] = session_id
                    self.log(f"Session established: {session_id[:16]}...")

                await self._run_session(read_stream, write_stream)
        except TypeError:
            # Older MCP client versions may not support headers parameter
            self.log("Note: MCP client may not support custom headers, connecting without")
            try:
                async with streamablehttp_client(url) as (read_stream, write_stream, get_session_id):
                    session_id = get_session_id()
                    if session_id:
                        self.mcp_session_id = session_id
                        self.results["session_id"] = session_id
                    await self._run_session(read_stream, write_stream)
            except Exception as e:
                error_msg = f"Streamable HTTP connection failed: {e}"
                self.log(error_msg)
                self.results["errors"].append(error_msg)
        except Exception as e:
            error_msg = f"Streamable HTTP connection failed: {e}"
            self.log(error_msg)
            self.results["errors"].append(error_msg)

    async def _run_session(self, read_stream, write_stream):
        """Run analysis session."""
        async with ClientSession(read_stream, write_stream) as session:
            self.session = session
            
            self.log("Initializing MCP session...")
            await session.initialize()
            self.log("Connected to MCP server")
            
            await self.test_capabilities()
            await self.analyze_tools()
            await self.analyze_prompts()
            await self.analyze_resources()

    async def test_capabilities(self):
        """Test server capabilities."""
        self.log("Testing server capabilities...")
        
        capabilities = {}
        
        try:
            await self.session.list_tools()
            capabilities["tools"] = True
        except Exception:
            capabilities["tools"] = False
            
        try:
            await self.session.list_prompts()
            capabilities["prompts"] = True
        except Exception:
            capabilities["prompts"] = False
            
        try:
            await self.session.list_resources()
            capabilities["resources"] = True
        except Exception:
            capabilities["resources"] = False
        
        self.results["capabilities"] = capabilities
        self.log(f"Server capabilities: {capabilities}")

    async def analyze_tools(self):
        """Analyze tools."""
        self.log("Analyzing tools...")

        try:
            result = await self.session.list_tools()
            if not hasattr(result, "tools") or not result.tools:
                self.log("No tools available")
                return

            self.log(f"Found {len(result.tools)} tools")

            for tool in result.tools:
                tool_details = {
                    "name": tool.name,
                    "title": getattr(tool, "title", None),  # MCP Spec 2025-11-25
                    "description": getattr(tool, "description", "No description"),
                    "input_schema": getattr(tool, "inputSchema", {}),
                    "output_schema": getattr(tool, "outputSchema", None),  # MCP Spec 2025-11-25
                    "icons": getattr(tool, "icons", []),  # MCP Spec 2025-11-25
                    "annotations": {},  # MCP Spec 2025-11-25 - Security hints
                    "parameters": [],
                    "function_signature": "",
                    "example_usage": {},
                    "complexity": "simple"
                }

                # Extract tool annotations (security-relevant) - MCP Spec 2025-11-25
                if hasattr(tool, "annotations") and tool.annotations:
                    annotations = tool.annotations
                    tool_details["annotations"] = {
                        "readOnlyHint": getattr(annotations, "readOnlyHint", False),
                        "destructiveHint": getattr(annotations, "destructiveHint", True),
                        "idempotentHint": getattr(annotations, "idempotentHint", False),
                        "openWorldHint": getattr(annotations, "openWorldHint", True),
                    }
                
                # Extract parameters
                if hasattr(tool, "inputSchema") and tool.inputSchema:
                    schema = tool.inputSchema
                    if isinstance(schema, dict):
                        properties = schema.get("properties", {})
                        required = schema.get("required", [])
                        
                        for param_name, param_info in properties.items():
                            if isinstance(param_info, dict):
                                tool_details["parameters"].append({
                                    "name": param_name,
                                    "type": param_info.get("type", "unknown"),
                                    "description": param_info.get("description", "No description"),
                                    "required": param_name in required
                                })
                
                self.generate_function_signature(tool_details)
                
                # Generate example usage
                self.generate_example_usage(tool_details)
                
                # Determine complexity
                param_count = len(tool_details["parameters"])
                if param_count == 0:
                    tool_details["complexity"] = "simple"
                elif param_count <= 3:
                    tool_details["complexity"] = "moderate"
                else:
                    tool_details["complexity"] = "complex"
                
                self.results["tools"].append(tool_details)
                
        except Exception as e:
            error_msg = f"Failed to analyze tools: {e}"
            self.log(error_msg)
            self.results["errors"].append(error_msg)

    def generate_function_signature(self, tool_details):
        """Generate function signature for the tool."""
        if not tool_details["parameters"]:
            signature = f"{tool_details['name']}()"
        else:
            param_strings = []
            for param in tool_details["parameters"]:
                if param["required"]:
                    param_strings.append(f"{param['name']}: {param['type']}")
                else:
                    param_strings.append(f"{param['name']}: {param['type']} = None")
            
            signature = f"{tool_details['name']}({', '.join(param_strings)})"
        
        tool_details["function_signature"] = signature

    def generate_example_usage(self, tool_details):
        """Generate example usage for the tool."""
        example = {}
        for param in tool_details["parameters"]:
            if param["required"]:
                param_type = param["type"]
                param_name = param["name"].lower()
                
                if param_type == "string":
                    if "content" in param_name or "text" in param_name:
                        example[param["name"]] = "example_content"
                    elif "name" in param_name:
                        example[param["name"]] = "example_name"
                    elif "description" in param_name:
                        example[param["name"]] = "example description"
                    else:
                        desc = param['description'][:10].replace(' ', '_')
                        example[param["name"]] = f"example_{desc}"
                elif param_type in ["number", "integer"]:
                    example[param["name"]] = 123
                elif param_type == "boolean":
                    example[param["name"]] = True
                elif param_type == "array":
                    example[param["name"]] = ["item1", "item2"]
                elif param_type == "object":
                    example[param["name"]] = {"key": "value"}
                else:
                    example[param["name"]] = "example_value"
        
        if example:
            tool_details["example_usage"] = example

    async def analyze_prompts(self):
        """Analyze prompts."""
        self.log("Analyzing prompts...")
        
        try:
            result = await self.session.list_prompts()
            if not hasattr(result, "prompts") or not result.prompts:
                self.log("No prompts available")
                return
            
            self.log(f"Found {len(result.prompts)} prompts")
            
            for prompt in result.prompts:
                prompt_details = {
                    "name": prompt.name,
                    "title": getattr(prompt, "title", None),  # MCP Spec 2025-11-25
                    "description": getattr(prompt, "description", "No description"),
                    "icons": getattr(prompt, "icons", []),  # MCP Spec 2025-11-25
                    "arguments": [],
                    "full_content": None
                }
                
                # Extract arguments
                if hasattr(prompt, "arguments") and prompt.arguments:
                    for arg in prompt.arguments:
                        prompt_details["arguments"].append({
                            "name": arg.name,
                            "description": getattr(arg, "description", "No description"),
                            "required": getattr(arg, "required", False)
                        })
                
                # Try to get full prompt content
                await self.get_prompt_content(prompt, prompt_details)
                
                self.results["prompts"].append(prompt_details)
                
        except Exception as e:
            # Server doesn't implement prompts capability
            info_msg = f"Server does not implement prompts capability: {e}"
            self.log(info_msg)
            # Don't add to errors since this is expected behavior for some servers

    async def get_prompt_content(self, prompt, prompt_details):
        """Get full prompt content."""
        try:
            # Try with empty arguments first
            result = await self.session.get_prompt(prompt.name, {})
            prompt_details["full_content"] = self.format_prompt_content(result)
        except Exception as e:
            # If empty args failed, try with sample arguments
            if "required" in str(e).lower():
                try:
                    sample_args = self.generate_sample_args(prompt_details["arguments"])
                    if sample_args:
                        result = await self.session.get_prompt(prompt.name, sample_args)
                        prompt_details["full_content"] = self.format_prompt_content(result)
                except Exception:
                    pass  # Keep trying other methods

    def generate_sample_args(self, arguments):
        """Generate sample arguments for testing."""
        sample_args = {}
        for arg in arguments:
            if arg["required"]:
                arg_name = arg["name"].lower()
                if "content" in arg_name or "text" in arg_name:
                    sample_args[arg["name"]] = "sample content"
                elif "name" in arg_name:
                    sample_args[arg["name"]] = "sample_name"
                elif "description" in arg_name:
                    sample_args[arg["name"]] = "sample description"
                else:
                    sample_args[arg["name"]] = "sample_value"
        return sample_args if sample_args else None

    def format_prompt_content(self, prompt_result):
        """Format prompt content."""
        content_info = {
            "description": getattr(prompt_result, 'description', None),
            "messages": []
        }
        
        if hasattr(prompt_result, 'messages') and prompt_result.messages:
            for msg in prompt_result.messages:
                message_info = {
                    "role": getattr(msg, 'role', 'unknown'),
                    "content": []
                }
                
                if hasattr(msg, 'content') and msg.content:
                    if isinstance(msg.content, list):
                        for content_item in msg.content:
                            if hasattr(content_item, 'type'):
                                if content_item.type == 'text':
                                    message_info["content"].append({
                                        "type": "text",
                                        "text": getattr(content_item, 'text', str(content_item))
                                    })
                                else:
                                    message_info["content"].append({
                                        "type": content_item.type,
                                        "data": str(content_item)
                                    })
                    else:
                        message_info["content"].append({
                            "type": "text",
                            "text": str(msg.content)
                        })
                
                content_info["messages"].append(message_info)
        
        return content_info

    async def analyze_resources(self):
        """Analyze resources."""
        self.log("Analyzing resources...")
        
        try:
            result = await self.session.list_resources()
            if not hasattr(result, "resources") or not result.resources:
                self.log("No resources available")
                return
            
            self.log(f"Found {len(result.resources)} resources")
            
            for resource in result.resources:
                resource_details = {
                    "uri": resource.uri,
                    "name": getattr(resource, "name", None),
                    "title": getattr(resource, "title", None),  # MCP Spec 2025-11-25
                    "description": getattr(resource, "description", "No description"),
                    "mime_type": getattr(resource, "mimeType", None),
                    "size": getattr(resource, "size", None),  # MCP Spec 2025-11-25
                    "icons": getattr(resource, "icons", []),  # MCP Spec 2025-11-25
                    "annotations": {},  # MCP Spec 2025-11-25
                }

                # Extract resource annotations - MCP Spec 2025-11-25
                if hasattr(resource, "annotations") and resource.annotations:
                    annotations = resource.annotations
                    resource_details["annotations"] = {
                        "audience": getattr(annotations, "audience", []),
                        "priority": getattr(annotations, "priority", None),
                        "lastModified": getattr(annotations, "lastModified", None),
                    }

                self.results["resources"].append(resource_details)
                
        except Exception as e:
            # Server doesn't implement resources capability
            info_msg = f"Server does not implement resources capability: {e}"
            self.log(info_msg)
            # Don't add to errors since this is expected behavior for some servers

    async def scan(self):
        """Main scanning function."""
        self.log(f"Starting MCP scan of {self.target}")
        
        if self.target.startswith("http"):
            endpoints = self.discover_endpoints()
            if not endpoints:
                return self.results
            
            # Test each discovered endpoint
            last_error = None
            success = False
            
            for endpoint_info in self.results["endpoints"]:
                url = endpoint_info["url"]
                transport_type = endpoint_info["type"]
                
                self.log(f"Analyzing endpoint: {url} ({transport_type})")
                try:
                    await self.connect_and_analyze(url, transport_type)
                    success = True
                    break  # Successfully connected to one endpoint
                except Exception as e:
                    self.log(f"Failed to analyze {url}: {e}")
                    last_error = f"Endpoint {url} failed: {e}"
            
            # Only add error if no endpoint succeeded
            if not success and last_error:
                self.results["errors"].append(last_error)
        else:
            await self.connect_and_analyze(self.target)
        
        return self.results


async def scan_mcp_server(target: str, token: Optional[str] = None, 
                         timeout: float = 10.0, verbose: bool = False,
                         spinner_callback: Optional[callable] = None):
    """
    Convenience function to scan an MCP server.
    
    Args:
        target: MCP server target (URL or stdio command)
        token: Optional authentication token
        timeout: Connection timeout in seconds
        verbose: Enable verbose logging
        spinner_callback: Optional callback function to update spinner text
    
    Returns:
        dict: Scan results
    """
    scanner = MCPScanner(target=target, token=token, timeout=timeout, 
                        verbose=verbose, spinner_callback=spinner_callback)
    return await scanner.scan()