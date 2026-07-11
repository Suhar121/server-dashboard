# ai/nvidia_client.py
"""NVIDIA API client (OpenAI-compatible) with function calling support."""

import os
import json
from typing import AsyncGenerator

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    OpenAI = None

from .models import AIChatRequest
from .tools import get_tool_schemas, execute_tool, TOOLS
from .guardrails import create_pending_action, get_pending_action

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL", "z-ai/glm-5.1")
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")

ROLE_DESCRIPTIONS = {
    "viewer": "read-only dashboard access",
    "operator": "read access + ability to start/stop services, use terminal, manage todos",
    "admin": "full access including user management, alert rules, file manager",
}


class NvidiaChat:
    def __init__(self, session_user: dict):
        self.user = session_user
        self.model_name = NVIDIA_MODEL

    def _build_system_prompt(self) -> str:
        role = self.user.get("role", "viewer")
        role_desc = ROLE_DESCRIPTIONS.get(role, "read-only access")
        tools_list = "\n".join(
            f"- {t['name']}: {t['description']}" for t in TOOLS
        )
        return f"""You are an AI assistant inside a DevOps dashboard. The current user has the role '{role}' ({role_desc}).

Your capabilities via tools:
{tools_list}

Guidelines:
- Always use a tool if available rather than guessing data.
- If a tool fails, explain the error to the user and suggest next steps.
- For actions needing confirmation (auto_exec=False), describe what you will do and wait.
- Never make up port numbers, service names, or PIDs — always use tools to get real data.
- Keep responses concise but informative.
- Sensitive actions (start/stop/restart services, create alert rules) require user confirmation.
- You have read access to: system metrics, ports, Docker, services, todos, audit logs.
"""

    def _get_client(self):
        if not OPENAI_AVAILABLE:
            return None
        return OpenAI(
            base_url=NVIDIA_BASE_URL,
            api_key=NVIDIA_API_KEY,
        )

    def _build_tools_payload(self) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["parameters"],
                },
            }
            for t in TOOLS
        ]

    async def chat_stream(self, message: str) -> AsyncGenerator[dict, None]:
        if not NVIDIA_API_KEY:
            yield {"type": "error", "message": "NVIDIA API key not configured. Set NVIDIA_API_KEY in .env"}
            return

        if not OPENAI_AVAILABLE:
            yield {"type": "error", "message": "openai package not installed. Run: pip install openai"}
            return

        try:
            client = self._get_client()
            messages = [
                {"role": "system", "content": self._build_system_prompt()},
                {"role": "user", "content": message},
            ]

            max_rounds = 10
            for _ in range(max_rounds):
                response = client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    temperature=1,
                    top_p=1,
                    max_tokens=16384,
                    tools=self._build_tools_payload(),
                    stream=False,
                )

                choice = response.choices[0]
                assistant_msg = choice.message

                if assistant_msg.tool_calls:
                    messages.append(assistant_msg.model_dump())

                    for tc in assistant_msg.tool_calls:
                        tool_name = tc.function.name
                        try:
                            tool_args = json.loads(tc.function.arguments)
                        except json.JSONDecodeError:
                            tool_args = {}

                        yield {"type": "tool_call", "tool": tool_name, "params": tool_args}

                        result = execute_tool(tool_name, self.user, tool_args)
                        yield {"type": "tool_result", "tool": tool_name, "result": result}

                        tool_def = next((t for t in TOOLS if t["name"] == tool_name), None)
                        needs_confirm = tool_def and not tool_def["auto_exec"]

                        if needs_confirm:
                            action_id = create_pending_action(tool_name, tool_args)
                            yield {
                                "type": "action_pending",
                                "action_id": action_id,
                                "tool": tool_name,
                                "summary": f"Wants to {tool_name} with {tool_args}",
                            }
                        else:
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tc.id,
                                "content": json.dumps(result),
                            })
                else:
                    if assistant_msg.content:
                        yield {"type": "text", "content": assistant_msg.content}
                    break

            yield {"type": "done", "summary": "Chat complete"}

        except Exception as e:
            yield {"type": "error", "message": f"AI error: {str(e)}"}

    async def chat_stream_tokens(self, message: str) -> AsyncGenerator[dict, None]:
        if not NVIDIA_API_KEY:
            yield {"type": "error", "message": "NVIDIA API key not configured. Set NVIDIA_API_KEY in .env"}
            return

        if not OPENAI_AVAILABLE:
            yield {"type": "error", "message": "openai package not installed. Run: pip install openai"}
            return

        try:
            client = self._get_client()
            messages = [
                {"role": "system", "content": self._build_system_prompt()},
                {"role": "user", "content": message},
            ]

            max_rounds = 10
            for _ in range(max_rounds):
                stream = client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    temperature=1,
                    top_p=1,
                    max_tokens=16384,
                    tools=self._build_tools_payload(),
                    extra_body={
                        "chat_template_kwargs": {
                            "enable_thinking": True,
                            "clear_thinking": False,
                        }
                    },
                    stream=True,
                )

                collected_content = ""
                collected_tool_calls = {}

                for chunk in stream:
                    if not getattr(chunk, "choices", None):
                        continue
                    if len(chunk.choices) == 0:
                        continue
                    delta = chunk.choices[0].delta
                    if delta is None:
                        continue

                    reasoning = getattr(delta, "reasoning_content", None)
                    if reasoning:
                        yield {"type": "reasoning", "content": reasoning}

                    if getattr(delta, "content", None) is not None:
                        collected_content += delta.content
                        yield {"type": "token", "content": delta.content}

                    if getattr(delta, "tool_calls", None):
                        for tc_delta in delta.tool_calls:
                            idx = tc_delta.index
                            if idx not in collected_tool_calls:
                                collected_tool_calls[idx] = {
                                    "id": tc_delta.id or "",
                                    "name": tc_delta.function.name if tc_delta.function and tc_delta.function.name else "",
                                    "arguments": "",
                                }
                            if tc_delta.function and tc_delta.function.arguments:
                                collected_tool_calls[idx]["arguments"] += tc_delta.function.arguments
                            if tc_delta.id:
                                collected_tool_calls[idx]["id"] = tc_delta.id

                if collected_tool_calls:
                    tool_calls_list = sorted(collected_tool_calls.items())
                    for _, tc_info in tool_calls_list:
                        tool_name = tc_info["name"]
                        try:
                            tool_args = json.loads(tc_info["arguments"])
                        except json.JSONDecodeError:
                            tool_args = {}

                        yield {"type": "tool_call", "tool": tool_name, "params": tool_args}

                        result = execute_tool(tool_name, self.user, tool_args)
                        yield {"type": "tool_result", "tool": tool_name, "result": result}

                        tool_def = next((t for t in TOOLS if t["name"] == tool_name), None)
                        needs_confirm = tool_def and not tool_def["auto_exec"]

                        if needs_confirm:
                            action_id = create_pending_action(tool_name, tool_args)
                            yield {
                                "type": "action_pending",
                                "action_id": action_id,
                                "tool": tool_name,
                                "summary": f"Wants to {tool_name} with {tool_args}",
                            }
                        else:
                            messages.append({
                                "role": "assistant",
                                "content": collected_content or None,
                                "tool_calls": [
                                    {
                                        "id": tc_info["id"],
                                        "type": "function",
                                        "function": {
                                            "name": tc_info["name"],
                                            "arguments": tc_info["arguments"],
                                        },
                                    }
                                    for _, tc_info in tool_calls_list
                                ],
                            })
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tc_info["id"],
                                "content": json.dumps(result),
                            })
                else:
                    if collected_content:
                        yield {"type": "text", "content": collected_content}
                    break

            yield {"type": "done", "summary": "Chat complete"}

        except Exception as e:
            yield {"type": "error", "message": f"AI error: {str(e)}"}

    async def analyze(self, trigger: str, context: dict) -> dict:
        if not NVIDIA_API_KEY:
            return {"analysis": "AI not configured", "recommended_action": None, "auto_executable": False}

        if not OPENAI_AVAILABLE:
            return {"analysis": "openai package not installed", "recommended_action": None, "auto_executable": False}

        system_info = execute_tool("get_system_metrics", self.user, {})

        prompts = {
            "port_down": f"""A pinned port just went down.
Port: {context.get('port')}
Previous state: {context.get('previous_state', 'unknown')}
Current system metrics: {system_info}

Diagnose: Why might this port have gone down? Is it a service crash, network issue, or resource exhaustion?
Respond with: 1) Likely cause, 2) Immediate action to take, 3) Whether auto-restart is safe.""",

            "cpu_spike": f"""CPU alert triggered.
Threshold: {context.get('threshold')}%
Current CPU: {system_info.get('cpu_percent')}%
Top processes: {context.get('top_processes', 'unknown')}

Diagnose: What is causing the CPU spike? Suggest a remediation.""",

            "service_crash": f"""A managed service crashed.
Service: {context.get('service_name')}
Recent log lines: {context.get('log_lines', [])}

Diagnose: What does the crash log indicate? Propose a fix.""",

            "docker_stop": f"""A Docker container stopped unexpectedly.
Container: {context.get('container_name')} ({context.get('container_id')})
Status: {context.get('status')}

Diagnose: Why might it have stopped? Suggest restart or investigation steps.""",
        }

        prompt = prompts.get(trigger, "Analyze this situation and suggest actions.")
        try:
            client = self._get_client()
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a DevOps diagnostic assistant. Provide concise analysis."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.7,
                max_tokens=4096,
            )
            return {
                "analysis": response.choices[0].message.content or "No analysis generated",
                "recommended_action": context,
                "auto_executable": False,
            }
        except Exception as e:
            return {"analysis": f"AI error: {str(e)}", "recommended_action": None, "auto_executable": False}
