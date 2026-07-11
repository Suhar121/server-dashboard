# ai/gemini_client.py
"""Gemini API client with function calling support."""

import os
import time
from typing import AsyncGenerator

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    genai = None

from .models import AIChatRequest
from .tools import get_tool_schemas, execute_tool, TOOLS
from .guardrails import create_pending_action, get_pending_action

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Role display names for the AI
ROLE_DESCRIPTIONS = {
    "viewer": "read-only dashboard access",
    "operator": "read access + ability to start/stop services, use terminal, manage todos",
    "admin": "full access including user management, alert rules, file manager",
}


class GeminiChat:
    _configured = False

    @classmethod
    def configure(cls):
        if cls._configured:
            return
        if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_KEY":
            cls._configured = True
            return
        if GEMINI_AVAILABLE:
            genai.configure(api_key=GEMINI_API_KEY)
            cls._configured = True

    def __init__(self, session_user: dict):
        self.user = session_user
        self.configure()
        self.model_name = GEMINI_MODEL

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

    def _tool_to_gemini_func(self, tool: dict) -> dict:
        return {
            "name": tool["name"],
            "description": tool["description"],
            "parameters": tool["parameters"],
        }

    @staticmethod
    def _extract_text(response) -> str | None:
        """Safely extract text from a Gemini response, ignoring function_call parts."""
        try:
            if not response.candidates:
                return None
            parts = response.candidates[0].content.parts
            text_parts = [p.text for p in parts if hasattr(p, 'text') and p.text]
            return "\n".join(text_parts) if text_parts else None
        except Exception:
            return None

    @staticmethod
    def _has_function_calls(response) -> bool:
        """Check if response contains function calls."""
        try:
            return bool(response.candidates and
                        response.candidates[0].content.parts and
                        any(hasattr(p, 'function_call') and p.function_call
                            for p in response.candidates[0].content.parts))
        except Exception:
            return False

    @staticmethod
    def _get_function_calls(response) -> list:
        """Extract function_call objects from a response safely."""
        calls = []
        try:
            if response.candidates and response.candidates[0].content.parts:
                for p in response.candidates[0].content.parts:
                    if hasattr(p, 'function_call') and p.function_call:
                        calls.append(p.function_call)
        except Exception:
            pass
        return calls

    async def chat_stream(self, message: str) -> AsyncGenerator[dict, None]:
        """Stream chat response as dicts with type tags."""
        if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_KEY":
            yield {"type": "error", "message": "Gemini API key not configured. Set GEMINI_API_KEY in .env"}
            return

        if not GEMINI_AVAILABLE:
            yield {"type": "error", "message": "google-generativeai package not installed. Run: pip install google-generativeai"}
            return

        try:
            model = genai.GenerativeModel(
                model_name=self.model_name,
                system_instruction=self._build_system_prompt(),
                tools=[{"function_declarations": [self._tool_to_gemini_func(t) for t in TOOLS]}],
            )
            chat = model.start_chat()

            response = chat.send_message(message, stream=False)

            max_rounds = 10
            for _ in range(max_rounds):
                func_calls = self._get_function_calls(response)
                if not func_calls:
                    text = self._extract_text(response)
                    if text:
                        yield {"type": "text", "content": text}
                    break

                function_responses = []
                for fc in func_calls:
                    tool_name = fc.name
                    tool_args = dict(fc.args) if hasattr(fc, 'args') else {}
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
                        function_responses.append(
                            genai.protos.Part(function_response=genai.protos.FunctionResponse(
                                name=tool_name,
                                response={"result": str(result)}
                            ))
                        )

                if not function_responses:
                    break

                response = chat.send_message(
                    genai.protos.Content(parts=function_responses),
                    stream=False,
                )

            yield {"type": "done", "summary": "Chat complete"}

        except Exception as e:
            yield {"type": "error", "message": f"AI error: {str(e)}"}

    async def analyze(self, trigger: str, context: dict) -> dict:
        """Run AI diagnostic analysis for auto-remediation."""
        if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_KEY":
            return {"analysis": "AI not configured", "recommended_action": None, "auto_executable": False}

        if not GEMINI_AVAILABLE:
            return {"analysis": "AI package not installed", "recommended_action": None, "auto_executable": False}

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
        model = genai.GenerativeModel(model_name=self.model_name)
        response = model.generate_content(prompt)
        return {
            "analysis": self._extract_text(response) or "No analysis generated",
            "recommended_action": context,
            "auto_executable": False,
        }