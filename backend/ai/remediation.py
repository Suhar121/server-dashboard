# ai/remediation.py
"""Auto-remediation triggers integrated with dashboard monitoring loop.

These functions are called by main.py's existing monitoring endpoints
(/system, /ports) to trigger AI analysis when threshold conditions are met.
"""

import os
import time
import asyncio
from .guardrails import check_remediation_rate_limit

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
AI_AUTO_REMEDIATION = os.getenv("AI_AUTO_REMEDIATION", "false").lower() in {"1", "true", "yes"}


def should_remediate() -> bool:
    return AI_AUTO_REMEDIATION and GEMINI_API_KEY and GEMINI_API_KEY != "YOUR_KEY"


def trigger_remediation(session_id: str, trigger: str, context: dict, callback):
    """Trigger async AI analysis. callback(analysis_dict) is called with results.

    Only triggers if rate limit allows and AI_AUTO_REMEDIATION=true.
    """
    if not should_remediate():
        return
    if not check_remediation_rate_limit(session_id):
        return  # Silently skip if rate limited

    async def run():
        from .gemini_client import GeminiChat
        session_user = {"role": "admin"}
        chat = GeminiChat(session_user)
        analysis = await chat.analyze(trigger, context)
        callback(analysis)

    asyncio.create_task(run())


# ─── Trigger hooks (called from main.py monitoring) ─────────────────────────

def on_port_down(port: int, session_id: str | None = None):
    """Called when a pinned port becomes unreachable."""
    if not should_remediate():
        return
    context = {"port": port, "previous_state": "up"}
    trigger_remediation(
        session_id or "system",
        "port_down",
        context,
        lambda a: None,
    )


def on_cpu_alert(threshold: float, current_cpu: float, session_id: str | None = None):
    """Called when CPU exceeds alert threshold."""
    if not should_remediate():
        return
    context = {"threshold": threshold, "current_cpu": current_cpu}
    trigger_remediation(session_id or "system", "cpu_spike", context, lambda a: None)
