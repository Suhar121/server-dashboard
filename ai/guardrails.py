# ai/guardrails.py
"""Rate limiting and pending action confirmation queue."""

import time
import uuid
from collections import defaultdict
from .models import PendingAction

# Rate limiting: session_id -> list of timestamps
_chat_rate_limit: dict[str, list[float]] = defaultdict(list)
_chat_rate_limit_count = 10  # per minute
_chat_rate_limit_window = 60.0  # seconds

# Remediation rate limiting
_remediation_rate_limit: dict[str, list[float]] = defaultdict(list)
_remediation_rate_limit_count = 3
_remediation_rate_limit_window = 60.0

# Pending confirmation actions: action_id -> PendingAction
_pending_actions: dict[str, PendingAction] = {}

# Pending action TTL in seconds
PENDING_ACTION_TTL = 60.0


def check_chat_rate_limit(session_id: str) -> bool:
    """Returns True if within rate limit, False if exceeded."""
    now = time.time()
    window = _chat_rate_limit[session_id]
    # Remove old entries
    window[:] = [t for t in window if now - t < _chat_rate_limit_window]
    if len(window) >= _chat_rate_limit_count:
        return False
    window.append(now)
    return True


def check_remediation_rate_limit(session_id: str) -> bool:
    """Returns True if within rate limit for auto-remediation."""
    now = time.time()
    window = _remediation_rate_limit[session_id]
    window[:] = [t for t in window if now - t < _remediation_rate_limit_window]
    if len(window) >= _remediation_rate_limit_count:
        return False
    window.append(now)
    return True


def create_pending_action(tool: str, params: dict) -> str:
    """Create a pending confirmation action. Returns action_id."""
    action_id = str(uuid.uuid4())
    _pending_actions[action_id] = PendingAction(
        action_id=action_id,
        tool=tool,
        params=params,
        created_at=time.time(),
    )
    return action_id


def get_pending_action(action_id: str) -> PendingAction | None:
    """Get and validate a pending action (checks TTL)."""
    action = _pending_actions.get(action_id)
    if not action:
        return None
    if time.time() - action.created_at > PENDING_ACTION_TTL:
        _pending_actions.pop(action_id, None)
        return None
    return action


def confirm_action(action_id: str) -> bool:
    """Mark an action as confirmed. Returns True if found and confirmed."""
    action = _pending_actions.pop(action_id, None)
    if action:
        action.confirmed = True
        return True
    return False


def deny_action(action_id: str) -> bool:
    """Remove a pending action without executing. Returns True if found."""
    return _pending_actions.pop(action_id, None) is not None


def clear_expired_actions():
    """Remove all expired pending actions."""
    now = time.time()
    expired = [aid for aid, a in _pending_actions.items() if now - a.created_at > PENDING_ACTION_TTL]
    for aid in expired:
        _pending_actions.pop(aid, None)