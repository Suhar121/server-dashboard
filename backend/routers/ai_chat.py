import json
import sqlite3
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import config
import database
from routers.auth import get_current_user, require_role

# Import AI modules
try:
    from ai.nvidia_client import NvidiaChat
    from ai.gemini_client import GeminiChat
except ImportError:
    NvidiaChat = None
    GeminiChat = None

from ai.models import AIChatRequest, AIActionConfirmation, AIAnalyzeRequest
from ai.guardrails import check_chat_rate_limit, get_pending_action, confirm_action, deny_action

router = APIRouter(prefix="/ai", tags=["ai"])


def _get_ai_chat(user: dict):
    if config.AI_PROVIDER == "nvidia" and config.NVIDIA_API_KEY:
        if NvidiaChat is None:
            raise HTTPException(status_code=501, detail="Nvidia client not loaded")
        return NvidiaChat(user)
    
    if GeminiChat is None:
        raise HTTPException(status_code=501, detail="Gemini client not loaded")
    return GeminiChat(user)


@router.post("/chat")
async def ai_chat(
    request: AIChatRequest,
    user: dict = Depends(get_current_user),
):
    if not check_chat_rate_limit(user["session_id"]):
        raise HTTPException(429, detail="Rate limit exceeded. Try again in a minute.")

    image_patterns = ['data:image', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp']
    if any(p in request.message.lower() for p in image_patterns):
        async def error_stream():
            yield f"data: {json.dumps({'type': 'error', 'message': 'Image input is not supported. Please describe what you need instead.'})}\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    async def event_stream():
        chat = _get_ai_chat(user)
        async for event in chat.chat_stream(request.message):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )


@router.post("/confirm-action")
async def ai_confirm_action(
    data: AIActionConfirmation,
    user: dict = Depends(get_current_user),
):
    if data.approved:
        action = get_pending_action(data.action_id)
        if not action:
            return {"executed": False, "error": "Action not found or expired"}
        from ai.tools import execute_tool
        result = execute_tool(action.tool, user, action.params)
        confirm_action(data.action_id)
        database.log_audit(user["username"], "ai_action", f"AI action approved: {action.tool} with {action.params}")
        return {"executed": True, "result": result}
    else:
        deny_action(data.action_id)
        return {"executed": False, "denied": True}


@router.get("/status")
async def ai_status(user: dict = Depends(get_current_user)):
    if config.AI_PROVIDER == "nvidia":
        has_key = bool(config.NVIDIA_API_KEY)
        return {
            "available": has_key,
            "provider": "nvidia",
            "model": config.NVIDIA_MODEL if has_key else None,
            "configured": has_key,
        }
    has_key = bool(config.GEMINI_API_KEY and config.GEMINI_API_KEY != "YOUR_KEY")
    return {
        "available": has_key,
        "provider": "gemini",
        "model": config.GEMINI_MODEL if has_key else None,
        "configured": has_key,
    }


@router.post("/analyze")
async def ai_analyze(
    data: AIAnalyzeRequest,
    user: dict = Depends(require_role("operator")),
):
    chat = _get_ai_chat(user)
    analysis = await chat.analyze(data.trigger, data.context)
    return analysis


@router.get("/conversations")
async def ai_conversations(
    user: dict = Depends(get_current_user),
    limit: int = Query(default=50, le=100),
):
    conn = sqlite3.connect(database.USERS_DB_PATH)
    cursor = conn.execute(
        "SELECT id, action, details, timestamp FROM audit_logs "
        "WHERE action LIKE 'ai_%' AND details LIKE ? "
        "ORDER BY timestamp DESC LIMIT ?",
        (f"%{user['session_id']}%", limit),
    )
    rows = cursor.fetchall()
    conn.close()
    return {"conversations": [{"id": r[0], "action": r[1], "details": r[2], "timestamp": r[3]} for r in rows]}
