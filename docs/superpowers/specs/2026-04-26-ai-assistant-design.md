# AI Assistant for DevOps Dashboard — Design Spec

## Context

User wants to integrate an AI assistant into the existing DevOps Control Panel (FastAPI + SQLite + vanilla HTML/JS). The assistant should handle Natural Language Commands, Smart Alerts & Diagnostics, and Auto-Remediation within safety guardrails. Gemini API is the backend. Full dashboard context is available to the AI.

---

## 1. Architecture

```
Browser (Floating Chat Panel)
       ↓  POST /ai/chat (SSE streaming)
FastAPI Backend
       ↓
Gemini API (function calling, gemini-2.0-flash)
       ↓
AI Tools (mirror existing dashboard APIs)
       ↓
Action Execution via existing endpoints (with guardrails)
       ↓
Streaming response → Browser Panel
```

**Module location:** `ai/` directory in project root, imported by `main.py`.

---

## 2. API Endpoints

### `POST /ai/chat`
- **Auth:** Requires active session (any role).
- **Request:** `{ "message": "...", "stream": true }`
- **Response:** `text/event-stream`
  - `data: {"type": "text", "content": "..."}` — streamed text
  - `data: {"type": "tool_call", "tool": "...", "params": {...}}` — AI requesting tool
  - `data: {"type": "tool_result", "tool": "...", "result": {...}}` — tool result returned to AI
  - `data: {"type": "action_pending", "action": {...}, "action_id": "..."}` — needs user confirm
  - `data: {"type": "done", "summary": "..."}` — complete
  - `data: {"type": "error", "message": "..."}` — error

### `POST /ai/analyze`
- **Auth:** Admin or operator.
- **Request:** `{ "trigger": "port_down | cpu_spike | service_crash | docker_stop", "context": {...} }`
- **Response:** `{ "analysis": "...", "recommended_action": {...}, "auto_executable": bool }`
- Fires AI diagnostic in background when auto-remediation triggers fire.

### `GET /ai/status`
- **Auth:** Any role.
- **Response:** `{ "available": true, "model": "gemini-2.0-flash", "latency_ms": 123 }`

### `POST /ai/confirm-action`
- **Auth:** Any role (must match session that initiated the action).
- **Request:** `{ "action_id": "...", "approved": true }`
- **Response:** `{ "executed": true, "result": "..." }`

### `GET /ai/conversations`
- **Auth:** Any role (own conversations only).
- **Response:** Paginated list of conversation history for the current session.

---

## 3. Gemini Integration

- **SDK:** `google-generativeai` Python package.
- **Model:** Configurable via `GEMINI_MODEL` env var (default: `gemini-2.0-flash`).
- **API Key:** From `GEMINI_API_KEY` env var.
- **Function Calling:** Gemini's native tool support with `tools` parameter.
- **Streaming:** Use SDK's streaming generate_content for chat responses.
- **System Prompt:** Includes dashboard role, current user role, available tools, and safety guidelines.

---

## 4. AI Tools (Function Schemas)

All tools mirror existing API endpoints and are gated by the user's role.

| Tool Name | Parameters | Role Required | Auto? |
|-----------|------------|---------------|-------|
| `get_system_metrics` | `{}` | viewer | Yes |
| `get_open_ports` | `{}` | viewer | Yes |
| `get_port_details` | `{"port": int}` | viewer | Yes |
| `get_docker_status` | `{}` | viewer | Yes |
| `get_services` | `{}` | viewer | Yes |
| `get_service_logs` | `{"service_name": str}` | operator | Yes |
| `start_service` | `{"service_name": str}` | operator | Confirm |
| `stop_service` | `{"service_name": str}` | operator | Confirm |
| `restart_service` | `{"service_name": str}` | operator | Confirm |
| `get_todos` | `{}` | viewer | Yes |
| `add_todo` | `{"text": str}` | operator | Confirm |
| `toggle_todo` | `{"todo_id": int}` | operator | Confirm |
| `get_alert_rules` | `{}` | admin | Yes |
| `create_alert_rule` | `{"metric": str, "threshold": float}` | admin | Confirm |
| `get_recent_events` | `{"limit": int}` | viewer | Yes |
| `run_saved_command` | `{"command_id": int}` | operator | Confirm |
| `check_port_health` | `{"port": int}` | viewer | Yes |

---

## 5. Auto-Remediation Triggers

Background tasks use the existing monitoring loop (already polling every ~3s). When a trigger condition is met, `POST /ai/analyze` is called asynchronously.

| Trigger | Condition | Default Behavior |
|---------|-----------|------------------|
| `port_down` | Pinned port becomes unreachable | AI diagnoses + offers restart |
| `cpu_spike` | CPU > threshold (from alert rules) | AI alerts + suggests action |
| `service_crash` | Managed service exits unexpectedly | AI reads logs + proposes fix |
| `docker_stop` | Docker container stops | AI diagnoses + offers restart |

Auto-remediation toggle: `AI_AUTO_REMEDIATION=true` env var.

---

## 6. Guardrails

### Role Enforcement
- Every tool checks `require_role()` against current session user.
- AI is told its effective role in system prompt — it cannot request actions above its role.

### Confirmation Queue
- Sensitive tools (start/stop/restart service, add todo, create alert rule) return `action_pending` event.
- User sees inline "Approve / Deny" buttons in the chat panel.
- Pending actions expire after 60 seconds.
- `action_id` maps to a UUID stored in-memory with full context.

### Audit Logging
- All AI-initiated actions logged to `audit_logs` table with `initiated_by: "ai"` and full prompt stored.
- AI conversation history also logged (without tool result payloads to save space).

### Rate Limiting
- 10 AI chat calls per minute per session.
- 3 auto-remediation analyses per minute per session.
- Returns `429 Too Many Requests` with retry-after header.

### Command Safety
- `run_saved_command` only executes from the saved command library (template placeholders resolved server-side).
- Direct shell commands are NOT allowed via AI.
- File operations are NOT exposed to AI (too dangerous via natural language).

### No-file-ops via AI
- Explicitly excluded from function schemas. Users use the File Manager UI for file operations.

---

## 7. Chat UI — Floating Panel

### Position & Behavior
- Fixed to bottom-right corner of viewport.
- States: `collapsed` (chat bubble icon), `expanded` (full panel).
- Draggable within viewport bounds.
- Remembers position in `localStorage`.

### Visual Design
- Width: 380px, max-height: 600px.
- Matches existing dashboard theme (CSS variables).
- Header: "AI Assistant" title + collapse button + clear history button.
- Message list: user messages right-aligned (blue bg), AI messages left-aligned (dark bg).
- AI responses render markdown (bold, code blocks, lists).
- Tool calls show as inline cards: "🔧 Getting system metrics..." then result expandable.

### Components
- **Header bar:** Title, collapse chevron, trash icon (clear history).
- **Message list:** Scrollable, auto-scrolls to bottom on new message.
- **Input area:** Multi-line textarea (Shift+Enter for newline, Enter to send), send button.
- **Confirmation cards:** Inline approval buttons for pending actions.
- **Loading indicator:** Animated dots during AI thinking/tool execution.

### Persistence
- Conversation history stored in `localStorage` as JSON array.
- Key: `ai_chat_history_{session_id}`.
- Max 50 messages per session (FIFO eviction).
- "Clear history" wipes localStorage entry.

### Streaming Display
- Text arrives word-by-word, rendered in real-time in the AI message bubble.
- Tool calls show a "thinking" indicator, then reveal result when complete.

---

## 8. Configuration (`.env`)

```env
# Gemini AI
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.0-flash

# AI Behavior
AI_AUTO_REMEDIATION=true
AI_CONFIRM_SENSITIVE=true
AI_RATE_LIMIT_PER_MIN=10
AI_MAX_CONVERSATION_MESSAGES=50
```

---

## 9. Database Schema

```sql
CREATE TABLE ai_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user', 'ai')),
    content TEXT NOT NULL,
    tools_used TEXT,  -- JSON array of tool names
    action_initiated TEXT,  -- JSON object of action details
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ai_conversations_session ON ai_conversations(session_id, created_at);
```

---

## 10. File Structure

```
d:\server-dashboard\
├── main.py                    # Add /ai/* endpoints, integrate ai module
├── index.html                 # Add floating chat panel
├── ai/
│   ├── __init__.py
│   ├── gemini_client.py       # Gemini API client (chat, function schemas)
│   ├── tools.py                # Tool definitions + RBAC enforcement
│   ├── guardrails.py           # Rate limiting, confirmation queue
│   ├── remediation.py          # Auto-remediation trigger handlers
│   └── models.py               # Pydantic request/response models
├── .env                       # Add GEMINI_API_KEY, GEMINI_MODEL, AI_* vars
└── users.db                   # Add ai_conversations table
```

---

## 11. Error Handling

| Error | Response |
|-------|----------|
| Gemini API unreachable | `{"type": "error", "message": "AI service unavailable. Try again."}` |
| Invalid API key | Log warning, return error, don't crash |
| Rate limit exceeded | `429` with `Retry-After: 60` |
| Session expired mid-chat | Return error, UI prompts re-login |
| Tool execution fails | Return error to AI, AI reformulates or apologizes |
| Confirmation timeout | Return `action_expired` to UI, clear from queue |

---

## 12. Testing Plan

1. **AI chat basic:** Send "What services are running?" → verify AI calls `get_services`, returns correct info.
2. **Role restriction:** Viewer role sends "Stop nginx" → AI says it can't do that.
3. **Confirmation flow:** Operator asks to start a service → pending card appears → approve → service starts.
4. **Auto-remediation:** Stop a pinned service externally → AI detects, analyzes, offers restart.
5. **Rate limit:** Spam 15 messages in 30s → 5 get 429 errors.
6. **Streaming:** Long response streams word-by-word in UI.
7. **History persistence:** Refresh page → chat history restored from localStorage.
