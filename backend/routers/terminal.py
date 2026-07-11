import os
import signal
import json
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import config
import database
from routers.auth import get_valid_session

router = APIRouter(tags=["terminal"])

try:
    import pwd
except ImportError:
    pwd = None

try:
    import pty
    import fcntl
    import termios
    import struct
    TERMINAL_BACKEND_AVAILABLE = True
except ImportError:
    pty = None
    fcntl = None
    termios = None
    struct = None
    TERMINAL_BACKEND_AVAILABLE = False


@router.websocket("/ws/terminal")
async def websocket_terminal(websocket: WebSocket):
    """Browser terminal over WebSocket with PTY (operator/admin)."""
    session_id = websocket.cookies.get(config.SESSION_COOKIE_NAME)
    session = get_valid_session(session_id)

    if not session:
        await websocket.close(code=4401, reason="Not authenticated")
        return

    role_rank = config.ROLE_ORDER.get(session.get("role", ""), 0)
    if role_rank < config.ROLE_ORDER["operator"]:
        await websocket.close(code=4403, reason="operator role required")
        return

    if not TERMINAL_BACKEND_AVAILABLE:
        await websocket.close(code=4403, reason="Web terminal is not supported on this OS")
        return

    await websocket.accept()

    if (websocket.query_params.get("protocol") or "").strip().lower() == "v2":
        try:
            await websocket.send_text(config.TERMINAL_PROTOCOL_V2_MARKER)
        except Exception:
            pass

    pid = None
    master_fd = None

    try:
        pid, master_fd = pty.fork()

        if pid == 0:
            shell = os.environ.get("SHELL") or "/bin/bash"
            if not os.path.exists(shell):
                shell = "/bin/sh"
            os.execvp(shell, [shell, "-i"])

        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        def set_pty_window_size(rows: int, cols: int):
            safe_rows = max(5, min(200, int(rows)))
            safe_cols = max(20, min(500, int(cols)))
            winsize = struct.pack("HHHH", safe_rows, safe_cols, 0, 0)
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)

        try:
            set_pty_window_size(24, 80)
        except Exception:
            pass

        database.log_audit(session["username"], "terminal_open", "Opened web terminal session")

        async def pty_to_websocket():
            while True:
                try:
                    data = os.read(master_fd, 4096)
                    if not data:
                        break
                    await websocket.send_text(data.decode("utf-8", errors="replace"))
                except BlockingIOError:
                    await asyncio.sleep(0.02)
                except OSError:
                    break

        async def websocket_to_pty():
            while True:
                data = await websocket.receive_text()
                if master_fd is None:
                    break

                payload = None
                try:
                    payload = json.loads(data)
                except Exception:
                    payload = None

                if isinstance(payload, dict):
                    message_type = str(payload.get("type", "")).strip().lower()

                    if message_type == "resize":
                        try:
                            rows = int(payload.get("rows", 24))
                            cols = int(payload.get("cols", 80))
                            set_pty_window_size(rows, cols)
                            if pid:
                                try:
                                    os.kill(pid, signal.SIGWINCH)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        continue

                    if message_type == "input":
                        input_data = payload.get("data", "")
                        if isinstance(input_data, str) and input_data:
                            os.write(master_fd, input_data.encode("utf-8", errors="ignore"))
                        continue

                if data:
                    os.write(master_fd, data.encode("utf-8", errors="ignore"))

        await asyncio.gather(pty_to_websocket(), websocket_to_pty())

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(f"\r\n[terminal error] {str(e)}\r\n")
        except Exception:
            pass
    finally:
        if master_fd is not None:
            try:
                os.close(master_fd)
            except Exception:
                pass

        if pid:
            try:
                os.kill(pid, signal.SIGHUP)
            except Exception:
                pass

        database.log_audit(session["username"], "terminal_close", "Closed web terminal session")
