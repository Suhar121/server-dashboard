import asyncio
import datetime
import httpx
import database

async def send_telegram_notification(bot_token: str, chat_id: str, text: str) -> dict:
    """Sends an HTML-formatted Telegram message via Bot API."""
    if not bot_token or not chat_id:
        raise ValueError("Telegram Bot Token and Chat ID are required.")

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML"
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.post(url, json=payload)
        data = res.json()
        if not data.get("ok"):
            err_msg = data.get("description", "Failed to send Telegram message")
            raise RuntimeError(err_msg)
        return data

async def trigger_alert(monitor: dict, new_status: str, previous_status: str, details: str = None):
    """Dispatches a Telegram downtime or recovery alert for a status transition."""
    # Check if Telegram alerts are disabled per monitor
    if monitor.get("telegramEnabled") is False:
        print(f"[Telegram] Skipped for [{monitor.get('name')}] (disabled per monitor)")
        return

    settings = database.db_get_telegram_settings()
    if not settings.get("enabled"):
        return

    bot_token = monitor.get("telegramBotToken") or settings.get("botToken")
    chat_id = monitor.get("telegramChatId") or settings.get("chatId")

    if not bot_token or not chat_id:
        return

    is_down = (new_status == "down")
    icon = "🔴" if is_down else "🟢"
    status_text = "DOWN" if is_down else "UP"
    target_text = monitor.get("url") or monitor.get("target") or monitor.get("type", "service")

    timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    message = (
        f"<b>{icon} [{monitor.get('name')}] is {status_text}</b>\n\n"
        f"<b>Service:</b> {monitor.get('tag') or monitor.get('name')}\n"
        f"<b>Target:</b> <code>{target_text}</code>\n"
        f"<b>Time:</b> {timestamp_str}\n"
    )
    if details:
        message += f"<b>Details:</b> <i>{details}</i>"

    try:
        await send_telegram_notification(bot_token, chat_id, message.strip())
        print(f"[Telegram] Alert sent for [{monitor.get('name')}] to {chat_id} ({status_text})")
    except Exception as e:
        print(f"[Telegram] Failed to send alert for [{monitor.get('name')}]: {e}")
