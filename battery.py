import psutil
import time
import requests
import os

# Change if needed
API_URL = "http://127.0.0.1:8000/notify"
LOGIN_URL = "http://127.0.0.1:8000/auth/login"


def load_env_file(path: str = ".env"):
    if not os.path.exists(path):
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except Exception as e:
        print("Failed to load .env:", e)


load_env_file()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

LOW_BATTERY_LEVEL = 20  # %

session = requests.Session()


def ensure_authenticated():
    try:
        response = session.post(
            LOGIN_URL,
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            timeout=10,
        )
        return response.ok
    except Exception as e:
        print("Login error:", e)
        return False

while True:
    battery = psutil.sensors_battery()

    if battery is None:
        print("Battery info not available")
        break

    percent = battery.percent
    plugged = battery.power_plugged

    print(f"Battery: {percent}% | Charging: {plugged}")

    # Send alert only when battery is low and not charging
    if percent <= LOW_BATTERY_LEVEL and not plugged:
        try:
            response = session.post(
                API_URL,
                json={"msg": f"⚠️ Battery low: {percent}%"},
                timeout=10,
            )

            if response.status_code == 401:
                if ensure_authenticated():
                    response = session.post(
                        API_URL,
                        json={"msg": f"⚠️ Battery low: {percent}%"},
                        timeout=10,
                    )

            print("Alert sent:", response.json())
        except Exception as e:
            print("Error sending alert:", e)

        time.sleep(300)  # wait 5 min to avoid spam
    else:
        time.sleep(60)  # check every 1 min
