import requests
import sqlite3
import hashlib
import hmac

# create admin user
conn = sqlite3.connect('users.db')
cur = conn.cursor()
# ... wait, I can just write a quick script to test the python function directly!
