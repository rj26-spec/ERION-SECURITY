import sqlite3
import os

db1 = r'C:\Users\RAJALAXMI\OneDrive\Desktop\ERION CYBERGUARD\CyberGuard-Image-Detection\cyberguard_audit.db'
if os.path.exists(db1):
    conn = sqlite3.connect(db1)
    c = conn.cursor()
    # Find tables
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = c.fetchall()
    for table in tables:
        t_name = table[0]
        if t_name != 'sqlite_sequence':
            c.execute(f"DELETE FROM {t_name}")
    conn.commit()
    conn.close()
    print(f"Cleared {db1}")

db2 = r'C:\Users\RAJALAXMI\OneDrive\Desktop\ERION CYBERGUARD\mailguard\mailguard.db'
if os.path.exists(db2):
    conn = sqlite3.connect(db2)
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = c.fetchall()
    for table in tables:
        t_name = table[0]
        if t_name == 'users':
            # Remove duplicates for users if any based on email (or just leave it)
            pass
        elif t_name != 'sqlite_sequence':
            c.execute(f"DELETE FROM {t_name}")
    conn.commit()
    conn.close()
    print(f"Cleared {db2}")
