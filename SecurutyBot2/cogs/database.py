import sqlite3
import time
import datetime
import discord
from discord.ext import commands, tasks

# ==========================================
# DATABASE SETUP (SQLite)
# ==========================================
DB_FILE = "security_bot.db"
whitelist_cache = {}
config_cache = {}

DEFAULT_LOG_CHANNEL_ID = 1500828287964938381
DEFAULT_HONEYPOT_CHANNEL_ID = 1536412083535609966
DEFAULT_WHITELIST_ROLES = [
    1459142303921737936,
    1500441740929269863,
    1532420811850256494,
    1530943658600431787,
    1523319813621940315
]

ALLOWED_CONFIG_KEYS = {
    "log_channel_id", "malware_filter", "ai_filter", "strike_system", 
    "anti_nuke", "anti_mention", "phishing_api", "quarantine_role_id", 
    "voice_anti_raid", "enforce_permissions", "anti_dox", "honeypot_channel_id", 
    "self_bot", "webhook_guard", "auto_purge", "image_scanner",
    "verify_channel_id", "verify_role_id", "min_account_age_days", "ip_ban_guard",
    "anti_vpn", "ghost_ping_guard", "owner_pin", "anti_invite", "verify_domain",
    "suspect_scan", "global_panic"
}

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS whitelist (guild_id INTEGER, role_id INTEGER, role_name TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS warnings (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER, user_id INTEGER, reason TEXT, timestamp REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS guild_config (
                    guild_id INTEGER PRIMARY KEY, 
                    log_channel_id INTEGER, 
                    malware_filter INTEGER DEFAULT 1, 
                    ai_filter INTEGER DEFAULT 0, 
                    strike_system INTEGER DEFAULT 1,
                    anti_nuke INTEGER DEFAULT 1,
                    anti_mention INTEGER DEFAULT 1,
                    phishing_api INTEGER DEFAULT 1,
                    quarantine_role_id INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS quarantine (guild_id INTEGER, user_id INTEGER, original_roles TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS backups (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER, timestamp REAL, data TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS ip_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER, user_id INTEGER, ip_address TEXT, user_agent TEXT, timestamp REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS banned_ips (ip_address TEXT PRIMARY KEY, reason TEXT, timestamp REAL)''')
    conn.commit()
    
    # อัปเกรดฐานข้อมูลรองรับฟีเจอร์ใหม่
    columns = [
        ("anti_nuke", 1), ("anti_mention", 1), ("phishing_api", 1), ("quarantine_role_id", 0),
        ("voice_anti_raid", 1), ("enforce_permissions", 1), ("anti_dox", 1), ("honeypot_channel_id", 0),
        ("self_bot", 1), ("webhook_guard", 1), ("auto_purge", 1), ("image_scanner", 0),
        ("verify_channel_id", 0), ("verify_role_id", 0), ("min_account_age_days", 3), ("ip_ban_guard", 1),
        ("anti_vpn", 1), ("ghost_ping_guard", 1), ("anti_invite", 1), ("suspect_scan", 1),
        ("global_panic", 0)
    ]
    for col, default in columns:
        try: c.execute(f"ALTER TABLE guild_config ADD COLUMN {col} INTEGER DEFAULT {default}")
        except: pass
        
    try: c.execute("ALTER TABLE guild_config ADD COLUMN owner_pin TEXT DEFAULT '123456'")
    except: pass
    try: c.execute("ALTER TABLE guild_config ADD COLUMN verify_domain TEXT DEFAULT ''")
    except: pass

    conn.commit()
    conn.close()

init_db()

def get_config(guild_id: int):
    if guild_id in config_cache: return config_cache[guild_id]
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT log_channel_id, malware_filter, ai_filter, strike_system, anti_nuke, anti_mention, phishing_api, quarantine_role_id, voice_anti_raid, enforce_permissions, anti_dox, honeypot_channel_id, self_bot, webhook_guard, auto_purge, image_scanner, verify_channel_id, verify_role_id, min_account_age_days, ip_ban_guard, anti_vpn, ghost_ping_guard, owner_pin, anti_invite, verify_domain, suspect_scan, global_panic FROM guild_config WHERE guild_id = ?", (guild_id,))
    row = c.fetchone()
    conn.close()
    if row:
        conf = {
            "log_channel": row[0] if (row[0] is not None and row[0] != 0) else DEFAULT_LOG_CHANNEL_ID,
            "malware": bool(row[1]), "ai": bool(row[2]), "strike": bool(row[3]),
            "anti_nuke": bool(row[4]), "anti_mention": bool(row[5]), "phishing_api": bool(row[6]), "quarantine_role_id": row[7],
            "voice_anti_raid": bool(row[8]), "enforce_permissions": bool(row[9]), "anti_dox": bool(row[10]),
            "honeypot_channel_id": row[11] if (row[11] is not None and row[11] != 0) else DEFAULT_HONEYPOT_CHANNEL_ID,
            "self_bot": bool(row[12]), "webhook_guard": bool(row[13]), "auto_purge": bool(row[14]), "image_scanner": bool(row[15]),
            "verify_channel_id": row[16] or 0, "verify_role_id": row[17] or 0, "min_account_age_days": row[18] or 3, "ip_ban_guard": bool(row[19]),
            "anti_vpn": bool(row[20] if row[20] is not None else 1), "ghost_ping_guard": bool(row[21] if row[21] is not None else 1), "owner_pin": row[22] or "123456",
            "anti_invite": bool(row[23] if len(row) > 23 and row[23] is not None else 1),
            "verify_domain": row[24] if len(row) > 24 and row[24] else "",
            "suspect_scan": bool(row[25] if len(row) > 25 and row[25] is not None else 1),
            "global_panic": bool(row[26] if len(row) > 26 and row[26] is not None else 0)
        }
    else:
        conf = {
            "log_channel": DEFAULT_LOG_CHANNEL_ID, "malware": True, "ai": False, "strike": True,
            "anti_nuke": True, "anti_mention": True, "phishing_api": True, "quarantine_role_id": 0,
            "voice_anti_raid": True, "enforce_permissions": True, "anti_dox": True,
            "honeypot_channel_id": DEFAULT_HONEYPOT_CHANNEL_ID,
            "self_bot": True, "webhook_guard": True, "auto_purge": True, "image_scanner": False,
            "verify_channel_id": 0, "verify_role_id": 0, "min_account_age_days": 3, "ip_ban_guard": True,
            "anti_vpn": True, "ghost_ping_guard": True, "owner_pin": "123456", "anti_invite": True, "verify_domain": "",
            "suspect_scan": True, "global_panic": False
        }
        update_config(guild_id, "log_channel_id", DEFAULT_LOG_CHANNEL_ID)
        update_config(guild_id, "honeypot_channel_id", DEFAULT_HONEYPOT_CHANNEL_ID)
    config_cache[guild_id] = conf
    return conf

def update_config(guild_id: int, key: str, value: int):
    if key not in ALLOWED_CONFIG_KEYS:
        raise ValueError(f"Invalid config key: {key}")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO guild_config (guild_id) VALUES (?)", (guild_id,))
    c.execute(f"UPDATE guild_config SET {key} = ? WHERE guild_id = ?", (value, guild_id))
    conn.commit()
    conn.close()
    if guild_id in config_cache: del config_cache[guild_id]

def get_whitelist(guild_id: int):
    if guild_id in whitelist_cache: return whitelist_cache[guild_id]
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT role_id FROM whitelist WHERE guild_id = ?", (guild_id,))
    roles = [row[0] for row in c.fetchall()]
    conn.close()

    if not roles:
        roles = DEFAULT_WHITELIST_ROLES.copy()

    whitelist_cache[guild_id] = roles
    return roles

def add_whitelist_db(guild_id: int, role_id: int, role_name: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO whitelist (guild_id, role_id, role_name) VALUES (?, ?, ?)", (guild_id, role_id, role_name))
    conn.commit()
    conn.close()
    if guild_id in whitelist_cache and role_id not in whitelist_cache[guild_id]:
        whitelist_cache[guild_id].append(role_id)
    else: whitelist_cache[guild_id] = [role_id]

def remove_whitelist_db(guild_id: int, role_id: int):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM whitelist WHERE guild_id = ? AND role_id = ?", (guild_id, role_id))
    conn.commit()
    conn.close()
    if guild_id in whitelist_cache and role_id in whitelist_cache[guild_id]:
        whitelist_cache[guild_id].remove(role_id)

def add_warning(guild_id: int, user_id: int, reason: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO warnings (guild_id, user_id, reason, timestamp) VALUES (?, ?, ?, ?)", (guild_id, user_id, reason, time.time()))
    conn.commit()
    conn.close()

def get_warning_count(guild_id: int, user_id: int):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM warnings WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
    count = c.fetchone()[0]
    conn.close()
    return count

def get_quarantine_data(guild_id: int, user_id: int):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT original_roles FROM quarantine WHERE guild_id = ? AND user_id = ? ORDER BY rowid DESC LIMIT 1", (guild_id, user_id))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def remove_quarantine_data(guild_id: int, user_id: int):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM quarantine WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
    conn.commit()
    conn.close()

def save_backup_to_db(guild_id: int, data: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO backups (guild_id, timestamp, data) VALUES (?, ?, ?)", (guild_id, time.time(), data))
    conn.commit()
    conn.close()

def get_latest_backup(guild_id: int):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, timestamp, data FROM backups WHERE guild_id = ? ORDER BY id DESC LIMIT 1", (guild_id,))
    row = c.fetchone()
    conn.close()
    return row

def add_ip_log(guild_id: int, user_id: int, ip_address: str, user_agent: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO ip_logs (guild_id, user_id, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)",
              (guild_id, user_id, ip_address, user_agent, time.time()))
    conn.commit()
    conn.close()

def ban_ip(ip_address: str, reason: str = "Banned User IP Match"):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO banned_ips (ip_address, reason, timestamp) VALUES (?, ?, ?)", (ip_address, reason, time.time()))
    conn.commit()
    conn.close()

def ban_user_ips(guild_id: int, user_id: int, reason: str = "Auto IP Sync for Banned User"):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT DISTINCT ip_address FROM ip_logs WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
    ips = [row[0] for row in c.fetchall()]
    conn.close()
    for ip in ips:
        ban_ip(ip, reason)
    return len(ips)

def is_ip_banned(ip_address: str) -> bool:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT ip_address FROM banned_ips WHERE ip_address = ?", (ip_address,))
    row = c.fetchone()
    conn.close()
    return bool(row)

def check_user_ip_banned(guild_id: int, user_id: int, ip_address: str) -> bool:
    if is_ip_banned(ip_address):
        return True
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user_id FROM ip_logs WHERE ip_address = ? AND user_id != ?", (ip_address, user_id))
    other_users = [row[0] for row in c.fetchall()]
    conn.close()
    
    return False

async def send_audit_log(guild: discord.Guild, title: str, description: str, color: discord.Color):
    conf = get_config(guild.id)
    if not conf.get("log_channel"): return
    channel = guild.get_channel(conf["log_channel"])
    if channel:
        embed = discord.Embed(title=title, description=description, color=color, timestamp=datetime.datetime.now())
        try: await channel.send(embed=embed)
        except: pass

class DatabaseCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.auto_purge_task.start()

    def cog_unload(self):
        self.auto_purge_task.cancel()

    @tasks.loop(hours=24)
    async def auto_purge_task(self):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        ninety_days_ago = time.time() - (90 * 24 * 3600) 
        c.execute("SELECT guild_id FROM guild_config WHERE auto_purge = 1")
        guilds = [row[0] for row in c.fetchall()]
        for g_id in guilds:
            c.execute("DELETE FROM warnings WHERE guild_id = ? AND timestamp < ?", (g_id, ninety_days_ago))
        conn.commit()
        conn.close()

    @auto_purge_task.before_loop
    async def before_purge(self):
        await self.bot.wait_until_ready()

async def setup(bot):
    await bot.add_cog(DatabaseCog(bot))