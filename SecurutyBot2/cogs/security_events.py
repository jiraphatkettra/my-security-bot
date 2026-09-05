import re
import time
import datetime
import discord
import io
import aiohttp
import pytesseract
from PIL import Image
import asyncio
import os
import sys
from collections import defaultdict
from discord.ext import commands, tasks

from cogs.database import get_config, get_whitelist, send_audit_log, ban_user_ips, update_config, save_server_snapshot, increment_security_stat
import json
import unicodedata
import difflib

if sys.platform == "win32" and os.path.exists(r'C:\Program Files\Tesseract-OCR\tesseract.exe'):
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# ==========================================
# CONFIG & TRACKERS
# ==========================================
URL_REGEX = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+|www\.[-\w.]+"
DISCORD_INVITE_REGEX = r"(https?://)?(www\.)?(discord\.gg|discord\.com/invite|discordapp\.com/invite|discord\.com/oauth2)/[a-zA-Z0-9]+"
DANGEROUS_EXTENSIONS = ('.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.msi', '.pif')
DISCORD_TOKEN_REGEX = r"[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}"

PHONE_REGEX = r"\b(?:06|08|09)\d{8}\b"
THAI_ID_REGEX = r"\b[1-9]\d{12}\b"
IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

BAD_WORDS = []  # ปิดการสแกนคำหยาบ (ใส่คำลงใน [ ] หากต้องการให้สแกน)
SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "v.ht"]

SPAM_THRESHOLD = 4
SPAM_INTERVAL = 3

# Trackers
user_message_timestamps = defaultdict(list)
user_last_messages = defaultdict(list)
admin_action_timestamps = defaultdict(lambda: defaultdict(list)) 
voice_join_timestamps = defaultdict(lambda: defaultdict(list))
recent_joins_dict = defaultdict(list)
webhook_update_timestamps = defaultdict(list)
webhook_msg_timestamps = defaultdict(lambda: defaultdict(list))
thread_create_timestamps = defaultdict(lambda: defaultdict(list))
kick_timestamps = defaultdict(lambda: defaultdict(list))
timeout_timestamps = defaultdict(lambda: defaultdict(list))
role_edit_timestamps = defaultdict(lambda: defaultdict(list))
channel_edit_timestamps = defaultdict(lambda: defaultdict(list))
emoji_delete_timestamps = defaultdict(lambda: defaultdict(list))
sticker_delete_timestamps = defaultdict(lambda: defaultdict(list))
unban_timestamps = defaultdict(lambda: defaultdict(list))
recent_member_profiles = defaultdict(list)
invite_cache = {}
last_raid_invite_purge = defaultdict(float)

# ==========================================
# HELPER FUNCTIONS & MATH VALIDATORS (ZERO FALSE POSITIVES)
# ==========================================
def is_valid_thai_id(id_str: str) -> bool:
    """ตรวจสอบเลขบัตรประชาชนไทยด้วยอัลกอริทึม Modulo 11 (ป้องกันการตรวจผิดพลาด 100%)"""
    if not id_str.isdigit() or len(id_str) != 13:
        return False
    if id_str[0] == '0':
        return False
    digits = [int(ch) for ch in id_str]
    total = sum(digits[i] * (13 - i) for i in range(12))
    check = (11 - (total % 11)) % 10
    return check == digits[12]

def is_valid_public_ip(ip_str: str) -> bool:
    """ตรวจสอบ IP Address และคัดกรอง IP ทั่วไป/เวอร์ชันโปรแกรมทิ้ง"""
    parts = ip_str.split('.')
    if len(parts) != 4: return False
    try:
        nums = [int(p) for p in parts]
        if any(n < 0 or n > 255 for n in nums): return False
        if nums[0] in (0, 10, 127): return False
        if nums[0] == 172 and (16 <= nums[1] <= 31): return False
        if nums[0] == 192 and nums[1] == 168: return False
        if nums[0] >= 224: return False
        return True
    except ValueError:
        return False

# ==========================================
# BULK DELETE QUEUE SYSTEM (Anti 429 Rate Limit)
# ==========================================
delete_queue = defaultdict(list)
delete_queue_lock = asyncio.Lock()

async def safe_delete(message: discord.Message):
    """ส่งข้อความเข้า Queue สำหรับการลบแบบ Bulk Delete เพื่อป้องกัน HTTP 429 Rate Limit"""
    if not message or not message.channel:
        return
    async with delete_queue_lock:
        if message not in delete_queue[message.channel.id]:
            delete_queue[message.channel.id].append(message)

# 🖼️ ฟังก์ชันสำหรับแยกตัวอักษรออกจากรูป (ทำงานใน Background)
def extract_text_from_image(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes))
        text = pytesseract.image_to_string(img, lang='eng+tha') 
        return text.strip()
    except Exception as e:
        print(f"OCR Error: {e}")
        return ""

async def analyze_content_with_ai(content: str):
    mock_phishing_patterns = ["login", "verify", "wallet", "gift"]
    if any(p in content.lower() for p in mock_phishing_patterns) and "http" in content.lower():
        return True, "พฤติกรรมคล้าย Phishing Scam (AI Analysis)"
    return False, ""

async def check_phishing_api(url: str):
    mock_scam_domains = ["freediscordnitro.com", "steampromos.ru", "roblox-free-robux.scam", "discord-gift.com"]
    url_lower = url.lower()
    if any(domain in url_lower for domain in mock_scam_domains):
        return True
    if any(s_dom in url_lower for s_dom in SHORTENER_DOMAINS):
        return True
    is_typo, _ = is_typosquatting(url)
    if is_typo:
        return True
    return False

# ==========================================
# 🚨 OWNER EMERGENCY DM ALERT SYSTEM
# ==========================================
async def dm_alert_owner(guild: discord.Guild, title: str, description: str, color: discord.Color = discord.Color.dark_red()):
    conf = get_config(guild.id)
    if not conf.get("dm_owner_alert", True):
        return
    try:
        owner = guild.owner
        if not owner and guild.owner_id:
            try: owner = await guild.fetch_member(guild.owner_id)
            except: pass
        if not owner:
            return
        embed = discord.Embed(
            title=f"[CRITICAL ALERT] {title}",
            description=f"**Server:** `{guild.name}` (ID: `{guild.id}`)\n\n{description}",
            color=color,
            timestamp=datetime.datetime.now()
        )
        embed.set_footer(text="Security Core • Emergency Notification")
        await owner.send(embed=embed)
    except Exception as e:
        print(f"Failed to send DM to owner: {e}")

# ==========================================
# 🌐 ENHANCED PHISHING & HOMOGLYPH DETECTION
# ==========================================
CYRILLIC_HOMOGLYPHS = {
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0456': 'i', '\u0443': 'y', '\u0445': 'x',
    '\u0455': 's', '\u0406': 'I', '\u0410': 'A', '\u0412': 'B',
    '\u0415': 'E', '\u041a': 'K', '\u041c': 'M', '\u041d': 'H',
    '\u041e': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T',
    '\u0425': 'X'
}

TYPO_KEYWORDS = [
    "disc0rd", "discorcl", "discrod", "dlscord", "discordd", "discord-app",
    "discord-nitro", "discord-gift", "discord-airdrop", "steamcommunlty",
    "steamcommunityy", "steancommunity", "robl0x", "free-nitro", "free-robux",
    "discorcl.com", "disc0rd.com", "dlscord.com", "discord-claim", "discord-free"
]

RISKY_TLDS = (
    ".ru", ".xyz", ".tk", ".ml", ".ga", ".cf", ".top", ".click", 
    ".rest", ".buzz", ".fit", ".kim", ".gq", ".work", ".loan"
)

def is_typosquatting(text: str) -> tuple[bool, str]:
    if not text:
        return False, ""
    text_lower = text.lower()
    
    # 1. Direct typo keywords
    for typo in TYPO_KEYWORDS:
        if typo in text_lower:
            return True, f"ตรวจพบชื่อโดเมนเลียนแบบ/Typosquatting: `{typo}`"

    # 2. Extract URLs and check homoglyphs & risky TLDs
    urls = re.findall(URL_REGEX, text, re.IGNORECASE)
    for url in urls:
        url_clean = url.lower().replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]
        
        # Homoglyphs check: Contains Cyrillic mixed into domain
        has_cyrillic = any(ch in CYRILLIC_HOMOGLYPHS for ch in url)
        if has_cyrillic:
            normalized_domain = "".join(CYRILLIC_HOMOGLYPHS.get(ch, ch) for ch in url_clean)
            if any(k in normalized_domain for k in ["discord", "steam", "nitro", "gift"]):
                return True, f"ตรวจพบ Homograph Attack (ผสมอักษร Cyrillic ปลอมแปลงโดเมน): `{url_clean}`"

        # Risky TLDs with lure keywords
        for tld in RISKY_TLDS:
            if url_clean.endswith(tld) or f"{tld}/" in url.lower():
                if any(k in url.lower() for k in ["discord", "nitro", "gift", "steam", "promo", "free", "airdrop", "verify", "claim"]):
                    return True, f"ตรวจพบ Phishing URL บนโดเมนความเสี่ยงสูง (`{tld}`): `{url_clean}`"

    return False, ""

# ==========================================
# 🎭 NICKNAME IMPERSONATION GUARD
# ==========================================
def is_impersonating_admin(member: discord.Member) -> tuple[bool, str]:
    if not member or not member.guild or member.bot:
        return False, ""
    guild = member.guild
    if member.id == guild.owner_id:
        return False, ""
    if member.guild_permissions.administrator:
        return False, ""
    if any(r.id in get_whitelist(guild.id) for r in member.roles):
        return False, ""

    protected_names = set()
    owner = guild.owner
    if owner:
        protected_names.add(owner.name.lower())
        if owner.nick:
            protected_names.add(owner.nick.lower())

    for m in guild.members:
        if m.id != member.id and (m.guild_permissions.administrator or any(r.id in get_whitelist(guild.id) for r in m.roles)):
            protected_names.add(m.name.lower())
            if m.nick:
                protected_names.add(m.nick.lower())

    candidate_names = [member.name.lower(), member.display_name.lower()]
    if member.nick:
        candidate_names.append(member.nick.lower())

    for name in candidate_names:
        for tag in ["[admin]", "[owner]", "[staff]", "[mod]", "[moderator]", "[official]", "owner |", "admin |", "staff |"]:
            if name.startswith(tag) or tag in name:
                return True, f"สวมรอยใช้แท็ก Staff ({tag})"

    def clean_str(s: str) -> str:
        trans = str.maketrans({'0': 'o', '1': 'i', '3': 'e', '4': 'a', '@': 'a', '$': 's', '!': 'i'})
        s = s.translate(trans)
        return re.sub(r"[^a-zA-Z0-9\u0E00-\u0E7F]", "", s)

    for cand in candidate_names:
        cleaned_cand = clean_str(cand)
        if len(cleaned_cand) < 3:
            continue
        for prot in protected_names:
            cleaned_prot = clean_str(prot)
            if len(cleaned_prot) < 3:
                continue
            if cleaned_cand == cleaned_prot:
                return True, prot
            if len(cleaned_prot) >= 5:
                ratio = difflib.SequenceMatcher(None, cleaned_cand, cleaned_prot).ratio()
                if ratio >= 0.88:
                    return True, prot

    return False, ""

# ==========================================
# 🕵️ RAID FINGERPRINTING SYSTEM
# ==========================================
def check_raid_fingerprint(guild: discord.Guild, member: discord.Member) -> tuple[bool, str]:
    now = time.time()
    recent_member_profiles[guild.id].append({
        "id": member.id,
        "name": member.name.lower(),
        "created_at": member.created_at,
        "avatar": member.avatar is not None,
        "joined_at": now
    })
    recent_member_profiles[guild.id] = [p for p in recent_member_profiles[guild.id] if now - p["joined_at"] < 60]
    
    profiles = recent_member_profiles[guild.id]
    if len(profiles) < 3:
        return False, ""

    reasons = []
    
    # Indicator 1: Default Avatar
    no_avatar_count = sum(1 for p in profiles if not p["avatar"])
    if no_avatar_count >= 3 and (no_avatar_count / len(profiles)) >= 0.7:
        reasons.append(f"• สมาชิก {no_avatar_count}/{len(profiles)} บัญชีไม่มีรูปโปรไฟล์ (Default Avatar)")

    # Indicator 2: Very fresh accounts (< 24 hours old)
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    fresh_count = 0
    for p in profiles:
        c_at = p["created_at"] if p["created_at"].tzinfo else p["created_at"].replace(tzinfo=datetime.timezone.utc)
        if (now_utc - c_at).total_seconds() < 86400:
            fresh_count += 1
    if fresh_count >= 3 and (fresh_count / len(profiles)) >= 0.6:
        reasons.append(f"• สมาชิก {fresh_count}/{len(profiles)} บัญชีสมัครใหม่ไม่ถึง 24 ชั่วโมง")

    # Indicator 3: Created in same time window (within 6 hours of each other)
    timestamps = [p["created_at"].timestamp() for p in profiles]
    time_span = max(timestamps) - min(timestamps)
    if len(profiles) >= 3 and time_span < 21600:
        reasons.append(f"• สมาชิกทั้งหมดถูกสร้างขึ้นในเวลาไล่เลี่ยกัน (ช่วงเวลาห่างกันไม่เกิน 6 ชม.)")

    # Indicator 4: Common name pattern
    names = [p["name"] for p in profiles]
    prefix = os.path.commonprefix(names)
    has_common_prefix = len(prefix) >= 3
    digit_suffix_count = sum(1 for n in names if re.search(r"\d{2,}$", n))
    if has_common_prefix:
        reasons.append(f"• รูปแบบชื่อบัญชีมี Prefix ตรงกัน: `{prefix}`")
    elif digit_suffix_count >= 3:
        reasons.append(f"• รูปแบบชื่อบัญชีลงท้ายด้วยตัวเลขสแปมสอดคล้องกัน ({digit_suffix_count}/{len(profiles)} คน)")

    if len(reasons) >= 3:
        return True, "\n".join(reasons)

    return False, ""

def is_zalgo_text(text: str) -> bool:
    """ตรวจจับข้อความ Zalgo ที่มี Combining Marks ซ้อนกันหนาแน่นเกินไป"""
    if not text:
        return False
    combining_count = 0
    base_count = 0
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith('M'):  # Combining Mark (Mn, Mc, Me)
            combining_count += 1
        else:
            base_count += 1
    if base_count == 0:
        return combining_count > 10
    ratio = combining_count / max(base_count, 1)
    return ratio > 3.0 or combining_count > 50

def is_crash_text(text: str) -> bool:
    """ตรวจจับข้อความที่ออกแบบมาเพื่อทำให้ Discord Client ค้าง"""
    if not text:
        return False
    # ตัวอักษร Zero-Width / Invisible ซ้ำมากเกินไป
    invisible_chars = sum(1 for ch in text if unicodedata.category(ch) in ('Cf', 'Cc') and ch not in ('\n', '\r', '\t'))
    if invisible_chars > 100:
        return True
    # อิโมจิมากเกิน 20 ตัวต่อข้อความ
    emoji_count = sum(1 for ch in text if unicodedata.category(ch) == 'So')
    if emoji_count > 20:
        return True
    # ตัวอักษรเดียวกันซ้ำเกิน 50 ครั้งติดกัน
    if len(text) > 100:
        repeat_count = 1
        for i in range(1, len(text)):
            if text[i] == text[i-1]:
                repeat_count += 1
                if repeat_count > 50:
                    return True
            else:
                repeat_count = 1
    return False

async def take_server_snapshot(guild: discord.Guild):
    """สำรองโครงสร้างเซิร์ฟเวอร์ (ยศ, ห้อง, หมวดหมู่, สิทธิ์) ลงฐานข้อมูล"""
    try:
        snapshot = {
            "name": guild.name,
            "icon_url": str(guild.icon.url) if guild.icon else None,
            "roles": [],
            "categories": [],
            "channels": []
        }
        for r in guild.roles:
            if r.is_default() or r.is_bot_managed():
                continue
            snapshot["roles"].append({
                "id": r.id, "name": r.name,
                "permissions": r.permissions.value,
                "color": r.color.value,
                "position": r.position,
                "hoist": r.hoist, "mentionable": r.mentionable
            })
        for cat in guild.categories:
            overwrites_data = {}
            for target, ow in cat.overwrites.items():
                pair = ow.pair()
                overwrites_data[str(target.id)] = {"allow": pair[0].value, "deny": pair[1].value, "type": "role" if isinstance(target, discord.Role) else "member"}
            snapshot["categories"].append({"id": cat.id, "name": cat.name, "position": cat.position, "overwrites": overwrites_data})
        for ch in guild.channels:
            if isinstance(ch, discord.CategoryChannel):
                continue
            overwrites_data = {}
            for target, ow in ch.overwrites.items():
                pair = ow.pair()
                overwrites_data[str(target.id)] = {"allow": pair[0].value, "deny": pair[1].value, "type": "role" if isinstance(target, discord.Role) else "member"}
            snapshot["channels"].append({
                "id": ch.id, "name": ch.name,
                "type": str(ch.type),
                "category_id": ch.category_id,
                "position": ch.position,
                "overwrites": overwrites_data
            })
        save_server_snapshot(guild.id, json.dumps(snapshot, ensure_ascii=False))
        return snapshot
    except Exception as e:
        print(f"Snapshot Error: {e}")
        return None

async def check_anti_nuke(guild: discord.Guild, user: discord.Member, action: str):
    if not user or user.bot: return
    conf = get_config(guild.id)
    if not conf["anti_nuke"]: return

    now = time.time()
    admin_action_timestamps[guild.id][user.id].append(now)
    admin_action_timestamps[guild.id][user.id] = [t for t in admin_action_timestamps[guild.id][user.id] if now - t < 10]

    if len(admin_action_timestamps[guild.id][user.id]) >= 4:
        # 🔥 Auto-Panic Escalation: เมื่อ Anti-Nuke ตรวจพบ Nuke -> ล็อกดาวน์อัตโนมัติ
        conf_for_panic = get_config(guild.id)
        if conf_for_panic.get("auto_panic_escalation") and not conf_for_panic.get("global_panic"):
            update_config(guild.id, "global_panic", 1)
            default_role = guild.default_role
            for channel in guild.channels:
                try:
                    overwrite = channel.overwrites_for(default_role)
                    overwrite.send_messages = False
                    overwrite.send_messages_in_threads = False
                    overwrite.connect = False
                    await channel.set_permissions(default_role, overwrite=overwrite)
                except: pass
            increment_security_stat(guild.id, "auto_panic")
            await send_audit_log(guild, "🔥 AUTO-PANIC ESCALATION!",
                f"Anti-Nuke ตรวจพบการทำลายเซิร์ฟเวอร์โดย {user.mention}\n"
                f"⚡ **สั่งล็อกดาวน์ (Global Panic) อัตโนมัติทันที!**",
                discord.Color.dark_red())
            await dm_alert_owner(guild, "🔥 AUTO-PANIC ESCALATION!",
                f"Anti-Nuke ตรวจพบการทำลายเซิร์ฟเวอร์โดย {user.mention} (`{user.id}`)\n"
                f"⚡ **สั่งล็อกดาวน์ (Global Panic) อัตโนมัติทันที!**")

        try:
            for role in user.roles:
                if role.permissions.administrator or role.permissions.manage_guild or role.permissions.manage_channels or role.permissions.manage_roles:
                    try: await user.remove_roles(role, reason="[Anti-Nuke] ตรวจพบการทำลายเซิร์ฟเวอร์")
                    except: pass
            increment_security_stat(guild.id, "anti_nuke")
            await send_audit_log(guild, "🚨 ANTI-NUKE ทำงาน!", f"ทำการริบสิทธิ์ {user.mention} ทันที\nสาเหตุ: ทำการ {action} ถี่เกินกำหนด (เกิน 4 ครั้ง/10 วิ)", discord.Color.red())
            await dm_alert_owner(guild, "🚨 ANTI-NUKE DETECTED!", f"ตรวจพบ {user.mention} (`{user.id}`) ทำการ **{action}** ถี่เกินกำหนด (> 4 ครั้ง/10 วิ)\nบอทได้ทำการริบยศแอดมินทั้งหมดทันที")
            admin_action_timestamps[guild.id][user.id].clear()
        except Exception as e:
            await send_audit_log(guild, "⚠️ ANTI-NUKE ขัดข้อง", f"ไม่สามารถริบยศ {user.mention} ได้ (อาจจะยศสูงกว่าบอท)\nError: {e}", discord.Color.orange())

async def get_cached_guild_invites(guild: discord.Guild):
    now = time.time()
    if guild.id in invite_cache:
        cached_time, codes = invite_cache[guild.id]
        if now - cached_time < 60:
            return codes
    try:
        invites = await guild.invites()
        codes = [inv.code for inv in invites]
        invite_cache[guild.id] = (now, codes)
        return codes
    except Exception:
        return []

# ==========================================
# AUTOMATED EVENTS & SECURITY LOGIC
# ==========================================
class SecurityEventsCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.flush_delete_queue.start()
        self.auto_snapshot_task.start()

    def cog_unload(self):
        self.flush_delete_queue.cancel()
        self.auto_snapshot_task.cancel()

    @tasks.loop(seconds=0.8)
    async def flush_delete_queue(self):
        """ระบบ Bulk Delete รวมข้อความลบทีละ 100 ข้อความต่อ 1 API Call เพื่อป้องกัน HTTP 429"""
        async with delete_queue_lock:
            if not delete_queue:
                return
            current_queues = dict(delete_queue)
            delete_queue.clear()

        for channel_id, messages in current_queues.items():
            if not messages:
                continue
            channel = messages[0].channel
            if not isinstance(channel, (discord.TextChannel, discord.Thread)):
                for msg in messages:
                    try: await msg.delete()
                    except: pass
                    await asyncio.sleep(0.2)
                continue

            now = datetime.datetime.now(datetime.timezone.utc)
            young_msgs = []
            old_msgs = []
            for msg in messages:
                created_at = msg.created_at if msg.created_at.tzinfo else msg.created_at.replace(tzinfo=datetime.timezone.utc)
                if (now - created_at).total_seconds() < 1209000:
                    young_msgs.append(msg)
                else:
                    old_msgs.append(msg)

            for i in range(0, len(young_msgs), 100):
                chunk = young_msgs[i:i + 100]
                try:
                    if len(chunk) == 1:
                        await chunk[0].delete()
                    else:
                        await channel.delete_messages(chunk)
                except (discord.NotFound, discord.Forbidden):
                    pass
                except discord.HTTPException as e:
                    if e.status == 429:
                        await asyncio.sleep(2)
                except Exception:
                    pass
                await asyncio.sleep(0.3)

            for msg in old_msgs:
                try: await msg.delete()
                except: pass
                await asyncio.sleep(0.35)

    @flush_delete_queue.before_loop
    async def before_flush_delete_queue(self):
        await self.bot.wait_until_ready()

    async def run_message_backlog_scan(self, guild: discord.Guild):
        """ฟังก์ชันสแกนและลบข้อความสแปม/อันตรายย้อนหลังในแชท"""
        conf = get_config(guild.id)
        guild_invites = await get_cached_guild_invites(guild) if conf.get("anti_invite") else []
        scanned_count = 0
        deleted_count = 0

        active_webhook_ids = set()
        try:
            guild_webhooks = await guild.webhooks()
            active_webhook_ids = {wh.id for wh in guild_webhooks}
        except: pass

        for channel in guild.text_channels:
            if not channel.permissions_for(guild.me).read_messages or not channel.permissions_for(guild.me).read_message_history:
                continue
            try:
                async for message in channel.history(limit=500):
                    scanned_count += 1
                    if not message.guild or message.author.id == self.bot.user.id:
                        continue
                    
                    is_wl = isinstance(message.author, discord.Member) and (
                        message.author.id == guild.owner_id or message.author.guild_permissions.administrator or any(r.id in get_whitelist(guild.id) for r in message.author.roles)
                    )
                    if is_wl:
                        continue

                    content = message.content.strip() if message.content else ""

                    # Check for Webhook messages (ลบข้อความ Webhook ค้าง หรือ Webhook ที่โดนลบไปแล้ว/สแปม)
                    if message.webhook_id:
                        is_orphan_webhook = message.webhook_id not in active_webhook_ids
                        has_spam_content = (
                            bool(re.search(URL_REGEX, content, re.IGNORECASE)) or
                            any(w in content.lower() for w in ["cybernuvex", "โกโก้กลัว", "จำกูได้ป่ะ", "ไอ้พวกโง่", "ยิงดิส", "nuke", "raid", "bypass", "bot"]) or
                            (BAD_WORDS and any(w in content.lower() for w in BAD_WORDS))
                        )
                        if is_orphan_webhook or has_spam_content:
                            await safe_delete(message)
                            deleted_count += 1
                            await send_audit_log(guild, "🚨 เคลียร์ข้อความ Webhook สแปมย้อนหลังสำเร็จ", f"ลบข้อความสแปม Webhook ใน {channel.mention}\nเนื้อหา: `{content[:100]}`", discord.Color.red())
                            await asyncio.sleep(0.05)
                            continue

                    # Token Leak
                    if content and re.search(DISCORD_TOKEN_REGEX, content):
                        await safe_delete(message)
                        deleted_count += 1
                        await send_audit_log(guild, "🚨 ตรวจพบ DISCORD BOT TOKEN LEAK (Manual Scan)!", f"ผู้ใช้ {message.author.mention} โพสต์ Discord Bot Token ใน {channel.mention}\n*ลบข้อความย้อนหลังสำเร็จ*", discord.Color.dark_red())
                        await asyncio.sleep(0.1)
                        continue
                    
                    # Dangerous attachments (Malware)
                    if conf.get("malware") and message.attachments:
                        for att in message.attachments:
                            if att.filename.lower().endswith(DANGEROUS_EXTENSIONS):
                                await safe_delete(message)
                                deleted_count += 1
                                await send_audit_log(guild, "🛡️ มัลแวร์สกัดกั้น (Manual Scan)", f"ลบไฟล์อันตรายย้อนหลัง `{att.filename}` จาก {message.author.mention} ใน {channel.mention}", discord.Color.red())
                                await asyncio.sleep(0.1)
                                break
                                
                    # Phishing Links
                    if conf.get("phishing_api") and content:
                        urls = re.findall(URL_REGEX, content, re.IGNORECASE)
                        has_scam = False
                        for url in urls:
                            if await check_phishing_api(url):
                                await safe_delete(message)
                                deleted_count += 1
                                await send_audit_log(guild, "🚨 ลิงก์สแกมสกัดกั้น (Manual Scan)", f"ลบข้อความลิงก์สแกมย้อนหลัง จาก {message.author.mention} ใน {channel.mention}", discord.Color.red())
                                await asyncio.sleep(0.1)
                                has_scam = True
                                break
                        if has_scam:
                            continue

                    # Anti-Invite Links & OAuth2 Bot Invites
                    if conf.get("anti_invite") and content:
                        invite_match = re.search(r"(https?://)?(www\.)?(discord\.gg|discord\.com/invite|discordapp\.com/invite|discord\.com/oauth2|discord\.com/api/oauth2)/([a-zA-Z0-9_?&=.-]+)", content, re.IGNORECASE)
                        if invite_match:
                            code = invite_match.group(4)
                            if code not in guild_invites:
                                await safe_delete(message)
                                deleted_count += 1
                                await send_audit_log(guild, "🔗 Anti-Invite / OAuth2 Guard (Manual Scan)", f"ลบลิงก์เชิญ/OAuth2 ย้อนหลัง จาก {message.author.mention} ใน {channel.mention}", discord.Color.orange())
                                await asyncio.sleep(0.1)
                                continue

                    # Anti-Dox (Thai ID Modulo 11 & Public IP & Phone)
                    if conf.get("anti_dox") and content:
                        clean_text = re.sub(r"```[\s\S]*?```|`[^`]*`", "", content)
                        clean_text = re.sub(URL_REGEX, "", clean_text, flags=re.IGNORECASE)
                        thai_ids = re.findall(r"\b[1-9]\d{12}\b", clean_text)
                        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", clean_text)
                        phones = re.findall(r"\b(?:06|08|09)\d{8}\b", clean_text)
                        if any(is_valid_thai_id(tid) for tid in thai_ids) or any(is_valid_public_ip(ip) for ip in ips) or len(phones) > 0:
                            await safe_delete(message)
                            deleted_count += 1
                            await send_audit_log(guild, "👁️ ANTI-DOX (Manual Scan)", f"ลบการเปิดเผยข้อมูลสำคัญย้อนหลัง จาก {message.author.mention} ใน {channel.mention}", discord.Color.red())
                            await asyncio.sleep(0.1)
                            continue

                    # Bad Words (ถ้าตั้งไว้)
                    if BAD_WORDS and content and any(w in content.lower() for w in BAD_WORDS):
                        await safe_delete(message)
                        deleted_count += 1
                        await asyncio.sleep(0.1)
                        continue

                    await asyncio.sleep(0.01)
            except Exception as e:
                print(f"Error scanning channel {channel.name}: {e}")

        return scanned_count, deleted_count

    async def run_suspect_account_scan(self, guild: discord.Guild):
        """ฟังก์ชันสแกนไอดีดิสสมัครใหม่/น่าสงสัยในเซิร์ฟเวอร์"""
        suspicious_members = []
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        for member in guild.members:
            if member.bot:
                continue
            account_age_days = (now_utc - member.created_at).days
            is_default_avatar = member.avatar is None
            is_very_new = account_age_days < 7
            has_suspicious_name = bool(re.search(r"discord|nitro|steam|gift|free|promo|bot|scam", member.name, re.IGNORECASE))
            
            if is_very_new or (is_default_avatar and account_age_days < 14) or has_suspicious_name:
                suspicious_members.append(member)

        if suspicious_members:
            total_members = len(suspicious_members)
            chunk_size = 20
            total_batches = ((total_members - 1) // chunk_size) + 1

            for batch_idx in range(total_batches):
                chunk = suspicious_members[batch_idx * chunk_size : (batch_idx + 1) * chunk_size]
                summary_lines = []
                for m in chunk:
                    age_days = (now_utc - m.created_at).days
                    summary_lines.append(f"• {m.mention} (`{m.id}`) - อายุบัญชี {age_days} วัน")
                
                suspect_details = "\n".join(summary_lines)
                batch_title = f"🔍 สแกนไอดีน่าสงสัยย้อนหลัง ({batch_idx + 1}/{total_batches})" if total_batches > 1 else "🔍 ผลการสแกนไอดีน่าสงสัยย้อนหลัง"
                
                await send_audit_log(
                    guild,
                    batch_title,
                    f"พบสมาชิกน่าสงสัยทั้งหมด **{total_members}** บัญชี (ชุดที่ {batch_idx + 1}/{total_batches}):\n\n{suspect_details}",
                    discord.Color.gold()
                )
                await asyncio.sleep(0.3)

        return suspicious_members

    async def run_guild_backlog_scan(self, guild: discord.Guild):
        """ฟังก์ชันสแกนรวมทั้งข้อความและไอดีน่าสงสัย (เพื่อความเข้ากันได้ย้อนหลัง)"""
        scanned_count, deleted_count = await self.run_message_backlog_scan(guild)
        suspicious_members = await self.run_suspect_account_scan(guild)
        return scanned_count, deleted_count, suspicious_members

    @commands.Cog.listener()
    async def on_ready(self):
        print(f"✅ Ultimate Enterprise Security Bot is ACTIVE!")
        # Auto-Snapshot เมื่อบอทพร้อมทำงาน
        await asyncio.sleep(5)
        for guild in self.bot.guilds:
            await take_server_snapshot(guild)
        print(f"💾 Auto-Snapshot: สำรองโครงสร้างเซิร์ฟเวอร์ {len(self.bot.guilds)} ดิสสำเร็จ")

    @tasks.loop(hours=6)
    async def auto_snapshot_task(self):
        """สำรองโครงสร้างเซิร์ฟเวอร์อัตโนมัติทุก 6 ชั่วโมง"""
        for guild in self.bot.guilds:
            await take_server_snapshot(guild)

    @auto_snapshot_task.before_loop
    async def before_auto_snapshot(self):
        await self.bot.wait_until_ready()

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        guild = member.guild
        conf = get_config(guild.id)
        
        # 1. 🔍 Suspicious Account Scanner (ระบบออโต้สแกนไอดีสมัครใหม่ขณะย้ายเข้าดิส)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        account_age_days = (now_utc - member.created_at).days
        account_age_hours = int((now_utc - member.created_at).total_seconds() / 3600)

        is_default_avatar = member.avatar is None
        is_very_new = account_age_days < 7
        risk_reasons = []

        if is_very_new:
            risk_reasons.append(f"• สมัครใหม่ไม่ถึง 7 วัน ({account_age_days} วัน / {account_age_hours} ชม.)")
        if is_default_avatar:
            risk_reasons.append("• ไม่มีรูปโปรไฟล์ (Default Avatar)")
        if re.search(r"discord|nitro|steam|gift|free|promo|bot|scam", member.name, re.IGNORECASE):
            risk_reasons.append(f"• ชื่อบัญชีสุ่มเสี่ยงสแปม (`{member.name}`)")

        if conf.get("suspect_scan") and (is_very_new or (is_default_avatar and account_age_days < 14) or len(risk_reasons) >= 2):
            risk_text = "\n".join(risk_reasons)
            created_str = member.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            await send_audit_log(
                guild,
                "🔍 ตรวจพบสมาชิกสมัครใหม่น่าสงสัย! (Suspicious Account)",
                f"ผู้ใช้: {member.mention} (`{member.id}`)\n"
                f"วันที่สร้างบัญชี: `{created_str}`\n"
                f"**รายการประเมินความเสี่ยง:**\n{risk_text}\n"
                f"⚠️ *ระบบเฝ้าระวังพฤติกรรมในเซิร์ฟเวอร์อัตโนมัติ*",
                discord.Color.gold()
            )

        # 2. Check Account Age (Alt Account Raid Defense)
        min_days = conf.get("min_account_age_days", 3)
        if min_days > 0:
            if account_age_days < min_days:
                try:
                    await member.kick(reason=f"[Alt Guard] อายุบัญชีสั้นเกินกำหนด ({account_age_days} วัน < ขั้นต่ำ {min_days} วัน)")
                    await send_audit_log(guild, "🛡️ Alt Guard ทำงาน", f"สกัดกั้นไอดีอวตาร {member.mention} (`{member.id}`)\nอายุบัญชี: {account_age_days} วัน (ขั้นต่ำ {min_days} วัน)", discord.Color.orange())
                    return
                except: pass

        # 2.5 🤖 Anti-Bot Add Guard (ป้องกันการดึงบอทแปลกหน้าเข้าดิส)
        if member.bot and conf.get("anti_bot_add"):
            try:
                async for entry in guild.audit_logs(action=discord.AuditLogAction.bot_add, limit=5):
                    if entry.target and entry.target.id == member.id:
                        inviter = entry.user
                        if inviter and inviter.id != guild.owner_id:
                            is_wl = isinstance(inviter, discord.Member) and any(r.id in get_whitelist(guild.id) for r in inviter.roles)
                            if not is_wl:
                                await member.kick(reason="[Anti-Bot Guard] บอทไม่ได้รับอนุญาตจาก Server Owner หรือ Whitelist")
                                # ริบยศ Admin ของคนเชิญ
                                if isinstance(inviter, discord.Member):
                                    for role in inviter.roles:
                                        if role.permissions.administrator or role.permissions.manage_guild:
                                            try: await inviter.remove_roles(role, reason="[Anti-Bot Guard] ริบสิทธิ์เนื่องจากเชิญบอทไม่ได้รับอนุญาต")
                                            except: pass
                                increment_security_stat(guild.id, "anti_bot_add")
                                await send_audit_log(guild, "🤖 Anti-Bot Guard ทำงาน!",
                                    f"สกัดกั้นบอท {member.mention} (`{member.id}`) ที่ถูกเชิญโดย {inviter.mention}\n"
                                    f"⚡ **เตะบอทออก + ริบสิทธิ์แอดมินผู้เชิญทันที!**",
                                    discord.Color.dark_red())
                                await dm_alert_owner(guild, "🤖 ANTI-BOT ADD DETECTED!",
                                    f"ตรวจพบบอท {member.name} (`{member.id}`) ถูกเชิญเข้าเซิร์ฟเวอร์โดย {inviter.mention} (`{inviter.id}`)\n"
                                    f"บอทได้ทำการเตะบอทออกและริบยศแอดมินของคนเชิญทันที!")
                                return
                        break
            except Exception as e:
                print(f"Anti-Bot Guard Error: {e}")

        # 2.8 🕵️ Raid Fingerprint Scanner (วิเคราะห์ลายนิ้วมือกลุ่มโจมตี)
        if not member.bot and conf.get("raid_fingerprint", True):
            is_fp, fp_reason = check_raid_fingerprint(guild, member)
            if is_fp:
                try:
                    await member.ban(reason="[Raid Fingerprint] ลายนิ้วมือตรงกับกลุ่ม Raider โจมตีเซิร์ฟเวอร์")
                    increment_security_stat(guild.id, "raid_fingerprint")
                    await send_audit_log(guild, "🕵️ RAID FINGERPRINT DETECTED!",
                        f"ตรวจพบลายพิมพ์กลุ่ม Raider บุกเซิร์ฟเวอร์!\n"
                        f"ผู้ใช้: {member.mention} (`{member.id}`)\n"
                        f"📌 **รูปแบบที่ตรวจพบ:**\n{fp_reason}\n"
                        f"⚡ **สั่งแบนสมาชิกกลุ่ม Raid ทันที!**",
                        discord.Color.dark_red())
                    await dm_alert_owner(guild, "🕵️ RAID FINGERPRINT ATTACK!",
                        f"ตรวจพบลายพิมพ์กลุ่ม Raider ทะลักเข้าดิส!\n"
                        f"ผู้ใช้: {member.name} (`{member.id}`)\n"
                        f"{fp_reason}\n"
                        f"บอทได้สั่งแบนและสกัดกั้นเรียบร้อย")
                    return
                except Exception as e:
                    print(f"Raid Fingerprint Ban Error: {e}")

        # 2.9 🎭 Nickname Impersonation Guard on Join (ตรวจจับการปลอมชื่อตอนเข้า)
        if not member.bot and conf.get("anti_impersonation", True):
            is_imp, target = is_impersonating_admin(member)
            if is_imp:
                try:
                    await member.edit(nick="[Reset-Impersonation]", reason="[Nickname Guard] ปลอมชื่อแอดมินหรือเจ้าของเซิร์ฟ")
                    increment_security_stat(guild.id, "nickname_impersonation")
                    await send_audit_log(guild, "🎭 NICKNAME IMPERSONATION GUARD!",
                        f"ตรวจพบสมาชิกใหม่ {member.mention} (`{member.id}`) มีชื่อส่อแววเลียนแบบแอดมิน/Owner (`{target}`)\n"
                        f"⚡ **ระบบได้ทำการรีเซ็ตชื่อเล่น (Nickname) ทันที!**",
                        discord.Color.orange())
                except Exception as e:
                    print(f"Impersonation on join error: {e}")

        # 3. Check Member Join Flood (Raid Defense)
        now = time.time()
        recent_joins_dict[guild.id].append(now)
        recent_joins_dict[guild.id] = [t for t in recent_joins_dict[guild.id] if now - t < 10]
        
        if len(recent_joins_dict[guild.id]) >= 5:
            try: 
                await member.ban(reason="[Auto Security] บอท Raid ทะลักเข้าดิส")
                increment_security_stat(guild.id, "join_flood_raid")
            except: pass

            # 🔥 Auto-Panic Escalation: ถ้าสมาชิกทะลักเกิน 10 คนใน 5 วินาที -> ล็อกดาวน์อัตโนมัติ
            if conf.get("auto_panic_escalation") and len(recent_joins_dict[guild.id]) >= 10:
                if not conf.get("global_panic"):
                    update_config(guild.id, "global_panic", 1)
                    default_role = guild.default_role
                    for channel in guild.channels:
                        try:
                            overwrite = channel.overwrites_for(default_role)
                            overwrite.send_messages = False
                            overwrite.send_messages_in_threads = False
                            overwrite.connect = False
                            await channel.set_permissions(default_role, overwrite=overwrite)
                        except: pass
                    increment_security_stat(guild.id, "auto_panic")
                    await send_audit_log(guild, "🔥 AUTO-PANIC ESCALATION!",
                        f"ตรวจพบสมาชิกทะลักเข้าดิสพร้อมกัน **{len(recent_joins_dict[guild.id])}** คนใน 10 วินาที!\n"
                        f"⚡ **สั่งล็อกดาวน์ (Global Panic) อัตโนมัติทันที!**\n"
                        f"💡 *แอดมินสามารถปลดล็อกดาวน์ได้ผ่าน Dashboard: ปุ่ม 🟢 ปลด Global Panic*",
                        discord.Color.dark_red())
                    await dm_alert_owner(guild, "🔥 AUTO-PANIC ESCALATION!",
                        f"ตรวจพบสมาชิกทะลักเข้าดิสพร้อมกัน **{len(recent_joins_dict[guild.id])}** คนใน 10 วินาที!\n"
                        f"⚡ **สั่งล็อกดาวน์ (Global Panic) อัตโนมัติทันที!**")
            
            if now - last_raid_invite_purge[guild.id] > 20:
                last_raid_invite_purge[guild.id] = now
                try:
                    invites = await guild.invites()
                    for inv in invites:
                        if inv.uses > 5 and inv.max_age == 0: 
                            await inv.delete(reason="[Anti-Raid] ลบลิงก์เชิญต้นตอที่กลุ่ม Raid ใช้")
                            await send_audit_log(guild, "🔗 ตัดวงจรลิงก์สแปม", f"บอททำลายลิงก์ `{inv.code}` สำเร็จ เพื่อหยุดการโจมตี!", discord.Color.red())
                except: pass

    @commands.Cog.listener()
    async def on_guild_channel_create(self, channel):
        async for entry in channel.guild.audit_logs(action=discord.AuditLogAction.channel_create, limit=1):
            if entry.target.id == channel.id:
                await check_anti_nuke(channel.guild, entry.user, "สร้างห้อง")

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel):
        async for entry in channel.guild.audit_logs(action=discord.AuditLogAction.channel_delete, limit=1):
            if entry.target.id == channel.id:
                await check_anti_nuke(channel.guild, entry.user, "ลบห้อง")

    @commands.Cog.listener()
    async def on_guild_role_create(self, role):
        async for entry in role.guild.audit_logs(action=discord.AuditLogAction.role_create, limit=1):
            if entry.target.id == role.id:
                await check_anti_nuke(role.guild, entry.user, "สร้างยศ")

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role):
        async for entry in role.guild.audit_logs(action=discord.AuditLogAction.role_delete, limit=1):
            if entry.target.id == role.id:
                await check_anti_nuke(role.guild, entry.user, "ลบยศ")

    @commands.Cog.listener()
    async def on_member_ban(self, guild, user):
        async for entry in guild.audit_logs(action=discord.AuditLogAction.ban, limit=1):
            if entry.target.id == user.id:
                await check_anti_nuke(guild, entry.user, "สั่งแบนสมาชิก")
        
        try:
            banned_count = ban_user_ips(guild.id, user.id, f"Auto IP Sync for Banned User {user.name}")
            if banned_count > 0:
                await send_audit_log(guild, "🔄 Auto IP Blacklist Sync", f"ทำการดึงประวัติ IP ของผู้ใช้ {user.name} (`{user.id}`) เข้าสู่ตารางแบน IP สำเร็จ **{banned_count}** IP", discord.Color.dark_red())
        except Exception as e:
            print(f"Auto IP Sync Error: {e}")

    # ==========================================
    # 🆕 ANTI-MASS KICK DETECTION
    # ==========================================
    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member):
        guild = member.guild
        conf = get_config(guild.id)
        if not conf.get("anti_mass_action"): return

        try:
            async for entry in guild.audit_logs(action=discord.AuditLogAction.kick, limit=1):
                if entry.target.id == member.id:
                    kicker = entry.user
                    if not kicker or kicker.bot or kicker.id == guild.owner_id: return
                    now = time.time()
                    kick_timestamps[guild.id][kicker.id].append(now)
                    kick_timestamps[guild.id][kicker.id] = [t for t in kick_timestamps[guild.id][kicker.id] if now - t < 10]
                    if len(kick_timestamps[guild.id][kicker.id]) >= 4:
                        for role in kicker.roles:
                            if role.permissions.administrator or role.permissions.manage_guild or role.permissions.kick_members:
                                try: await kicker.remove_roles(role, reason="[Anti-Mass Kick] ตรวจพบการไล่เตะคนรัว")
                                except: pass
                        increment_security_stat(guild.id, "anti_mass_kick")
                        await send_audit_log(guild, "🚨 ANTI-MASS KICK ทำงาน!",
                            f"ทำการริบสิทธิ์ {kicker.mention} ทันที\nสาเหตุ: ไล่เตะสมาชิกเกิน 4 คนใน 10 วินาที",
                            discord.Color.red())
                        await dm_alert_owner(guild, "🚨 ANTI-MASS KICK DETECTED!",
                            f"ตรวจพบ {kicker.mention} (`{kicker.id}`) ไล่เตะสมาชิกเกิน 4 คนใน 10 วินาที\nบอทได้ทำการริบยศแอดมินทันที")
                        kick_timestamps[guild.id][kicker.id].clear()
                    break
        except: pass

    # ==========================================
    # 🆕 ANTI-MASS TIMEOUT & NICKNAME IMPERSONATION
    # ==========================================
    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):
        guild = after.guild
        conf = get_config(guild.id)

        # 1. 🎭 Nickname Impersonation Guard
        if conf.get("anti_impersonation", True) and not after.bot:
            name_changed = (before.nick != after.nick) or (before.name != after.name) or (before.display_name != after.display_name)
            if name_changed:
                is_imp, target = is_impersonating_admin(after)
                if is_imp:
                    try:
                        await after.edit(nick="[Reset-Impersonation]", reason="[Nickname Guard] ปลอมชื่อแอดมินหรือเจ้าของเซิร์ฟ")
                        increment_security_stat(guild.id, "nickname_impersonation")
                        await send_audit_log(guild, "🎭 NICKNAME IMPERSONATION GUARD!",
                            f"ตรวจพบ {after.mention} (`{after.id}`) เปลี่ยนชื่อเลียนแบบแอดมิน/Owner (`{target}`)\n"
                            f"⚡ **ระบบได้ทำการรีเซ็ตชื่อเล่น (Nickname) ทันที!**",
                            discord.Color.orange())
                        try:
                            await after.send(f"⚠️ **เตือนความปลอดภัย:** ไม่อนุญาตให้ตั้งชื่อเลียนแบบ Admin/Staff ในเซิร์ฟเวอร์ `{guild.name}` ระบบได้รีเซ็ตชื่อของคุณเรียบร้อย")
                        except: pass
                    except Exception as e:
                        print(f"Impersonation edit error: {e}")

        # 2. 🛑 Anti-Mass Timeout Check
        if before.timed_out_until == after.timed_out_until: return
        if after.timed_out_until is None: return

        if not conf.get("anti_mass_action"): return

        try:
            async for entry in guild.audit_logs(action=discord.AuditLogAction.member_update, limit=3):
                if entry.target.id == after.id and entry.user and not entry.user.bot and entry.user.id != guild.owner_id:
                    moderator = entry.user
                    now = time.time()
                    timeout_timestamps[guild.id][moderator.id].append(now)
                    timeout_timestamps[guild.id][moderator.id] = [t for t in timeout_timestamps[guild.id][moderator.id] if now - t < 10]
                    if len(timeout_timestamps[guild.id][moderator.id]) >= 4:
                        for role in moderator.roles:
                            if role.permissions.administrator or role.permissions.manage_guild or role.permissions.moderate_members:
                                try: await moderator.remove_roles(role, reason="[Anti-Mass Timeout] ตรวจพบการไล่จับ Timeout รัว")
                                except: pass
                        increment_security_stat(guild.id, "anti_mass_timeout")
                        await send_audit_log(guild, "🚨 ANTI-MASS TIMEOUT ทำงาน!",
                            f"ทำการริบสิทธิ์ {moderator.mention} ทันที\nสาเหตุ: จับ Timeout สมาชิกเกิน 4 คนใน 10 วินาที",
                            discord.Color.red())
                        await dm_alert_owner(guild, "🚨 ANTI-MASS TIMEOUT DETECTED!",
                            f"ตรวจพบ {moderator.mention} (`{moderator.id}`) จับ Timeout สมาชิกเกิน 4 คนใน 10 วินาที\nบอทได้ทำการริบยศแอดมินทันที")
                        timeout_timestamps[guild.id][moderator.id].clear()
                    break
        except: pass

    # ==========================================
    # 🆕 ANTI-SERVER HIJACK (on_guild_update)
    # ==========================================
    @commands.Cog.listener()
    async def on_guild_update(self, before: discord.Guild, after: discord.Guild):
        conf = get_config(after.id)
        if not conf.get("anti_server_hijack"): return

        name_changed = before.name != after.name
        icon_changed = before.icon != after.icon

        if not name_changed and not icon_changed:
            return

        try:
            async for entry in after.audit_logs(action=discord.AuditLogAction.guild_update, limit=1):
                editor = entry.user
                if not editor or editor.bot or editor.id == after.owner_id:
                    return

                is_wl = isinstance(editor, discord.Member) and any(r.id in get_whitelist(after.id) for r in editor.roles)
                if is_wl:
                    return

                changes_desc = []
                # เปลี่ยนชื่อดิสกลับ
                if name_changed:
                    try:
                        await after.edit(name=before.name, reason="[Anti-Hijack] คืนชื่อเซิร์ฟเวอร์")
                        changes_desc.append(f"ชื่อ: `{before.name}` → `{after.name}` (**คืนกลับแล้ว**) ")
                    except: 
                        changes_desc.append(f"ชื่อ: `{before.name}` → `{after.name}` (ไม่สามารถคืนกลับ)")
                # เปลี่ยนรูปดิสกลับ
                if icon_changed:
                    try:
                        if before.icon:
                            icon_bytes = await before.icon.read()
                            await after.edit(icon=icon_bytes, reason="[Anti-Hijack] คืนรูปโปรไฟล์เซิร์ฟเวอร์")
                            changes_desc.append("รูปโปรไฟล์เซิร์ฟเวอร์ (**คืนกลับแล้ว**)")
                        else:
                            changes_desc.append("รูปโปรไฟล์เซิร์ฟเวอร์ถูกเปลี่ยน")
                    except:
                        changes_desc.append("รูปโปรไฟล์เซิร์ฟเวอร์ (ไม่สามารถคืนกลับ)")

                # ริบยศแอดมิน
                if isinstance(editor, discord.Member):
                    for role in editor.roles:
                        if role.permissions.administrator or role.permissions.manage_guild:
                            try: await editor.remove_roles(role, reason="[Anti-Hijack] ริบสิทธิ์เนื่องจากแก้ไขข้อมูลเซิร์ฟเวอร์โดยไม่ได้รับอนุญาต")
                            except: pass

                increment_security_stat(after.id, "anti_server_hijack")
                await send_audit_log(after, "🏰 ANTI-SERVER HIJACK ทำงาน!",
                    f"ตรวจพบ {editor.mention} แก้ไขข้อมูลเซิร์ฟเวอร์:\n" + "\n".join(changes_desc) +
                    f"\n⚡ **ริบสิทธิ์แอดมินของผู้กระทำทันที!**",
                    discord.Color.dark_red())
                await dm_alert_owner(after, "🏰 ANTI-SERVER HIJACK DETECTED!",
                    f"ตรวจพบ {editor.mention} (`{editor.id}`) พยายามแก้ไขข้อมูลเซิร์ฟเวอร์\n" + "\n".join(changes_desc) +
                    f"\nบอทได้ทำการคืนค่าและริบยศผู้กระทำทันที!")
                break
        except Exception as e:
            print(f"Anti-Hijack Error: {e}")

    # ==========================================
    # 🏠 ANTI-CHANNEL TAMPERING GUARD
    # ==========================================
    @commands.Cog.listener()
    async def on_guild_channel_update(self, before, after):
        guild = after.guild
        conf = get_config(guild.id)
        if not conf.get("anti_nuke", True): return

        tampered = (
            before.name != after.name or 
            getattr(before, 'topic', None) != getattr(after, 'topic', None) or
            getattr(before, 'slowmode_delay', None) != getattr(after, 'slowmode_delay', None) or
            getattr(before, 'nsfw', None) != getattr(after, 'nsfw', None) or
            before.overwrites != after.overwrites
        )
        if not tampered: return

        try:
            async for entry in guild.audit_logs(action=discord.AuditLogAction.channel_update, limit=1):
                if entry.target.id == after.id:
                    actor = entry.user
                    if not actor or actor.bot or actor.id == guild.owner_id: return
                    is_wl = isinstance(actor, discord.Member) and any(r.id in get_whitelist(guild.id) for r in actor.roles)
                    if is_wl: return

                    now = time.time()
                    channel_edit_timestamps[guild.id][actor.id].append(now)
                    channel_edit_timestamps[guild.id][actor.id] = [t for t in channel_edit_timestamps[guild.id][actor.id] if now - t < 10]

                    if len(channel_edit_timestamps[guild.id][actor.id]) >= 4:
                        if isinstance(actor, discord.Member):
                            for role in actor.roles:
                                if role.permissions.administrator or role.permissions.manage_channels or role.permissions.manage_guild:
                                    try: await actor.remove_roles(role, reason="[Anti-Channel Tampering] ดัดแปลงห้องรัวเกินกำหนด")
                                    except: pass
                        increment_security_stat(guild.id, "channel_tampering")
                        await send_audit_log(guild, "🚨 ANTI-CHANNEL TAMPERING ทำงาน!", 
                            f"ตรวจพบ {actor.mention} แก้ไขข้อมูลห้อง {after.mention} รัวเกินกำหนด (> 4 ครั้งใน 10 วินาที)\n⚡ **ทำการริบสิทธิ์ทันที!**", 
                            discord.Color.red())
                        await dm_alert_owner(guild, "🚨 ANTI-CHANNEL TAMPERING ATTACK!", 
                            f"ผู้ใช้ {actor.mention} (`{actor.id}`) ดัดแปลงห้องรัวในเซิร์ฟเวอร์ (> 4 ครั้ง/10 วิ)\nบอทได้ทำการริบยศแอดมินทันที")
                        channel_edit_timestamps[guild.id][actor.id].clear()
                    break
        except Exception as e:
            print(f"Channel Update Check Error: {e}")

    # ==========================================
    # 💀 ANTI-EMOJI NUKE GUARD
    # ==========================================
    @commands.Cog.listener()
    async def on_guild_emojis_update(self, guild, before, after):
        if len(after) >= len(before): return
        conf = get_config(guild.id)
        if not conf.get("anti_nuke", True): return

        try:
            async for entry in guild.audit_logs(action=discord.AuditLogAction.emoji_delete, limit=1):
                actor = entry.user
                if not actor or actor.bot or actor.id == guild.owner_id: return
                is_wl = isinstance(actor, discord.Member) and any(r.id in get_whitelist(guild.id) for r in actor.roles)
                if is_wl: return

                now = time.time()
                emoji_delete_timestamps[guild.id][actor.id].append(now)
                emoji_delete_timestamps[guild.id][actor.id] = [t for t in emoji_delete_timestamps[guild.id][actor.id] if now - t < 10]

                if len(emoji_delete_timestamps[guild.id][actor.id]) >= 3:
                    if isinstance(actor, discord.Member):
                        for role in actor.roles:
                            if role.permissions.administrator or role.permissions.manage_guild or role.permissions.manage_expressions:
                                try: await actor.remove_roles(role, reason="[Anti-Emoji Nuke] ลบอิโมจิรัว")
                                except: pass
                    increment_security_stat(guild.id, "emoji_nuke")
                    await send_audit_log(guild, "🚨 ANTI-EMOJI NUKE ทำงาน!", 
                        f"ตรวจพบ {actor.mention} ลบอิโมจิรัวเกินกำหนด (>= 3 ตัวใน 10 วินาที)\n⚡ **ทำการริบสิทธิ์ทันที!**", 
                        discord.Color.red())
                    await dm_alert_owner(guild, "🚨 ANTI-EMOJI NUKE DETECTED!", 
                        f"ผู้ใช้ {actor.mention} (`{actor.id}`) ไล่ลบอิโมจิในเซิร์ฟเวอร์\nบอทได้ทำการริบยศทันที")
                    emoji_delete_timestamps[guild.id][actor.id].clear()
                break
        except Exception as e:
            print(f"Emoji Update Error: {e}")

    # ==========================================
    # 💀 ANTI-STICKER NUKE GUARD
    # ==========================================
    @commands.Cog.listener()
    async def on_guild_stickers_update(self, guild, before, after):
        if len(after) >= len(before): return
        conf = get_config(guild.id)
        if not conf.get("anti_nuke", True): return

        try:
            async for entry in guild.audit_logs(action=discord.AuditLogAction.sticker_delete, limit=1):
                actor = entry.user
                if not actor or actor.bot or actor.id == guild.owner_id: return
                is_wl = isinstance(actor, discord.Member) and any(r.id in get_whitelist(guild.id) for r in actor.roles)
                if is_wl: return

                now = time.time()
                sticker_delete_timestamps[guild.id][actor.id].append(now)
                sticker_delete_timestamps[guild.id][actor.id] = [t for t in sticker_delete_timestamps[guild.id][actor.id] if now - t < 10]

                if len(sticker_delete_timestamps[guild.id][actor.id]) >= 3:
                    if isinstance(actor, discord.Member):
                        for role in actor.roles:
                            if role.permissions.administrator or role.permissions.manage_guild or role.permissions.manage_expressions:
                                try: await actor.remove_roles(role, reason="[Anti-Sticker Nuke] ลบสติกเกอร์รัว")
                                except: pass
                    increment_security_stat(guild.id, "sticker_nuke")
                    await send_audit_log(guild, "🚨 ANTI-STICKER NUKE ทำงาน!", 
                        f"ตรวจพบ {actor.mention} ลบสติกเกอร์รัวเกินกำหนด (>= 3 ตัวใน 10 วินาที)\n⚡ **ทำการริบสิทธิ์ทันที!**", 
                        discord.Color.red())
                    await dm_alert_owner(guild, "🚨 ANTI-STICKER NUKE DETECTED!", 
                        f"ผู้ใช้ {actor.mention} (`{actor.id}`) ไล่ลบสติกเกอร์ในเซิร์ฟเวอร์\nบอทได้ทำการริบยศทันที")
                    sticker_delete_timestamps[guild.id][actor.id].clear()
                break
        except Exception as e:
            print(f"Sticker Update Error: {e}")

    # ==========================================
    # 🔓 ANTI-UNBAN BYPASS GUARD
    # ==========================================
    @commands.Cog.listener()
    async def on_member_unban(self, guild: discord.Guild, user: discord.User):
        conf = get_config(guild.id)
        if not conf.get("anti_unban_guard", True): return

        try:
            async for entry in guild.audit_logs(action=discord.AuditLogAction.unban, limit=1):
                if entry.target.id == user.id:
                    actor = entry.user
                    if not actor or actor.bot or actor.id == guild.owner_id: return
                    is_wl = isinstance(actor, discord.Member) and any(r.id in get_whitelist(guild.id) for r in actor.roles)
                    if is_wl: return

                    # Actor is not owner or whitelisted! Unban bypass detected!
                    try:
                        await guild.ban(user, reason="[Anti-Unban Bypass] ปลดแบนโดยแอดมินที่ไม่ได้รับอนุญาต")
                    except: pass

                    if isinstance(actor, discord.Member):
                        for role in actor.roles:
                            if role.permissions.administrator or role.permissions.ban_members or role.permissions.manage_guild:
                                try: await actor.remove_roles(role, reason="[Anti-Unban Bypass] ริบสิทธิ์เนื่องจากปลดแบนโดยพลการ")
                                except: pass

                    increment_security_stat(guild.id, "anti_unban_bypass")
                    await send_audit_log(guild, "🔓 ANTI-UNBAN BYPASS ทำงาน!", 
                        f"ตรวจพบ {actor.mention} แอบปลดแบนสมาชิก {user.mention} (`{user.id}`)\n"
                        f"⚡ **ทำการแบนสมาชิกคนดังกล่าวกลับทันที + ริบสิทธิ์แอดมินของผู้ปลดแบน!**", 
                        discord.Color.dark_red())
                    await dm_alert_owner(guild, "🔓 ANTI-UNBAN BYPASS DETECTED!", 
                        f"ผู้ใช้ {actor.mention} (`{actor.id}`) แอบปลดแบน {user.name} (`{user.id}`) โดยไม่ได้รับอนุญาต\n"
                        f"บอทได้ทำการแบนผู้ใช้กลับและริบยศของผู้กระทำแล้ว")
                    break
        except Exception as e:
            print(f"Anti-Unban Bypass Error: {e}")

    @commands.Cog.listener()
    async def on_thread_create(self, thread: discord.Thread):
        guild = thread.guild
        owner = thread.owner or guild.get_member(thread.owner_id)
        if not owner or owner.bot: return

        now = time.time()
        thread_create_timestamps[guild.id][owner.id].append(now)
        thread_create_timestamps[guild.id][owner.id] = [t for t in thread_create_timestamps[guild.id][owner.id] if now - t < 10]

        if len(thread_create_timestamps[guild.id][owner.id]) >= 3:
            try:
                await thread.delete(reason="[Anti-Thread Raid] สแปมสร้างห้องย่อย/Forum ถี่เกินกำหนด")
                await owner.timeout(datetime.timedelta(minutes=10), reason="Anti-Thread Raid")
                increment_security_stat(guild.id, "thread_raid")
                await send_audit_log(guild, "🧵 สกัดกั้น Thread/Forum Raid!", f"ลบห้องย่อยสแปม และจับ {owner.mention} Timeout 10 นาที (สร้างเกิน 3 ห้องใน 10 วิ)", discord.Color.red())
                thread_create_timestamps[guild.id][owner.id].clear()
            except: pass

    @commands.Cog.listener()
    async def on_webhooks_update(self, channel):
        guild = channel.guild
        conf = get_config(guild.id)
        if not conf.get("webhook_guard"): return

        try:
            async for entry in guild.audit_logs(action=discord.AuditLogAction.webhook_create, limit=1):
                creator = entry.user
                if creator and not creator.bot and creator.id != guild.owner_id:
                    is_wl = any(r.id in get_whitelist(guild.id) for r in creator.roles) if isinstance(creator, discord.Member) else False
                    if not is_wl:
                        try:
                            webhooks = await channel.webhooks()
                            for wh in webhooks:
                                if wh.id == entry.target.id or (wh.user and wh.user.id == creator.id):
                                    await wh.delete(reason="[Webhook Guard] สกัดกั้นการสร้าง Webhook โดยไม่อยู่ใน Whitelist")
                        except: pass

                        try:
                            await guild.ban(creator, reason="[Webhook Guard] สั่งแบนผู้สร้าง Webhook ที่ไม่ได้อยู่ใน Whitelist ทันที")
                            ban_info = f"\n🔨 **สั่งแบนผู้สร้าง Webhook ทันที:** {creator.mention} (`{creator.id}`)"
                        except:
                            ban_info = f"\n⚠️ **ผู้สร้าง:** {creator.mention}"

                        increment_security_stat(guild.id, "webhook_guard")
                        await send_audit_log(guild, "🚨 สกัดการสร้าง Webhook ไม่อนุญาต!", f"ตรวจพบ {creator.mention} สร้าง Webhook ใน {channel.mention}\n⚡ **ทำการทำลาย Webhook ทันที!**{ban_info}", discord.Color.dark_red())
                        await dm_alert_owner(guild, "🚨 สกัดการสร้าง Webhook ไม่อนุญาต!", f"ตรวจพบ {creator.mention} (`{creator.id}`) สร้าง Webhook ใน {channel.mention}\nบอทได้ทำลาย Webhook และสั่งแบนเรียบร้อย")
                        return
        except Exception as e:
            print(f"Webhook Audit Check Error: {e}")

        now = time.time()
        webhook_update_timestamps[guild.id].append(now)
        webhook_update_timestamps[guild.id] = [t for t in webhook_update_timestamps[guild.id] if now - t < 60]
        
        if len(webhook_update_timestamps[guild.id]) >= 3:
            try:
                webhooks = await channel.webhooks()
                for wh in webhooks:
                    await wh.delete(reason="[Webhook Guard] สกัดการสร้าง Webhook สแปมเพื่อโจมตี")
                increment_security_stat(guild.id, "webhook_guard")
                await send_audit_log(guild, "🔗 Webhook Guard ทำงาน", f"สกัดกั้นการสแปม Webhook ใน {channel.mention} และเคลียร์ทิ้งทั้งหมด", discord.Color.red())
                webhook_update_timestamps[guild.id].clear()
            except: pass

    @commands.Cog.listener()
    async def on_voice_state_update(self, member, before, after):
        if member.bot: return
        if before.channel == after.channel: return
        
        conf = get_config(member.guild.id)
        if not conf.get("voice_anti_raid"): return

        now = time.time()
        guild_id = member.guild.id
        voice_join_timestamps[guild_id][member.id].append(now)
        voice_join_timestamps[guild_id][member.id] = [t for t in voice_join_timestamps[guild_id][member.id] if now - t < 10]
        
        if len(voice_join_timestamps[guild_id][member.id]) >= 5:
            try:
                await member.move_to(None)
                await member.timeout(datetime.timedelta(minutes=10), reason="Voice Spam / Channel Hopping")
                increment_security_stat(guild_id, "voice_spam")
                await send_audit_log(member.guild, "🎙️ สกัด Voice Spam", f"{member.mention} ถูกจับ Timeout โทษฐานกวนประสาทเข้าออกห้องเสียงถี่เกินไป (เกิน 5 ครั้ง/10 วิ)", discord.Color.red())
                voice_join_timestamps[guild_id][member.id].clear()
            except: pass

    # ==========================================
    # 🔐 ANTI-PERMISSION ESCALATION & MASS ROLE EDIT
    # ==========================================
    @commands.Cog.listener()
    async def on_guild_role_update(self, before: discord.Role, after: discord.Role):
        guild = after.guild
        conf = get_config(guild.id)

        # 1. 🔐 Anti-Permission Escalation Guard (ดักจับการแอบเปิดสิทธิ์อันตราย)
        if conf.get("enforce_permissions", True) and before.permissions != after.permissions:
            DANGEROUS_PERMS = {
                "administrator": "Administrator",
                "manage_guild": "Manage Server",
                "ban_members": "Ban Members",
                "kick_members": "Kick Members",
                "manage_channels": "Manage Channels",
                "manage_roles": "Manage Roles",
                "manage_webhooks": "Manage Webhooks",
                "mention_everyone": "Mention Everyone",
                "manage_expressions": "Manage Expressions"
            }
            escalated_perms = []
            for perm_attr, perm_name in DANGEROUS_PERMS.items():
                was_on = getattr(before.permissions, perm_attr, False)
                now_on = getattr(after.permissions, perm_attr, False)
                if not was_on and now_on:
                    escalated_perms.append(perm_name)

            if escalated_perms and after.id not in get_whitelist(guild.id):
                try:
                    async for entry in guild.audit_logs(action=discord.AuditLogAction.role_update, limit=1):
                        if entry.target.id == after.id:
                            editor = entry.user
                            if editor and editor.id != guild.owner_id:
                                is_wl = isinstance(editor, discord.Member) and any(r.id in get_whitelist(guild.id) for r in editor.roles)
                                if not is_wl:
                                    try:
                                        await after.edit(permissions=before.permissions, reason="[Anti-Permission Escalation] คืนค่าสิทธิ์อันตราย")
                                    except: pass

                                    if isinstance(editor, discord.Member):
                                        for role in editor.roles:
                                            if (role.permissions.administrator or role.permissions.manage_roles or 
                                                role.permissions.manage_guild or role.permissions.ban_members):
                                                try: await editor.remove_roles(role, reason="[Anti-Permission Escalation] ริบสิทธิ์เนื่องจากเปิดสิทธิ์อันตรายโดยไม่ได้รับอนุญาต")
                                                except: pass

                                    increment_security_stat(guild.id, "permission_escalation")
                                    perms_list = ", ".join(escalated_perms)
                                    await send_audit_log(guild, "🔐 ANTI-PERMISSION ESCALATION ทำงาน!",
                                        f"ตรวจพบ {editor.mention} พยายามเปิดสิทธิ์อันตรายให้กับยศ {after.mention}:\n"
                                        f"📌 **สิทธิ์ที่พยายามเปิด:** `{perms_list}`\n"
                                        f"⚡ **คืนค่าสิทธิ์ยศทันที + ริบสิทธิ์แอดมินของผู้กระทำ!**",
                                        discord.Color.dark_red())
                                    await dm_alert_owner(guild, "🔐 PERMISSION ESCALATION ATTACK!",
                                        f"ตรวจพบ {editor.mention} (`{editor.id}`) พยายามเปิดสิทธิ์อันตราย ({perms_list}) ให้ยศ `{after.name}`\n"
                                        f"บอทได้คืนค่าสิทธิ์และริบยศผู้กระทำทันที!")
                            break
                except Exception as e:
                    print(f"Permission Escalation Error: {e}")

        # 2. 🛑 Anti-Mass Role Edit Guard (ดักจับการไล่แก้ไขยศรัว)
        if conf.get("anti_nuke", True):
            role_changed = (
                before.name != after.name or
                before.color != after.color or
                before.hoist != after.hoist or
                before.mentionable != after.mentionable or
                before.permissions != after.permissions
            )
            if role_changed:
                try:
                    async for entry in guild.audit_logs(action=discord.AuditLogAction.role_update, limit=1):
                        if entry.target.id == after.id:
                            editor = entry.user
                            if not editor or editor.bot or editor.id == guild.owner_id: return
                            is_wl = isinstance(editor, discord.Member) and any(r.id in get_whitelist(guild.id) for r in editor.roles)
                            if is_wl: return

                            now = time.time()
                            role_edit_timestamps[guild.id][editor.id].append(now)
                            role_edit_timestamps[guild.id][editor.id] = [t for t in role_edit_timestamps[guild.id][editor.id] if now - t < 10]

                            if len(role_edit_timestamps[guild.id][editor.id]) >= 4:
                                if isinstance(editor, discord.Member):
                                    for role in editor.roles:
                                        if role.permissions.administrator or role.permissions.manage_roles or role.permissions.manage_guild:
                                            try: await editor.remove_roles(role, reason="[Anti-Mass Role Edit] แก้ไขยศรัวเกินกำหนด")
                                            except: pass
                                increment_security_stat(guild.id, "mass_role_edit")
                                await send_audit_log(guild, "🚨 ANTI-MASS ROLE EDIT ทำงาน!",
                                    f"ตรวจพบ {editor.mention} แก้ไขยศรัวเกินกำหนด (> 4 ครั้งใน 10 วินาที)\n"
                                    f"⚡ **ทำการริบสิทธิ์ทันที!**",
                                    discord.Color.red())
                                await dm_alert_owner(guild, "🚨 MASS ROLE EDIT DETECTED!",
                                    f"ผู้ใช้ {editor.mention} (`{editor.id}`) ไล่แก้ไขยศในเซิร์ฟเวอร์ (> 4 ครั้ง/10 วิ)\n"
                                    f"บอทได้ทำการริบยศทันที")
                                role_edit_timestamps[guild.id][editor.id].clear()
                            break
                except Exception as e:
                    print(f"Mass Role Edit Error: {e}")

    @commands.Cog.listener()
    async def on_message_delete(self, message: discord.Message):
        if not message.guild or message.author.bot: return
        conf = get_config(message.guild.id)
        if not conf.get("ghost_ping_guard"): return

        has_ping = message.mentions or message.role_mentions or "@everyone" in message.content or "@here" in message.content
        if has_ping:
            pings_count = len(message.mentions) + len(message.role_mentions)
            if "@everyone" in message.content: pings_count += 1
            if "@here" in message.content: pings_count += 1
            
            await send_audit_log(
                message.guild,
                "👻 Ghost Ping Detected!",
                f"ผู้ใช้: {message.author.mention} (`{message.author.id}`)\n"
                f"ช่อง: {message.channel.mention}\n"
                f"ข้อความที่ถูกลบ: `{message.content[:200]}`\n"
                f"จำนวนการแท็ก: {pings_count} ครั้ง",
                discord.Color.gold()
            )

    @commands.Cog.listener()
    async def on_message_edit(self, before: discord.Message, after: discord.Message):
        if not after.guild or after.author.bot or before.content == after.content: return
        await self.on_message(after)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if not message.guild: return
        conf = get_config(message.guild.id)

        # 🚨 GLOBAL PANIC CHECK: หากเปิดใช้งาน Panic Mode ให้บล็อกและลบการส่งข้อความจากสมาชิกทั่วไป/เว็บฮุคทันที
        if conf.get("global_panic"):
            if message.author.id != self.bot.user.id:
                is_wl = False
                if message.author.id == message.guild.owner_id:
                    is_wl = True
                elif isinstance(message.author, discord.Member):
                    is_wl = message.author.guild_permissions.administrator or any(r.id in get_whitelist(message.guild.id) for r in message.author.roles)
                
                if not is_wl:
                    await safe_delete(message)
                    return

        # 🔣 Anti-Zalgo & Anti-Crash Text Filter
        if conf.get("anti_zalgo") and message.content:
            if not message.author.bot and isinstance(message.author, discord.Member):
                is_wl = message.author.guild_permissions.administrator or any(r.id in get_whitelist(message.guild.id) for r in message.author.roles)
                if not is_wl:
                    if is_zalgo_text(message.content) or is_crash_text(message.content):
                        await safe_delete(message)
                        try:
                            await message.author.timeout(datetime.timedelta(minutes=10), reason="[Anti-Zalgo] ส่งข้อความ Zalgo/Crash Text")
                        except: pass
                        increment_security_stat(message.guild.id, "anti_zalgo")
                        await send_audit_log(message.guild, "🔣 Anti-Zalgo ทำงาน!",
                            f"ลบข้อความ Zalgo/Crash Text จาก {message.author.mention}\n"
                            f"⏰ **Timeout 10 นาที**",
                            discord.Color.orange())
                        return

        if message.webhook_id:
            now = time.time()
            wh_id = message.webhook_id
            g_id = message.guild.id
            webhook_msg_timestamps[g_id][wh_id].append(now)
            webhook_msg_timestamps[g_id][wh_id] = [t for t in webhook_msg_timestamps[g_id][wh_id] if now - t < 5]
            
            content_lower = message.content.lower() if message.content else ""
            is_nuke_spam_phrase = any(w in content_lower for w in ["cybernuvex", "โกโก้กลัว", "จำกูได้ป่ะ", "ไอ้พวกโง่", "ยิงดิส", "nuke", "raid", "bypass"])
            is_rapid_spam = len(webhook_msg_timestamps[g_id][wh_id]) >= 2

            if is_rapid_spam or is_nuke_spam_phrase:
                # 💥 BULK PURGE: กวาดลบข้อความสแปมค้างย้อนหลังของ Webhook นี้ทันที ไม่ให้เหลือค้างในช่องแชท (รองรับสูงสุด 500 ข้อความ)
                try:
                    await message.channel.purge(
                        limit=500, 
                        check=lambda m: m.webhook_id == wh_id or (m.author and m.author.name == message.author.name and m.webhook_id is not None)
                    )
                except Exception:
                    await safe_delete(message)

                try:
                    webhooks = await message.channel.webhooks()
                    target_wh = next((wh for wh in webhooks if wh.id == wh_id), None)
                    if target_wh:
                        await target_wh.delete(reason="[Webhook Guard] สกัดกั้นการสแปม Webhook ยิงดิส")
                    
                    creator_user = None
                    async for entry in message.guild.audit_logs(action=discord.AuditLogAction.webhook_create, limit=5):
                        if entry.target and entry.target.id == wh_id:
                            creator_user = entry.user
                            break
                    
                    ban_info = ""
                    if creator_user and not creator_user.bot and creator_user.id != message.guild.owner_id:
                        try:
                            await message.guild.ban(creator_user, reason="[Webhook Nuke Defense] สั่งแบนผู้สร้าง Webhook ที่ยิงสแปมเซิร์ฟเวอร์")
                            ban_info = f"\n🔨 **สั่งแบนผู้สร้าง Webhook ทันที:** {creator_user.mention} (`{creator_user.id}`)"
                        except: pass

                    increment_security_stat(g_id, "webhook_attack")
                    await send_audit_log(
                        message.guild, 
                        "🚨 สกัดกั้น WEBHOOK SPAM ATTACK!", 
                        f"ตรวจพบการยิงสแปมผ่าน Webhook ใน {message.channel.mention}\n"
                        f"⚡ **ทำการลบ Webhook ทิ้งและกวาดลบข้อความค้างทั้งหมด!**{ban_info}", 
                        discord.Color.dark_red()
                    )
                    await dm_alert_owner(message.guild, "🚨 WEBHOOK SPAM ATTACK BLOCKED!",
                        f"ตรวจพบการยิงสแปมผ่าน Webhook ใน {message.channel.mention}\n"
                        f"บอทได้ทำการลบ Webhook และกวาดล้างข้อความทั้งหมดแล้ว!{ban_info}")
                    webhook_msg_timestamps[g_id][wh_id].clear()
                except Exception as e:
                    print(f"Webhook Attack Defense Error: {e}")
                return

        if conf.get("honeypot_channel_id") and message.channel.id == conf["honeypot_channel_id"]:
            if not message.author.bot:
                await safe_delete(message)
                try: 
                    await message.author.ban(reason="[Honeypot Trap] บอทสแปมติดกับดักล่องหน")
                    increment_security_stat(message.guild.id, "honeypot_trap")
                    await send_audit_log(message.guild, "🍯 กับดักล่อบอททำงาน!", f"ผู้ใช้ {message.author.mention} ถูกแบนทันที เนื่องจากบุกรุกห้องล่องหนที่คนปกติมองไม่เห็น", discord.Color.dark_red())
                    await dm_alert_owner(message.guild, "🍯 HONEYPOT TRAP TRIGGERED!", f"ผู้ใช้ {message.author.mention} (`{message.author.id}`) ถูกแบนทันที เนื่องจากบุกรุกห้องล่องหน (Honeypot)")
                except: pass
            return

        content = message.content.strip() if message.content else ""

        if content and re.search(DISCORD_TOKEN_REGEX, content):
            try:
                await safe_delete(message)
                increment_security_stat(message.guild.id, "token_leak")
                await send_audit_log(message.guild, "🚨 ตรวจพบ DISCORD BOT TOKEN LEAK!", f"ผู้ใช้ {message.author.mention} โพสต์ Discord Bot Token ใน {message.channel.mention}\n*ลบข้อความทันทีเพื่อป้องกันบอทถูกแฮก*", discord.Color.dark_red())
                try: await message.author.send("⚠️ **คำเตือนความปลอดภัย:** คุณได้ส่ง Discord Bot Token ในช่องสาธารณะ! ระบบได้ทำการลบข้อความนั้นทันทีเพื่อความปลอดภัย กรุณาไปที่ Discord Developer Portal และสั่ง Reset Token ทันที")
                except: pass
            except: pass
            return

        if message.webhook_id or (message.author.bot and message.author.id != self.bot.user.id):
            if content and re.search(URL_REGEX, content, re.IGNORECASE):
                try: await safe_delete(message)
                except: pass
                return

        if message.author.bot: return

        is_wl = isinstance(message.author, discord.Member) and (message.author.guild_permissions.administrator or any(r.id in get_whitelist(message.guild.id) for r in message.author.roles))

        if not is_wl and isinstance(message.author, discord.Member):
            user = message.author
            now = time.time()

            if conf.get("anti_invite") and content:
                invite_match = re.search(r"(https?://)?(www\.)?(discord\.gg|discord\.com/invite|discordapp\.com/invite|discord\.com/oauth2|discord\.com/api/oauth2)/([a-zA-Z0-9_?&=.-]+)", content, re.IGNORECASE)
                if invite_match:
                    code = invite_match.group(4)
                    guild_invites = await get_cached_guild_invites(message.guild)
                    
                    if code not in guild_invites:
                        try:
                            await safe_delete(message)
                            increment_security_stat(message.guild.id, "anti_invite")
                            await send_audit_log(message.guild, "🔗 Anti-Invite / OAuth2 Guard", f"ลบลิงก์เชิญเซิร์ฟเวอร์/OAuth2 จาก {user.mention} ในช่อง {message.channel.mention}\nข้อความ: `{content}`", discord.Color.orange())
                            try: await user.send("⚠️ **เตือนความปลอดภัย:** ไม่อนุญาตให้โพสต์ลิงก์เชิญเข้า Discord หรือลิงก์ OAuth2 ดึงสิทธิ์ในเซิร์ฟเวอร์นี้")
                            except: pass
                            return
                        except: pass

            if conf.get("image_scanner") and message.attachments:
                for att in message.attachments:
                    if att.content_type and att.content_type.startswith('image/'):
                        async with aiohttp.ClientSession() as session:
                            async with session.get(att.url) as resp:
                                if resp.status == 200:
                                    image_data = await resp.read()
                                    extracted_text = await self.bot.loop.run_in_executor(None, extract_text_from_image, image_data)
                                    
                                    if extracted_text:
                                        if any(w in extracted_text.lower() for w in BAD_WORDS) or re.search(URL_REGEX, extracted_text, re.IGNORECASE):
                                            await safe_delete(message)
                                            try: 
                                                await user.timeout(datetime.timedelta(hours=1), reason="OCR: ตรวจพบข้อความ/ลิงก์อันตรายในรูปภาพ")
                                                increment_security_stat(message.guild.id, "image_scanner")
                                                await send_audit_log(message.guild, "🖼️ OCR สกัดกั้นภาพสแปม", f"ตรวจพบเนื้อหาอันตรายในรูปภาพจาก {user.mention}\nข้อความที่ถอดได้: `{extracted_text}`", discord.Color.red())
                                            except: pass
                                            return

            if conf.get("self_bot") and len(content) > 150:
                last_msg_time = user_message_timestamps[user.id][-1] if user_message_timestamps[user.id] else 0
                if last_msg_time > 0 and (now - last_msg_time) < 0.5:
                    await safe_delete(message)
                    try:
                        await user.timeout(datetime.timedelta(hours=1), reason="Self-Bot Detection: ส่งข้อความยาวเร็วกว่ามนุษย์")
                        increment_security_stat(message.guild.id, "self_bot")
                        await send_audit_log(message.guild, "🤖 Self-Bot ตรวจพบ!", f"{user.mention} ถูกจับ Mute เนื่องจากพิมพ์ข้อความยาวกว่า 150 ตัวอักษรภายในเสี้ยววินาที", discord.Color.red())
                    except: pass
                    return

            if conf.get("anti_dox") and content:
                clean_text = re.sub(r"```[\s\S]*?```|`[^`]*`", "", content)
                clean_text = re.sub(URL_REGEX, "", clean_text, flags=re.IGNORECASE)

                thai_ids = re.findall(r"\b[1-9]\d{12}\b", clean_text)
                has_real_thai_id = any(is_valid_thai_id(tid) for tid in thai_ids)

                ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", clean_text)
                has_real_ip = any(is_valid_public_ip(ip) for ip in ips)

                phones = re.findall(r"\b(?:06|08|09)\d{8}\b", clean_text)
                has_phone = len(phones) > 0

                if has_real_thai_id or has_real_ip or has_phone:
                    await safe_delete(message)
                    try: 
                        await user.timeout(datetime.timedelta(hours=2), reason="Anti-Dox: เปิดเผยข้อมูลส่วนตัว/สำคัญ")
                        increment_security_stat(message.guild.id, "anti_dox")
                        await send_audit_log(message.guild, "👁️ ANTI-DOX ทำงาน", f"สกัดกั้นการเปิดเผยข้อมูลสำคัญ (เบอร์/IP/เลขบัตร) จาก {user.mention}", discord.Color.red())
                    except: pass
                    return

            if conf["anti_mention"] and (len(message.mentions) + len(message.role_mentions)) >= 5:
                await safe_delete(message)
                try: 
                    await user.timeout(datetime.timedelta(hours=1))
                    increment_security_stat(message.guild.id, "anti_mention")
                except: pass
                return

            # 🌐 Enhanced Phishing & Typosquatting Detection
            if conf.get("phishing_api"):
                is_typo, typo_reason = is_typosquatting(content) if content else (False, "")
                has_link = re.search(URL_REGEX, content, re.IGNORECASE) if content else False
                has_scam = False
                scam_reason = ""
                if is_typo:
                    has_scam = True
                    scam_reason = typo_reason
                elif has_link:
                    urls = re.findall(URL_REGEX, content, re.IGNORECASE)
                    for url in urls:
                        if await check_phishing_api(url):
                            has_scam = True
                            scam_reason = f"ตรวจพบลิงก์ฟิชชิ่ง/สแกม: `{url}`"
                            break

                if has_scam:
                    await safe_delete(message)
                    try: 
                        await user.ban(reason=f"[Phishing Guard] {scam_reason}")
                        ban_status = "🔨 **สั่งแบนผู้ใช้ทันที**"
                    except:
                        try:
                            await user.timeout(datetime.timedelta(hours=24), reason=scam_reason)
                            ban_status = "⏰ **Timeout 24 ชั่วโมง**"
                        except:
                            ban_status = "⚠️ **ลบข้อความสกัดกั้น**"

                    increment_security_stat(message.guild.id, "phishing_typosquatting")
                    await send_audit_log(message.guild, "🌐 สกัดกั้น Phishing / Typosquatting!",
                        f"ผู้ใช้: {user.mention} (`{user.id}`)\n"
                        f"ช่อง: {message.channel.mention}\n"
                        f"สาเหตุ: {scam_reason}\n"
                        f"{ban_status}",
                        discord.Color.dark_red())
                    await dm_alert_owner(message.guild, "🌐 PHISHING ATTACK DETECTED!",
                        f"ตรวจพบ {user.mention} (`{user.id}`) ส่งลิงก์ Phishing ใน {message.channel.mention}\n"
                        f"สาเหตุ: {scam_reason}\n{ban_status}")
                    return

            if conf["malware"] and message.attachments:
                for att in message.attachments:
                    if att.filename.lower().endswith(DANGEROUS_EXTENSIONS):
                        await safe_delete(message)
                        increment_security_stat(message.guild.id, "malware")
                        return

            if conf["ai"] and content:
                is_mal, _ = await analyze_content_with_ai(content)
                if is_mal:
                    await safe_delete(message)
                    increment_security_stat(message.guild.id, "ai_filter")
                    return

            user_message_timestamps[user.id].append(now)
            user_message_timestamps[user.id] = [t for t in user_message_timestamps[user.id] if now - t < SPAM_INTERVAL]
            if len(user_message_timestamps[user.id]) >= SPAM_THRESHOLD:
                await safe_delete(message)
                try: 
                    await user.timeout(datetime.timedelta(minutes=10))
                    increment_security_stat(message.guild.id, "chat_spam")
                except: pass
                return

            if BAD_WORDS and content and any(w in content.lower() for w in BAD_WORDS):
                await safe_delete(message)
                return


async def setup(bot):
    await bot.add_cog(SecurityEventsCog(bot))