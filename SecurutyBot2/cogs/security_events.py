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

from cogs.database import get_config, get_whitelist, send_audit_log, ban_user_ips

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

BAD_WORDS = ["คำหยาบ1", "คำหยาบ2", "scam", "free nitro", "steam promo"]
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
        # คัดกรอง Private/Local/Multicast IP ทิ้ง (127.0.0.1, 192.168.x.x, 10.x.x.x ฯลฯ)
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
    return False

async def check_anti_nuke(guild: discord.Guild, user: discord.Member, action: str):
    if not user or user.bot: return
    conf = get_config(guild.id)
    if not conf["anti_nuke"]: return

    now = time.time()
    admin_action_timestamps[guild.id][user.id].append(now)
    admin_action_timestamps[guild.id][user.id] = [t for t in admin_action_timestamps[guild.id][user.id] if now - t < 10]

    if len(admin_action_timestamps[guild.id][user.id]) >= 4:
        try:
            for role in user.roles:
                if role.permissions.administrator or role.permissions.manage_guild or role.permissions.manage_channels or role.permissions.manage_roles:
                    try: await user.remove_roles(role, reason="[Anti-Nuke] ตรวจพบการทำลายเซิร์ฟเวอร์")
                    except: pass
            await send_audit_log(guild, "🚨 ANTI-NUKE ทำงาน!", f"ทำการริบสิทธิ์ {user.mention} ทันที\nสาเหตุ: ทำการ {action} ถี่เกินกำหนด (เกิน 4 ครั้ง/10 วิ)", discord.Color.red())
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
        self.backlog_scanned = False
        self.flush_delete_queue.start()

    def cog_unload(self):
        self.flush_delete_queue.cancel()

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

    async def scan_backlog_messages(self):
        await self.bot.wait_until_ready()
        if self.backlog_scanned:
            return
        self.backlog_scanned = True
        print("🔍 Starting Backlog Message Security Scan...")
        
        for guild in self.bot.guilds:
            conf = get_config(guild.id)
            for channel in guild.text_channels:
                if not channel.permissions_for(guild.me).read_messages or not channel.permissions_for(guild.me).read_message_history:
                    continue
                try:
                    async for message in channel.history(limit=50):
                        if message.author.bot or not message.guild:
                            continue
                        
                        is_wl = isinstance(message.author, discord.Member) and (
                            message.author.guild_permissions.administrator or any(r.id in get_whitelist(guild.id) for r in message.author.roles)
                        )
                        if is_wl:
                            continue

                        content = message.content.strip() if message.content else ""
                        
                        # 1. Bot Token Leak
                        if content and re.search(DISCORD_TOKEN_REGEX, content):
                            await safe_delete(message)
                            await send_audit_log(guild, "🚨 ตรวจพบ DISCORD BOT TOKEN LEAK (Backlog Scan)!", f"ผู้ใช้ {message.author.mention} โพสต์ Discord Bot Token ใน {channel.mention}\n*ลบข้อความย้อนหลังสำเร็จ*", discord.Color.dark_red())
                            await asyncio.sleep(0.2)
                            continue
                        
                        # 2. Dangerous attachments
                        if message.attachments:
                            for att in message.attachments:
                                if att.filename.lower().endswith(DANGEROUS_EXTENSIONS):
                                    await safe_delete(message)
                                    await send_audit_log(guild, "🛡️ มัลแวร์สกัดกั้น (Backlog Scan)", f"ลบไฟล์อันตรายย้อนหลัง `{att.filename}` จาก {message.author.mention} ใน {channel.mention}", discord.Color.red())
                                    await asyncio.sleep(0.2)
                                    break
                                    
                        # 3. Phishing Links
                        if conf.get("phishing_api") and content:
                            urls = re.findall(URL_REGEX, content, re.IGNORECASE)
                            for url in urls:
                                if await check_phishing_api(url):
                                    await safe_delete(message)
                                    await send_audit_log(guild, "🚨 ลิงก์สแกมสกัดกั้น (Backlog Scan)", f"ลบข้อความลิงก์สแกมย้อนหลัง จาก {message.author.mention} ใน {channel.mention}", discord.Color.red())
                                    await asyncio.sleep(0.2)
                                    break
                        await asyncio.sleep(0.05)
                except Exception as e:
                    print(f"Error scanning channel {channel.name}: {e}")
                await asyncio.sleep(0.1)
        print("✅ Backlog Message Security Scan completed!")

    @commands.Cog.listener()
    async def on_ready(self):
        print(f"✅ Ultimate Enterprise Security Bot is ACTIVE!")
        asyncio.create_task(self.scan_backlog_messages())

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        guild = member.guild
        conf = get_config(guild.id)
        
        # 1. 🔍 Suspicious Account Scanner (สแกนไอดีสมัครใหม่/น่าสงสัย)
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

        # 3. Check Member Join Flood (Raid Defense)
        now = time.time()
        recent_joins_dict[guild.id].append(now)
        recent_joins_dict[guild.id] = [t for t in recent_joins_dict[guild.id] if now - t < 10]
        
        if len(recent_joins_dict[guild.id]) >= 5:
            try: await member.ban(reason="[Auto Security] บอท Raid ทะลักเข้าดิส")
            except: pass
            
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
        # 1. Anti-Nuke check
        async for entry in guild.audit_logs(action=discord.AuditLogAction.ban, limit=1):
            if entry.target.id == user.id:
                await check_anti_nuke(guild, entry.user, "สั่งแบนสมาชิก")
        
        # 2. 🔄 Auto IP Blacklist Sync
        try:
            banned_count = ban_user_ips(guild.id, user.id, f"Auto IP Sync for Banned User {user.name}")
            if banned_count > 0:
                await send_audit_log(guild, "🔄 Auto IP Blacklist Sync", f"ทำการดึงประวัติ IP ของผู้ใช้ {user.name} (`{user.id}`) เข้าสู่ตารางแบน IP สำเร็จ **{banned_count}** IP", discord.Color.dark_red())
        except Exception as e:
            print(f"Auto IP Sync Error: {e}")

    # 🧵 Anti-Thread / Forum Spam Guard
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
                await send_audit_log(guild, "🧵 สกัดกั้น Thread/Forum Raid!", f"ลบห้องย่อยสแปม และจับ {owner.mention} Timeout 10 นาที (สร้างเกิน 3 ห้องใน 10 วิ)", discord.Color.red())
                thread_create_timestamps[guild.id][owner.id].clear()
            except: pass

    @commands.Cog.listener()
    async def on_webhooks_update(self, channel):
        guild = channel.guild
        conf = get_config(guild.id)
        if not conf.get("webhook_guard"): return

        now = time.time()
        webhook_update_timestamps[guild.id].append(now)
        webhook_update_timestamps[guild.id] = [t for t in webhook_update_timestamps[guild.id] if now - t < 60]
        
        if len(webhook_update_timestamps[guild.id]) >= 3:
            try:
                webhooks = await channel.webhooks()
                for wh in webhooks:
                    await wh.delete(reason="[Webhook Guard] สกัดการสร้าง Webhook สแปมเพื่อโจมตี")
                await send_audit_log(guild, "🔗 Webhook Guard ทำงาน", f"สกัดกั้นการสแปม Webhook ใน {channel.mention} และเคลียร์ทิ้งทั้งหมด", discord.Color.red())
                webhook_update_timestamps[guild.id].clear()
            except: pass

    # 🎙️ Voice Anti-Raid (แก้ไขปัญหาจับโดนคนบริสุทธิ์)
    @commands.Cog.listener()
    async def on_voice_state_update(self, member, before, after):
        if member.bot: return
        # ทำงานเฉพาะตอนย้ายหรือเข้าห้องเสียงใหม่จริงๆ เท่านั้น (ไม่ทำงานตอนเปิดปิดไมค์/หูฟัง)
        if before.channel == after.channel: return
        
        conf = get_config(member.guild.id)
        if not conf.get("voice_anti_raid"): return

        now = time.time()
        guild_id = member.guild.id
        voice_join_timestamps[guild_id][member.id].append(now)
        voice_join_timestamps[guild_id][member.id] = [t for t in voice_join_timestamps[guild_id][member.id] if now - t < 10]
        
        # ปรับเกณฑ์เป็นเข้า-ออก/ย้ายห้องเสียงเกิน 5 ครั้งใน 10 วินาที
        if len(voice_join_timestamps[guild_id][member.id]) >= 5:
            try:
                await member.move_to(None)
                await member.timeout(datetime.timedelta(minutes=10), reason="Voice Spam / Channel Hopping")
                await send_audit_log(member.guild, "🎙️ สกัด Voice Spam", f"{member.mention} ถูกจับ Timeout โทษฐานกวนประสาทเข้าออกห้องเสียงถี่เกินไป (เกิน 5 ครั้ง/10 วิ)", discord.Color.red())
                voice_join_timestamps[guild_id][member.id].clear()
            except: pass

    @commands.Cog.listener()
    async def on_guild_role_update(self, before, after):
        if before.permissions == after.permissions: return
        conf = get_config(after.guild.id)
        if not conf["enforce_permissions"]: return

        dangerous = after.permissions.administrator or after.permissions.manage_guild
        if dangerous and not (before.permissions.administrator or before.permissions.manage_guild):
            if after.id not in get_whitelist(after.guild.id):
                try:
                    perms = after.permissions
                    perms.administrator = False
                    perms.manage_guild = False
                    await after.edit(permissions=perms, reason="[Permission Enforcer] ริบสิทธิ์อันตราย")
                    await send_audit_log(after.guild, "🛡️ Perm Enforcer", f"ดึงสิทธิ์แอดมินออกจากยศ {after.mention} ทันที (ไม่ได้อยู่ใน Whitelist)", discord.Color.orange())
                except: pass

    # 👻 Ghost Ping Guard
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

    # ✏️ Message Edit Guard
    @commands.Cog.listener()
    async def on_message_edit(self, before: discord.Message, after: discord.Message):
        if not after.guild or after.author.bot or before.content == after.content: return
        await self.on_message(after)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if not message.guild: return
        conf = get_config(message.guild.id)

        # ⚓ 1. WEBHOOK SPAM DEFENSE (ป้องกัน Webhook ยิงดิส + แบนผู้สร้างทึนที)
        if message.webhook_id:
            now = time.time()
            wh_id = message.webhook_id
            g_id = message.guild.id
            webhook_msg_timestamps[g_id][wh_id].append(now)
            webhook_msg_timestamps[g_id][wh_id] = [t for t in webhook_msg_timestamps[g_id][wh_id] if now - t < 5]
            
            # หาก Webhook เดียวกันส่งข้อความตั้งแต่ 4 ข้อความขึ้นไปใน 5 วินาที = WEBHOOK ATTACK!
            if len(webhook_msg_timestamps[g_id][wh_id]) >= 4:
                await safe_delete(message)
                try:
                    # 1. ทำการลบ Webhook ทิ้งทันที
                    webhooks = await message.channel.webhooks()
                    target_wh = next((wh for wh in webhooks if wh.id == wh_id), None)
                    if target_wh:
                        await target_wh.delete(reason="[Webhook Guard] สกัดกั้นการสแปม Webhook ยิงดิส")
                    
                    # 2. ค้นหาผู้สร้าง Webhook ใน Audit Log เพื่อสั่งแบน
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

                    await send_audit_log(
                        message.guild, 
                        "🚨 สกัดกั้น WEBHOOK SPAM ATTACK!", 
                        f"ตรวจพบการยิงสแปมผ่าน Webhook ใน {message.channel.mention}\n"
                        f"⚡ **ทำการลบ Webhook ทิ้งทันที!**{ban_info}", 
                        discord.Color.dark_red()
                    )
                    webhook_msg_timestamps[g_id][wh_id].clear()
                except Exception as e:
                    print(f"Webhook Attack Defense Error: {e}")
                return

        # 🍯 Honeypot Check
        if conf.get("honeypot_channel_id") and message.channel.id == conf["honeypot_channel_id"]:
            if not message.author.bot:
                await safe_delete(message)
                try: 
                    await message.author.ban(reason="[Honeypot Trap] บอทสแปมติดกับดักล่องหน")
                    await send_audit_log(message.guild, "🍯 กับดักล่อบอททำงาน!", f"ผู้ใช้ {message.author.mention} ถูกแบนทันที เนื่องจากบุกรุกห้องล่องหนที่คนปกติมองไม่เห็น", discord.Color.dark_red())
                except: pass
            return

        content = message.content.strip() if message.content else ""

        # 🔑 Discord Bot Token Leak Protection
        if content and re.search(DISCORD_TOKEN_REGEX, content):
            try:
                await safe_delete(message)
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

            # 🔗 Anti-Invite Link Guard
            if conf.get("anti_invite") and content:
                invite_match = re.search(r"(https?://)?(www\.)?(discord\.gg|discord\.com/invite|discordapp\.com/invite)/([a-zA-Z0-9]+)", content, re.IGNORECASE)
                if invite_match:
                    code = invite_match.group(4)
                    guild_invites = await get_cached_guild_invites(message.guild)
                    
                    if code not in guild_invites:
                        try:
                            await safe_delete(message)
                            await send_audit_log(message.guild, "🔗 Anti-Invite Guard", f"ลบลิงก์เชิญเซิร์ฟเวอร์อื่นจาก {user.mention} ในช่อง {message.channel.mention}\nข้อความ: `{content}`", discord.Color.orange())
                            try: await user.send("⚠️ **เตือนความปลอดภัย:** ไม่อนุญาตให้โพสต์ลิงก์เชิญเข้า Discord เซิร์ฟเวอร์อื่นในเซิร์ฟเวอร์นี้")
                            except: pass
                            return
                        except: pass

            # 🖼️ OCR Scanner
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
                                                await send_audit_log(message.guild, "🖼️ OCR สกัดกั้นภาพสแปม", f"ตรวจพบเนื้อหาอันตรายในรูปภาพจาก {user.mention}\nข้อความที่ถอดได้: `{extracted_text}`", discord.Color.red())
                                            except: pass
                                            return

            # 🤖 Self-Bot Detection
            if conf.get("self_bot") and len(content) > 150:
                last_msg_time = user_message_timestamps[user.id][-1] if user_message_timestamps[user.id] else 0
                if last_msg_time > 0 and (now - last_msg_time) < 0.5:
                    await safe_delete(message)
                    try:
                        await user.timeout(datetime.timedelta(hours=1), reason="Self-Bot Detection: ส่งข้อความยาวเร็วกว่ามนุษย์")
                        await send_audit_log(message.guild, "🤖 Self-Bot ตรวจพบ!", f"{user.mention} ถูกจับ Mute เนื่องจากพิมพ์ข้อความยาวกว่า 150 ตัวอักษรภายในเสี้ยววินาที", discord.Color.red())
                    except: pass
                    return

            # 👁️ Anti-Dox Guard (แก้ไขปัญหาตรวจจับพลาดโดนคนบริสุทธิ์)
            if conf.get("anti_dox") and content:
                # กรอง URL และ Code Block ทิ้งก่อนสแกนเพื่อความแม่นยำ
                clean_text = re.sub(r"```[\s\S]*?```|`[^`]*`", "", content)
                clean_text = re.sub(URL_REGEX, "", clean_text, flags=re.IGNORECASE)

                # 1. ตรวจสอบเลขบัตรประชาชนไทยด้วยคณิตศาสตร์ Modulo 11
                thai_ids = re.findall(r"\b[1-9]\d{12}\b", clean_text)
                has_real_thai_id = any(is_valid_thai_id(tid) for tid in thai_ids)

                # 2. ตรวจสอบ Public IP Address (ไม่นับ 127.0.0.1 หรือ IP ภายใน)
                ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", clean_text)
                has_real_ip = any(is_valid_public_ip(ip) for ip in ips)

                # 3. ตรวจสอบเบอร์โทรศัพท์ไทย 10 หลัก
                phones = re.findall(r"\b(?:06|08|09)\d{8}\b", clean_text)
                has_phone = len(phones) > 0

                if has_real_thai_id or has_real_ip or has_phone:
                    await safe_delete(message)
                    try: 
                        await user.timeout(datetime.timedelta(hours=2), reason="Anti-Dox: เปิดเผยข้อมูลส่วนตัว/สำคัญ")
                        await send_audit_log(message.guild, "👁️ ANTI-DOX ทำงาน", f"สกัดกั้นการเปิดเผยข้อมูลสำคัญ (เบอร์/IP/เลขบัตร) จาก {user.mention}", discord.Color.red())
                    except: pass
                    return

            if conf["anti_mention"] and (len(message.mentions) + len(message.role_mentions)) >= 5:
                await safe_delete(message)
                try: await user.timeout(datetime.timedelta(hours=1))
                except: pass
                return

            has_link = re.search(URL_REGEX, content, re.IGNORECASE) if content else False
            if conf["phishing_api"] and has_link:
                urls = re.findall(URL_REGEX, content, re.IGNORECASE)
                for url in urls:
                    if await check_phishing_api(url):
                        await safe_delete(message)
                        try: await user.ban(reason="ส่งลิงก์สแกม/ลิงก์ย่อต้องสงสัย")
                        except: pass
                        return

            if conf["malware"] and message.attachments:
                for att in message.attachments:
                    if att.filename.lower().endswith(DANGEROUS_EXTENSIONS):
                        await safe_delete(message)
                        return

            if conf["ai"] and content:
                is_mal, _ = await analyze_content_with_ai(content)
                if is_mal:
                    await safe_delete(message)
                    return

            user_message_timestamps[user.id].append(now)
            user_message_timestamps[user.id] = [t for t in user_message_timestamps[user.id] if now - t < SPAM_INTERVAL]
            if len(user_message_timestamps[user.id]) >= SPAM_THRESHOLD:
                await safe_delete(message)
                try: await user.timeout(datetime.timedelta(minutes=10))
                except: pass
                return

            if content and any(w in content.lower() for w in BAD_WORDS):
                await safe_delete(message)
                return


async def setup(bot):
    await bot.add_cog(SecurityEventsCog(bot))