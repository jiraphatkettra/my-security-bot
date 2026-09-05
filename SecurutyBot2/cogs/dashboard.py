import discord
import json
import time
import datetime
import sqlite3
import asyncio
import socket
import os
import gc
import psutil
from collections import defaultdict
from discord import app_commands
from discord.ext import commands
from discord.ui import Button, View, Modal, TextInput, UserSelect, RoleSelect, Select

from cogs.database import (
    DB_FILE, get_config, update_config, get_whitelist, 
    add_whitelist_db, remove_whitelist_db, add_warning, 
    get_warning_count, save_backup_to_db, send_audit_log,
    get_quarantine_data, remove_quarantine_data, get_latest_backup, ban_user_ips,
    get_security_stats, log_security_incident, get_recent_incidents, apply_security_preset
)
from cogs.web_verify import generate_verify_signature, PORT

# ==========================================
# TELEMETRY & MICRO-GRAPH HELPERS
# ==========================================
def make_meter(val: int, max_val: int = 100, length: int = 10) -> str:
    """Generate sleek ASCII micro-bar meter e.g. [■■■■■■■■□□] 80%"""
    val = max(0, min(val, max_val))
    filled = int((val / max_val) * length)
    return f"[{'■' * filled}{'□' * (length - filled)}] {val}%"

def get_process_memory_mb() -> float:
    """Get real-time RAM usage for Render free tier monitoring."""
    try:
        proc = psutil.Process(os.getpid())
        return proc.memory_info().rss / (1024 * 1024)
    except Exception:
        return 0.0

def calculate_security_score(conf: dict) -> int:
    """Compute overall security readiness percentage across active modules."""
    keys = [
        "anti_nuke", "anti_bot_add", "anti_mass_action", "anti_server_hijack",
        "auto_panic_escalation", "anti_vpn", "malware", "phishing_api",
        "anti_mention", "anti_dox", "enforce_permissions", "raid_fingerprint"
    ]
    enabled = sum(1 for k in keys if conf.get(k))
    return int((enabled / len(keys)) * 100)

# ==========================================
# BILINGUAL LOCALIZATION (TH / EN)
# ==========================================
STRINGS = {
    "th": {
        "sec_engine": "ระบบป้องกันหลัก",
        "hardening": "ระบบป้องกันขั้นสูง",
        "verify_access": "ระบบยืนยันตัวตน",
        "member_controls": "จัดการสมาชิก",
        "configuration": "การตั้งค่าทั่วไป",
        "backup_restore": "สำรองข้อมูล",
        "lang_toggle": "Language: TH",
        "back": "← กลับ",
        "main_title": "🛡️ แดชบอร์ดความปลอดภัย",
        "main_desc": "ศูนย์ควบคุมและเฝ้าระวังความปลอดภัยของเซิร์ฟเวอร์แบบเรียลไทม์\n──────────────────────────────",
        "nav_placeholder": "เลือกเมนูที่ต้องการตั้งค่า...",
        "active": "เปิดใช้งาน",
        "disabled": "ปิดใช้งาน",
        "online": "พร้อมใช้งาน",
        "healthy": "ปกติ",
        "armed": "เปิดใช้งาน",
        "lockdown_btn": "🚨 ล็อกดาวน์ฉุกเฉิน",
        "unlock_btn": "🔓 ปลดล็อกดาวน์",
        "refresh_btn": "🔄 รีเฟรช",
        "sec_menu_title": "🛡️ ระบบป้องกันภัยคุกคาม",
        "sec_menu_desc": "ตั้งค่าการตรวจสอบและป้องกันภัยคุกคามอัตโนมัติ\n──────────────────────────────",
        "content_defense": "เนื้อหา & ข้อความ",
        "privilege_defense": "สิทธิ์ & ห้อง",
        "raid_abuse": "ป้องกัน Raid & ก่อกวน",
        "hardening_title": "⚡ ระบบป้องกันขั้นสูง",
        "hardening_desc": "ระบบวิเคราะห์พฤติกรรมและการปกป้องเซิร์ฟเวอร์ขั้นสูง\n──────────────────────────────",
        "verify_title": "🔐 ระบบยืนยันตัวตน (Verification)",
        "verify_desc": "ตั้งค่าระบบยืนยันตัวตนผ่านเว็บและดักจับ IP/VPN\n──────────────────────────────",
        "mod_title": "👥 ระบบจัดการสมาชิก",
        "mod_desc": "เลือกสมาชิกจากเมนูด้านล่างเพื่อดูข้อมูล เตือน มิวท์ หรือแบน\n──────────────────────────────",
        "settings_title": "⚙️ การตั้งค่าระบบ",
        "settings_desc": "จัดการห้องเก็บ Log, ห้องดักสแปม และรหัสความปลอดภัย\n──────────────────────────────",
        "backup_title": "💾 สำรองข้อมูลเซิร์ฟเวอร์",
        "backup_desc": "บันทึกและกู้คืนโครงสร้างห้อง หมวดหมู่ และยศ\n──────────────────────────────",
        "verify_public_title": "ยืนยันตัวตนเข้าสู่เซิร์ฟเวอร์",
        "verify_public_desc": "ยินดีต้อนรับสู่ **{guild_name}**\nเพื่อความปลอดภัยของชุมชน กรุณายืนยันตัวตนตามขั้นตอนด้านล่าง\n\n• กดปุ่ม **Verify Identity** ด้านล่าง\n• แก้รหัสผ่านภาพบนหน้าเว็บที่ปลอดภัย\n• บอทจะมอบยศสมาชิกให้อัตโนมัติทันที",
        "verify_btn_label": "Verify Identity",
        "scan_msg_btn": "สแกนข้อความ",
        "scan_acc_btn": "สแกนไอดีใหม่",
        "save_snapshot_btn": "บันทึก Snapshot",
        "restore_snapshot_btn": "กู้คืน Snapshot",
        "deploy_honeypot_btn": "สร้างห้องดักบอท",
    },
    "en": {
        "sec_engine": "Core Defense",
        "hardening": "Advanced Defense",
        "verify_access": "Verification & Access",
        "member_controls": "Member Moderation",
        "configuration": "Settings",
        "backup_restore": "Backup & Recovery",
        "lang_toggle": "Language: EN",
        "back": "← Back",
        "main_title": "🛡️ Security Dashboard",
        "main_desc": "Real-time server protection and automated security controls.\n──────────────────────────────",
        "nav_placeholder": "Select a menu to configure...",
        "active": "Active",
        "disabled": "Disabled",
        "online": "Online",
        "healthy": "Normal",
        "armed": "Active",
        "lockdown_btn": "🚨 Emergency Lockdown",
        "unlock_btn": "🔓 Release Lockdown",
        "refresh_btn": "🔄 Refresh",
        "sec_menu_title": "🛡️ Threat Defense System",
        "sec_menu_desc": "Configure automated security and rate-limiting modules.\n──────────────────────────────",
        "content_defense": "Content & Messages",
        "privilege_defense": "Privileges & Channels",
        "raid_abuse": "Raid & Anti-Abuse",
        "hardening_title": "⚡ Advanced Defense Engine",
        "hardening_desc": "Heuristic behavioral protection and permission controls.\n──────────────────────────────",
        "verify_title": "🔐 Member Verification",
        "verify_desc": "External web verification and anti-alt/VPN gateway.\n──────────────────────────────",
        "mod_title": "👥 Member Moderation",
        "mod_desc": "Select a member below to view status, warn, timeout, or ban.\n──────────────────────────────",
        "settings_title": "⚙️ Server Settings",
        "settings_desc": "Manage audit channels, decoy traps, and security PIN.\n──────────────────────────────",
        "backup_title": "💾 Server Backup & Recovery",
        "backup_desc": "Snapshot and restore channels, categories, and roles.\n──────────────────────────────",
        "verify_public_title": "Server Verification",
        "verify_public_desc": "Welcome to **{guild_name}**\nTo keep the community safe, please complete the identity verification below.\n\n• Click **Verify Identity** below\n• Complete the captcha on the web portal\n• Access role will be granted automatically",
        "verify_btn_label": "Verify Identity",
        "scan_msg_btn": "Scan Messages",
        "scan_acc_btn": "Scan Accounts",
        "save_snapshot_btn": "Save Snapshot",
        "restore_snapshot_btn": "Restore from Snapshot",
        "deploy_honeypot_btn": "Deploy Decoy Trap",
    }
}

def t(key: str, lang: str = "th") -> str:
    lang_dict = STRINGS.get(lang, STRINGS["th"])
    return lang_dict.get(key, STRINGS["en"].get(key, key))

# ==========================================
# RENDER MEMORY & COOLDOWN MANAGEMENT
# ==========================================
interaction_cooldowns = defaultdict(list)

def clean_interaction_cooldowns():
    now = time.time()
    stale_uids = [uid for uid, ts in interaction_cooldowns.items() if not ts or (now - ts[-1] > 15)]
    for uid in stale_uids[:200]:
        interaction_cooldowns.pop(uid, None)

def check_role_hierarchy(actor: discord.Member, target: discord.Member) -> bool:
    if actor.guild.owner_id == actor.id:
        return True
    if target.guild.owner_id == target.id:
        return False
    return actor.top_role > target.top_role

# ==========================================
# BASE SECURITY VIEW (RENDER STABILITY WRAPPER)
# ==========================================
class BaseSecurityView(View):
    def __init__(self, timeout: float = 300):
        super().__init__(timeout=timeout)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        clean_interaction_cooldowns()
        now = time.time()
        user_id = interaction.user.id
        interaction_cooldowns[user_id] = [timestamp for timestamp in interaction_cooldowns[user_id] if now - timestamp < 5]
        
        if len(interaction_cooldowns[user_id]) >= 4:
            if not interaction.response.is_done():
                try: 
                    await interaction.response.send_message("Rate Limit: Please wait a moment before sending more commands.", ephemeral=True)
                except Exception: 
                    pass
            return False
        
        interaction_cooldowns[user_id].append(now)
        return True

    async def on_error(self, interaction: discord.Interaction, error: Exception, item: discord.ui.Item):
        try:
            if not interaction.response.is_done():
                await interaction.response.send_message("Notice: Interaction timed out or network latency detected. Please retry.", ephemeral=True)
            else:
                await interaction.followup.send("Notice: Command execution completed or state updated.", ephemeral=True)
        except Exception:
            pass

# ==========================================
# MODALS
# ==========================================
class PurgeModal(Modal, title="Purge Messages"):
    amount = TextInput(label="Amount of messages (1-100)", placeholder="e.g. 20", default="10", max_length=3)
    
    async def on_submit(self, interaction: discord.Interaction):
        if not self.amount.value.isdigit():
            await interaction.response.send_message("Please provide a valid numeric value.", ephemeral=True)
            return
        limit = int(self.amount.value)
        await interaction.response.defer(ephemeral=True)
        deleted = await interaction.channel.purge(limit=limit)
        await interaction.followup.send(f"Successfully purged **{len(deleted)}** messages.", ephemeral=True)
        await send_audit_log(interaction.guild, "Purge Executed", f"Executor: {interaction.user.mention}\nAmount: {len(deleted)} messages", discord.Color(0x2B2D31))

class PunishModal(Modal, title="Sanction Member"):
    reason = TextInput(label="Reason for action", placeholder="Provide reason or incident details...", required=False, max_length=100)
    
    def __init__(self, action: str, target: discord.Member, **kwargs):
        super().__init__(**kwargs)
        self.action = action
        self.target = target

    async def on_submit(self, interaction: discord.Interaction):
        if not check_role_hierarchy(interaction.user, self.target):
            return await interaction.response.send_message("Hierarchy Error: You cannot moderate a member with an equal or higher role.", ephemeral=True)

        reason = self.reason.value or "No reason specified"
        await interaction.response.defer(ephemeral=True)
        try:
            if self.action == "mute":
                await self.target.timeout(datetime.timedelta(hours=1), reason=reason)
                await send_audit_log(interaction.guild, "Member Timed Out", f"Target: {self.target.mention}\nModerator: {interaction.user.mention}\nReason: {reason}", discord.Color.orange())
            elif self.action == "kick":
                await self.target.kick(reason=reason)
                await send_audit_log(interaction.guild, "Member Kicked", f"Target: {self.target.mention}\nModerator: {interaction.user.mention}\nReason: {reason}", discord.Color.red())
            elif self.action == "ban":
                ban_user_ips(interaction.guild.id, self.target.id, f"Dashboard Ban by {interaction.user.name}")
                await self.target.ban(reason=reason)
                await send_audit_log(interaction.guild, "Member Banned & IP Blacklisted", f"Target: {self.target.mention}\nModerator: {interaction.user.mention}\nReason: {reason}", discord.Color.dark_red())
            await interaction.followup.send(f"Sanction applied to {self.target.mention} successfully.", ephemeral=False)
        except discord.Forbidden:
            await interaction.followup.send("Action failed: Insufficient permissions or target role is above the bot.", ephemeral=True)

class WarnModal(Modal, title="Warn Member"):
    reason = TextInput(label="Reason for warning", placeholder="Provide reason for warning...", required=True)
    
    def __init__(self, target: discord.Member, **kwargs):
        super().__init__(**kwargs)
        self.target = target

    async def on_submit(self, interaction: discord.Interaction):
        reason = self.reason.value
        add_warning(interaction.guild.id, self.target.id, reason)
        count = get_warning_count(interaction.guild.id, self.target.id)
        
        await interaction.response.send_message(f"Warning issued to {self.target.mention} (Strike #{count})")
        await send_audit_log(interaction.guild, "Warning Issued", f"Target: {self.target.mention}\nStrike: #{count}\nReason: {reason}", discord.Color.gold())
        
        conf = get_config(interaction.guild.id)
        if conf["strike"]:
            if count == 3:
                try: await self.target.timeout(datetime.timedelta(hours=1), reason="Strike threshold reached (3 warnings)")
                except: pass
            elif count >= 5:
                try: await self.target.ban(reason="Strike threshold reached (5 warnings)")
                except: pass

class SetupConfigModal(Modal, title="Configuration"):
    target_id = TextInput(label="Target value to configure", placeholder="Numeric ID, Domain, or Value", required=True)
    
    def __init__(self, config_key: str, description: str, **kwargs):
        super().__init__(**kwargs)
        self.config_key = config_key
        self.description = description
        self.title = f"Config: {description}"[:40]

    async def on_submit(self, interaction: discord.Interaction):
        val = self.target_id.value
        if self.config_key in ("owner_pin", "verify_domain", "language"):
            update_config(interaction.guild.id, self.config_key, str(val))
            await interaction.response.send_message(f"Updated **{self.description}**: `{val}`", ephemeral=True)
        else:
            if not val.isdigit():
                await interaction.response.send_message("Please provide a numeric value.", ephemeral=True)
                return
            update_config(interaction.guild.id, self.config_key, int(val))
            await interaction.response.send_message(f"Updated **{self.description}**: `{val}`", ephemeral=True)

class OwnerPinModal(Modal, title="Security 2FA Verification"):
    pin_input = TextInput(label="Enter 6-digit Owner PIN", placeholder="Default: 123456", required=True, max_length=10)
    
    def __init__(self, action_type: str, callback_coro, **kwargs):
        super().__init__(**kwargs)
        self.action_type = action_type
        self.callback_coro = callback_coro

    async def on_submit(self, interaction: discord.Interaction):
        conf = get_config(interaction.guild.id)
        if self.pin_input.value.strip() != conf["owner_pin"]:
            return await interaction.response.send_message("Verification Failed: Invalid Owner PIN.", ephemeral=True)
        await self.callback_coro(interaction)

# ==========================================
# MEMBER MODERATION VIEWS & EMBED
# ==========================================
def get_moderation_embed(guild_id: int = 0):
    lang = get_config(guild_id).get("language", "th") if guild_id else "th"
    embed = discord.Embed(
        title=t("mod_title", lang),
        description=t("mod_desc", lang),
        color=discord.Color(0x2B2D31)
    )
    embed.set_footer(text="เลือกสมาชิกจากเมนูด้านล่างเพื่อจัดการ" if lang == "th" else "Select a member from the dropdown below")
    return embed

class UserActionView(BaseSecurityView):
    def __init__(self, target: discord.Member, guild_id: int = 0):
        super().__init__(timeout=180)
        self.target = target
        self.guild_id = guild_id or target.guild.id

    @discord.ui.button(label="Warn", style=discord.ButtonStyle.secondary, row=0)
    async def btn_warn(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(WarnModal(target=self.target))

    @discord.ui.button(label="Timeout", style=discord.ButtonStyle.secondary, row=0)
    async def btn_mute(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(PunishModal(action="mute", target=self.target))

    @discord.ui.button(label="Quarantine", style=discord.ButtonStyle.primary, row=0)
    async def btn_quarantine(self, interaction: discord.Interaction, button: Button):
        if not check_role_hierarchy(interaction.user, self.target):
            return await interaction.response.send_message("Hierarchy Error: You cannot quarantine a member with an equal or higher role.", ephemeral=True)
        conf = get_config(interaction.guild.id)
        if not conf["quarantine_role_id"]:
            return await interaction.response.send_message("Quarantine role is not configured.", ephemeral=True)
        q_role = interaction.guild.get_role(conf["quarantine_role_id"])
        
        roles_str = ",".join([str(r.id) for r in self.target.roles if r.name != "@everyone"])
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO quarantine (guild_id, user_id, original_roles) VALUES (?, ?, ?)", (interaction.guild.id, self.target.id, roles_str))
        conn.commit()
        conn.close()

        await interaction.response.defer(ephemeral=True)
        try:
            await self.target.edit(roles=[q_role], reason="Quarantined by Moderator")
            await interaction.followup.send(f"Quarantined {self.target.mention}.", ephemeral=True)
            await send_audit_log(interaction.guild, "Member Quarantined", f"{self.target.mention} was assigned quarantine isolation.", discord.Color(0x2B2D31))
        except:
            await interaction.followup.send("Action failed: Insufficient role permissions.", ephemeral=True)

    @discord.ui.button(label="Restore Roles", style=discord.ButtonStyle.secondary, row=1)
    async def btn_unquarantine(self, interaction: discord.Interaction, button: Button):
        orig_roles_str = get_quarantine_data(interaction.guild.id, self.target.id)
        if not orig_roles_str:
            return await interaction.response.send_message("No previous role snapshot found for this user.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        try:
            role_ids = [int(r) for r in orig_roles_str.split(",") if r.isdigit()]
            roles_to_restore = [interaction.guild.get_role(r_id) for r_id in role_ids if interaction.guild.get_role(r_id)]
            
            await self.target.edit(roles=roles_to_restore, reason="Un-Quarantine Restoration")
            remove_quarantine_data(interaction.guild.id, self.target.id)
            await interaction.followup.send(f"Restored previous roles to {self.target.mention}.", ephemeral=True)
            await send_audit_log(interaction.guild, "Quarantine Released", f"{self.target.mention} roles restored by {interaction.user.mention}", discord.Color(0x2B2D31))
        except Exception as e:
            await interaction.followup.send(f"Failed to restore roles: {e}", ephemeral=True)

    @discord.ui.button(label="Ban Member", style=discord.ButtonStyle.danger, row=1)
    async def btn_ban(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(PunishModal(action="ban", target=self.target))

    @discord.ui.button(label="← Back", style=discord.ButtonStyle.secondary, row=1)
    async def btn_back(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(embed=get_moderation_embed(self.guild_id), view=ModerationMenuView(self.guild_id))

class ModerationMenuView(BaseSecurityView):
    def __init__(self, guild_id: int = 0):
        super().__init__(timeout=300)
        self.guild_id = guild_id

    @discord.ui.select(cls=UserSelect, placeholder="Select a member to manage...", max_values=1)
    async def select_user(self, interaction: discord.Interaction, select: UserSelect):
        target = select.values[0]
        embed = discord.Embed(
            title=f"Member: {target.display_name}",
            description=f"**User ID:** `{target.id}`\n**Joined Server:** {discord.utils.format_dt(target.joined_at, 'R') if hasattr(target, 'joined_at') and target.joined_at else 'Unknown'}\n**Account Created:** {discord.utils.format_dt(target.created_at, 'R')}\n──────────────────────────────",
            color=discord.Color(0x2B2D31)
        )
        embed.set_thumbnail(url=target.display_avatar.url)
        embed.set_footer(text="Security Core • Member Actions")
        await interaction.response.edit_message(embed=embed, view=UserActionView(target=target, guild_id=interaction.guild.id))

    @discord.ui.button(label="← Back", style=discord.ButtonStyle.secondary, row=1)
    async def btn_back(self, interaction: discord.Interaction, button: Button):
        g_id = interaction.guild.id if interaction.guild else self.guild_id
        await interaction.response.edit_message(content=None, embed=get_main_embed(g_id), view=MainDashboardView(g_id))

# ==========================================
# PUBLIC VERIFICATION & ACCESS VIEWS
# ==========================================
def get_public_verify_host(guild_id: int) -> str:
    conf = get_config(guild_id)
    if conf.get("verify_domain"):
        dom = conf["verify_domain"].strip()
        if not dom.startswith("http://") and not dom.startswith("https://"):
            dom = f"http://{dom}"
        return dom.rstrip("/")
    
    discloud_domain = os.getenv("DISCLOUD_DOMAIN")
    if discloud_domain:
        if not discloud_domain.startswith("http://") and not discloud_domain.startswith("https://"):
            discloud_domain = f"https://{discloud_domain}"
        return discloud_domain.strip().rstrip("/")
        
    discloud_id = os.getenv("DISCLOUD_APP_ID") or os.getenv("DISCLOUD_APP_NAME")
    if discloud_id:
        return f"https://{discloud_id.strip()}.discloud.app"

    square_domain = os.getenv("SQUARECLOUD_DOMAIN") or os.getenv("SQUARECLOUD_SUBDOMAIN")
    if square_domain:
        if not square_domain.startswith("http://") and not square_domain.startswith("https://"):
            square_domain = f"https://{square_domain}"
        return square_domain.strip().rstrip("/")
        
    square_id = os.getenv("SQUARE_APP_ID") or os.getenv("SQUARECLOUD_APP_ID")
    if square_id:
        return f"https://{square_id.strip()}.squareweb.app"

    env_host = os.getenv("VERIFY_HOST") or os.getenv("PUBLIC_URL")
    if env_host:
        return env_host.strip().rstrip("/")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
        return f"http://{lan_ip}:{PORT}"
    except Exception:
        return f"http://localhost:{PORT}"

class VerifyPublicButton(View):
    def __init__(self, guild_id: int):
        super().__init__(timeout=None)
        self.guild_id = guild_id

    @discord.ui.button(label="Verify Identity", style=discord.ButtonStyle.primary, custom_id="persistent_web_verify_btn")
    async def btn_verify_click(self, interaction: discord.Interaction, button: Button):
        guild = interaction.guild
        user = interaction.user
        sig = generate_verify_signature(guild.id, user.id)
        
        base_host = get_public_verify_host(guild.id)
        verify_url = f"{base_host}/verify?guild_id={guild.id}&user_id={user.id}&sig={sig}&username={user.display_name}&handle={user.name}&avatar={user.display_avatar.url}"
        
        embed = discord.Embed(
            title="Identity Verification Gateway",
            description=f"Click the button below to complete verification in your browser.\n\n"
                        f"[Open Verification Page]({verify_url})\n\n"
                        f"──────────────────────────────\n"
                        f"*Session expires automatically. VPN and Proxy connections are filtered.*",
            color=discord.Color(0x2B2D31)
        )
        embed.set_footer(text="Security Core • Access Gateway")

        view = View()
        view.add_item(Button(label="Open Verification Page", url=verify_url, style=discord.ButtonStyle.link))
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

class VerifyMenuView(BaseSecurityView):
    def __init__(self, guild_id: int):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        conf = get_config(guild_id)
        lang = conf.get("language", "th")

        ip_label = f"IP Guard  [{'ON' if conf['ip_ban_guard'] else 'OFF'}]"
        ip_style = discord.ButtonStyle.primary if conf["ip_ban_guard"] else discord.ButtonStyle.secondary
        btn_ip_guard = Button(label=ip_label, style=ip_style, row=0)
        btn_ip_guard.callback = self.toggle_ip_guard
        self.add_item(btn_ip_guard)

        vpn_label = f"Anti-VPN  [{'ON' if conf.get('anti_vpn') else 'OFF'}]"
        vpn_style = discord.ButtonStyle.primary if conf.get("anti_vpn") else discord.ButtonStyle.secondary
        btn_vpn = Button(label=vpn_label, style=vpn_style, row=0)
        btn_vpn.callback = self.toggle_vpn
        self.add_item(btn_vpn)

        # Back button in row 3
        back_btn = Button(label=t("back", lang), style=discord.ButtonStyle.secondary, row=3)
        back_btn.callback = self.btn_back
        self.add_item(back_btn)

    async def toggle_ip_guard(self, interaction: discord.Interaction):
        conf = get_config(self.guild_id)
        update_config(self.guild_id, "ip_ban_guard", int(not conf["ip_ban_guard"]))
        await interaction.response.edit_message(embed=get_verify_embed(self.guild_id), view=VerifyMenuView(self.guild_id))

    async def toggle_vpn(self, interaction: discord.Interaction):
        conf = get_config(self.guild_id)
        update_config(self.guild_id, "anti_vpn", int(not conf.get("anti_vpn")))
        await interaction.response.edit_message(embed=get_verify_embed(self.guild_id), view=VerifyMenuView(self.guild_id))

    @discord.ui.select(cls=RoleSelect, placeholder="Select role granted after verification...", max_values=1, row=1)
    async def select_verify_role(self, interaction: discord.Interaction, select: RoleSelect):
        role = select.values[0]
        update_config(interaction.guild.id, "verify_role_id", role.id)
        await interaction.response.send_message(f"Configured verification role: {role.mention}", ephemeral=True)

    @discord.ui.button(label="Set Channel", style=discord.ButtonStyle.secondary, row=2)
    async def btn_set_verify_channel(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("verify_channel_id", "Verification Channel ID"))

    @discord.ui.button(label="Set Domain", style=discord.ButtonStyle.secondary, row=2)
    async def btn_set_domain(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("verify_domain", "Public Host Domain"))

    @discord.ui.button(label="Publish Verify Panel", style=discord.ButtonStyle.primary, row=2)
    async def btn_send_verify_embed(self, interaction: discord.Interaction, button: Button):
        conf = get_config(interaction.guild.id)
        lang = conf.get("language", "th")
        channel_id = conf["verify_channel_id"] or interaction.channel_id
        target_channel = interaction.guild.get_channel(channel_id)
        
        if not target_channel:
            return await interaction.response.send_message("Verification channel could not be found.", ephemeral=True)

        guild_name = interaction.guild.name
        embed = discord.Embed(
            title=t("verify_public_title", lang),
            description=t("verify_public_desc", lang).format(guild_name=guild_name),
            color=discord.Color(0x2B2D31)
        )
        embed.set_footer(text=f"{guild_name} • Security Verification")

        await target_channel.send(embed=embed, view=VerifyPublicButton(interaction.guild.id))
        await interaction.response.send_message(f"Published verification panel to {target_channel.mention}.", ephemeral=True)

    async def btn_back(self, interaction: discord.Interaction):
        await interaction.response.edit_message(content=None, embed=get_main_embed(self.guild_id), view=MainDashboardView(self.guild_id))

def get_verify_embed(guild_id: int):
    conf = get_config(guild_id)
    lang = conf.get("language", "th")
    v_chan = f"<#{conf['verify_channel_id']}>" if conf['verify_channel_id'] else ("`ยังไม่ตั้งค่า`" if lang == "th" else "`Unconfigured`")
    v_role = f"<@&{conf['verify_role_id']}>" if conf['verify_role_id'] else ("`ยังไม่ตั้งค่า`" if lang == "th" else "`Unconfigured`")
    ip_status = f"`{t('active', lang)}`" if conf['ip_ban_guard'] else f"`{t('disabled', lang)}`"
    vpn_status = f"`{t('active', lang)}`" if conf.get('anti_vpn') else f"`{t('disabled', lang)}`"
    domain_status = f"`{conf['verify_domain']}`" if conf.get('verify_domain') else f"`{get_public_verify_host(guild_id)}`"
    
    embed = discord.Embed(
        title=t("verify_title", lang),
        description=t("verify_desc", lang),
        color=discord.Color(0x2B2D31)
    )
    embed.add_field(name="ห้องยืนยันตัวตน" if lang == "th" else "Verify Channel", value=v_chan, inline=True)
    embed.add_field(name="ยศสมาชิกที่จะได้รับ" if lang == "th" else "Verified Role", value=v_role, inline=True)
    embed.add_field(name="ระบบแบน IP อัตโนมัติ" if lang == "th" else "IP Ban Sync", value=ip_status, inline=True)
    embed.add_field(name="บล็อก VPN / Proxy" if lang == "th" else "Anti-VPN / Proxy", value=vpn_status, inline=True)
    embed.add_field(name="ลิงก์หน้าเว็บ Verify" if lang == "th" else "Portal URL", value=domain_status, inline=False)
    embed.set_footer(text="ใช้ปุ่มด้านล่างเพื่อตั้งค่าหรือโพสต์กล่อง Verify" if lang == "th" else "Use the buttons below to configure or publish")
    return embed

# ==========================================
# SECURITY ENGINE MENU & DEFENSE VIEW
# ==========================================
def get_security_menu_embed(guild_id: int):
    conf = get_config(guild_id)
    lang = conf.get("language", "th")
    badge = lambda val: f"`{t('active', lang)}`" if val else f"`{t('disabled', lang)}`"
    
    embed = discord.Embed(
        title=t("sec_menu_title", lang),
        description=t("sec_menu_desc", lang),
        color=discord.Color(0x2B2D31)
    )
    if lang == "th":
        embed.add_field(
            name=t("content_defense", lang),
            value=f"• กรองมัลแวร์: {badge(conf['malware'])}\n"
                  f"• ป้องกัน Phishing: {badge(conf['phishing_api'])}\n"
                  f"• ป้องกัน Dox: {badge(conf['anti_dox'])}\n"
                  f"• กรองคำด้วย AI: {badge(conf['ai'])}",
            inline=True
        )
        embed.add_field(
            name=t("privilege_defense", lang),
            value=f"• Anti-Nuke: {badge(conf['anti_nuke'])}\n"
                  f"• ควบคุมสิทธิ์ยศ: {badge(conf['enforce_permissions'])}\n"
                  f"• Webhook Guard: {badge(conf.get('webhook_guard'))}\n"
                  f"• บล็อกลิงก์เชิญ: {badge(conf.get('anti_invite'))}",
            inline=True
        )
        embed.add_field(
            name=t("raid_abuse", lang),
            value=f"• ป้องกันแท็กหมู่: {badge(conf['anti_mention'])}\n"
                  f"• กันป่วนห้องเสียง: {badge(conf['voice_anti_raid'])}\n"
                  f"• ป้องกัน Ghost Ping: {badge(conf.get('ghost_ping_guard'))}\n"
                  f"• ตรวจจับไอดีใหม่: {badge(conf.get('suspect_scan'))}",
            inline=True
        )
    else:
        embed.add_field(
            name=t("content_defense", lang),
            value=f"• Malware Filter: {badge(conf['malware'])}\n"
                  f"• Phishing Guard: {badge(conf['phishing_api'])}\n"
                  f"• Anti-Dox Engine: {badge(conf['anti_dox'])}\n"
                  f"• AI Classifier: {badge(conf['ai'])}",
            inline=True
        )
        embed.add_field(
            name=t("privilege_defense", lang),
            value=f"• Anti-Nuke Engine: {badge(conf['anti_nuke'])}\n"
                  f"• Perm Enforcement: {badge(conf['enforce_permissions'])}\n"
                  f"• Webhook Guard: {badge(conf.get('webhook_guard'))}\n"
                  f"• Anti-Invite: {badge(conf.get('anti_invite'))}",
            inline=True
        )
        embed.add_field(
            name=t("raid_abuse", lang),
            value=f"• Mass Mention: {badge(conf['anti_mention'])}\n"
                  f"• Voice Raid Guard: {badge(conf['voice_anti_raid'])}\n"
                  f"• Ghost Ping Guard: {badge(conf.get('ghost_ping_guard'))}\n"
                  f"• Account Scanner: {badge(conf.get('suspect_scan'))}",
            inline=True
        )
    embed.set_footer(text="คลิกปุ่มด้านล่างเพื่อเปิด/ปิดระบบ" if lang == "th" else "Click the buttons below to toggle protections")
    return embed

class SecurityMenuView(BaseSecurityView):
    def __init__(self, guild_id: int):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        conf = get_config(guild_id)
        lang = conf.get("language", "th")
        
        # Row 0: Content Security
        mal_btn = Button(label=f"Malware  [{'ON' if conf['malware'] else 'OFF'}]", style=discord.ButtonStyle.primary if conf["malware"] else discord.ButtonStyle.secondary, row=0)
        mal_btn.callback = self.toggle_malware
        
        ai_btn = Button(label=f"AI Filter  [{'ON' if conf['ai'] else 'OFF'}]", style=discord.ButtonStyle.primary if conf["ai"] else discord.ButtonStyle.secondary, row=0)
        ai_btn.callback = self.toggle_ai
        
        phish_btn = Button(label=f"Phishing  [{'ON' if conf['phishing_api'] else 'OFF'}]", style=discord.ButtonStyle.primary if conf["phishing_api"] else discord.ButtonStyle.secondary, row=0)
        phish_btn.callback = self.toggle_phishing
        
        dox_btn = Button(label=f"Anti-Dox  [{'ON' if conf['anti_dox'] else 'OFF'}]", style=discord.ButtonStyle.primary if conf["anti_dox"] else discord.ButtonStyle.secondary, row=0)
        dox_btn.callback = self.toggle_dox

        # Row 1: Privilege & Abuse Security
        nuke_btn = Button(label=f"Anti-Nuke  [{'ON' if conf['anti_nuke'] else 'OFF'}]", style=discord.ButtonStyle.primary if conf["anti_nuke"] else discord.ButtonStyle.secondary, row=1)
        nuke_btn.callback = self.toggle_nuke
        
        mention_btn = Button(label=f"Mention  [{'ON' if conf['anti_mention'] else 'OFF'}]", style=discord.ButtonStyle.primary if conf["anti_mention"] else discord.ButtonStyle.secondary, row=1)
        mention_btn.callback = self.toggle_mention
        
        voice_btn = Button(label=f"Voice Raid  [{'ON' if conf['voice_anti_raid'] else 'OFF'}]", style=discord.ButtonStyle.primary if conf["voice_anti_raid"] else discord.ButtonStyle.secondary, row=1)
        voice_btn.callback = self.toggle_voice
        
        perm_btn = Button(label=f"Perm Enforce  [{'ON' if conf['enforce_permissions'] else 'OFF'}]", style=discord.ButtonStyle.primary if conf["enforce_permissions"] else discord.ButtonStyle.secondary, row=1)
        perm_btn.callback = self.toggle_perm

        # Row 2: Perimeters
        ghost_btn = Button(label=f"Ghost Ping  [{'ON' if conf.get('ghost_ping_guard') else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("ghost_ping_guard") else discord.ButtonStyle.secondary, row=2)
        ghost_btn.callback = self.toggle_ghost
        
        invite_btn = Button(label=f"Anti-Invite  [{'ON' if conf.get('anti_invite') else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("anti_invite") else discord.ButtonStyle.secondary, row=2)
        invite_btn.callback = self.toggle_invite
        
        wh_btn = Button(label=f"Webhook Guard  [{'ON' if conf.get('webhook_guard') else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("webhook_guard") else discord.ButtonStyle.secondary, row=2)
        wh_btn.callback = self.toggle_webhook
        
        suspect_btn = Button(label=f"Account Scan  [{'ON' if conf.get('suspect_scan') else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("suspect_scan") else discord.ButtonStyle.secondary, row=2)
        suspect_btn.callback = self.toggle_suspect

        self.add_item(mal_btn)
        self.add_item(ai_btn)
        self.add_item(phish_btn)
        self.add_item(dox_btn)
        self.add_item(nuke_btn)
        self.add_item(mention_btn)
        self.add_item(voice_btn)
        self.add_item(perm_btn)
        self.add_item(ghost_btn)
        self.add_item(invite_btn)
        self.add_item(wh_btn)
        self.add_item(suspect_btn)

        # Row 3 Actions
        btn_scan_msg = Button(label=t("scan_msg_btn", lang), style=discord.ButtonStyle.secondary, row=3)
        btn_scan_msg.callback = self.btn_scan_messages
        btn_scan_acc = Button(label=t("scan_acc_btn", lang), style=discord.ButtonStyle.secondary, row=3)
        btn_scan_acc.callback = self.btn_scan_suspects
        btn_panic_btn = Button(label=t("lockdown_btn", lang), style=discord.ButtonStyle.danger, row=3)
        btn_panic_btn.callback = self.btn_panic
        btn_unpanic_btn = Button(label=t("unlock_btn", lang), style=discord.ButtonStyle.secondary, row=3)
        btn_unpanic_btn.callback = self.btn_unpanic
        btn_back_btn = Button(label=t("back", lang), style=discord.ButtonStyle.secondary, row=3)
        btn_back_btn.callback = self.btn_back

        self.add_item(btn_scan_msg)
        self.add_item(btn_scan_acc)
        self.add_item(btn_panic_btn)
        self.add_item(btn_unpanic_btn)
        self.add_item(btn_back_btn)

    async def toggle_malware(self, interaction: discord.Interaction):
        update_config(self.guild_id, "malware_filter", int(not get_config(self.guild_id)["malware"]))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def toggle_ai(self, interaction: discord.Interaction):
        update_config(self.guild_id, "ai_filter", int(not get_config(self.guild_id)["ai"]))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def toggle_phishing(self, interaction: discord.Interaction):
        update_config(self.guild_id, "phishing_api", int(not get_config(self.guild_id)["phishing_api"]))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def toggle_dox(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_dox", int(not get_config(self.guild_id)["anti_dox"]))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def toggle_nuke(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_nuke", int(not get_config(self.guild_id)["anti_nuke"]))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def toggle_mention(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_mention", int(not get_config(self.guild_id)["anti_mention"]))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def toggle_voice(self, interaction: discord.Interaction):
        update_config(self.guild_id, "voice_anti_raid", int(not get_config(self.guild_id)["voice_anti_raid"]))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def toggle_perm(self, interaction: discord.Interaction):
        update_config(self.guild_id, "enforce_permissions", int(not get_config(self.guild_id)["enforce_permissions"]))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def toggle_ghost(self, interaction: discord.Interaction):
        update_config(self.guild_id, "ghost_ping_guard", int(not get_config(self.guild_id).get("ghost_ping_guard")))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def toggle_invite(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_invite", int(not get_config(self.guild_id).get("anti_invite")))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def toggle_webhook(self, interaction: discord.Interaction):
        update_config(self.guild_id, "webhook_guard", int(not get_config(self.guild_id).get("webhook_guard")))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def toggle_suspect(self, interaction: discord.Interaction):
        update_config(self.guild_id, "suspect_scan", int(not get_config(self.guild_id).get("suspect_scan")))
        await interaction.response.edit_message(embed=get_security_menu_embed(self.guild_id), view=SecurityMenuView(self.guild_id))

    async def btn_scan_messages(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        sec_cog = interaction.client.get_cog("SecurityEventsCog")
        if sec_cog and hasattr(sec_cog, "run_message_backlog_scan"):
            scanned, deleted = await sec_cog.run_message_backlog_scan(interaction.guild)
            msg = f"Backlog inspection complete: Scanned **{scanned}** messages, removed **{deleted}** malicious entries."
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.followup.send("Scanner module unavailable.", ephemeral=True)

    async def btn_scan_suspects(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        sec_cog = interaction.client.get_cog("SecurityEventsCog")
        if sec_cog and hasattr(sec_cog, "run_suspect_account_scan"):
            suspect_list = await sec_cog.run_suspect_account_scan(interaction.guild)
            suspect_count = len(suspect_list)
            await interaction.followup.send(f"Account scan complete: Identified **{suspect_count}** flagged accounts.", ephemeral=True)

            if suspect_count > 0:
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                chunk_size = 15
                total_batches = ((suspect_count - 1) // chunk_size) + 1

                for i in range(0, suspect_count, chunk_size):
                    chunk = suspect_list[i : i + chunk_size]
                    batch_lines = [f"**Flagged Accounts ({i//chunk_size + 1}/{total_batches}):**"]
                    for m in chunk:
                        age_days = (now_utc - m.created_at).days
                        batch_lines.append(f"• {m.mention} (`{m.id}`) - Age: {age_days}d")
                    await interaction.followup.send("\n".join(batch_lines), ephemeral=True)
                    await asyncio.sleep(0.2)
        else:
            await interaction.followup.send("Account scanner unavailable.", ephemeral=True)

    async def btn_panic(self, interaction: discord.Interaction):
        async def do_panic(inter: discord.Interaction):
            await inter.response.send_message("Initiating emergency lockdown across all channels...", ephemeral=False)
            guild = inter.guild
            update_config(guild.id, "global_panic", 1)
            default_role = guild.default_role
            for channel in guild.channels:
                try:
                    for target, overwrite in channel.overwrites.items():
                        if isinstance(target, discord.Role):
                            if target.permissions.administrator:
                                continue
                            ow = channel.overwrites_for(target)
                            ow.send_messages = False
                            ow.send_messages_in_threads = False
                            ow.create_public_threads = False
                            ow.create_private_threads = False
                            ow.send_voice_messages = False
                            ow.connect = False
                            await channel.set_permissions(target, overwrite=ow)

                    overwrite = channel.overwrites_for(default_role)
                    overwrite.send_messages = False
                    overwrite.send_messages_in_threads = False
                    overwrite.create_public_threads = False
                    overwrite.create_private_threads = False
                    overwrite.send_voice_messages = False
                    overwrite.connect = False
                    await channel.set_permissions(default_role, overwrite=overwrite)
                except: pass
            await inter.followup.send("Server successfully placed in emergency lockdown.", ephemeral=False)
            await send_audit_log(guild, "Emergency Lockdown Engaged", f"Authorized by: {inter.user.mention}", discord.Color.dark_red())

        await interaction.response.send_modal(OwnerPinModal("Global Panic", do_panic))

    async def btn_unpanic(self, interaction: discord.Interaction):
        async def do_unpanic(inter: discord.Interaction):
            await inter.response.send_message("Lifting emergency lockdown...", ephemeral=False)
            guild = inter.guild
            update_config(guild.id, "global_panic", 0)
            default_role = guild.default_role
            for channel in guild.channels:
                try:
                    for target, overwrite in channel.overwrites.items():
                        if isinstance(target, discord.Role):
                            if target.permissions.administrator:
                                continue
                            ow = channel.overwrites_for(target)
                            ow.send_messages = None
                            ow.send_messages_in_threads = None
                            ow.create_public_threads = None
                            ow.create_private_threads = None
                            ow.send_voice_messages = None
                            ow.connect = None
                            await channel.set_permissions(target, overwrite=ow)

                    overwrite = channel.overwrites_for(default_role)
                    overwrite.send_messages = None
                    overwrite.send_messages_in_threads = None
                    overwrite.create_public_threads = None
                    overwrite.create_private_threads = None
                    overwrite.send_voice_messages = None
                    overwrite.connect = None
                    await channel.set_permissions(default_role, overwrite=overwrite)
                except: pass
            await inter.followup.send("Emergency lockdown lifted successfully.", ephemeral=False)
            await send_audit_log(guild, "Lockdown Released", f"Released by: {inter.user.mention}", discord.Color.green())

        await interaction.response.send_modal(OwnerPinModal("Unpanic Lockdown", do_unpanic))

    async def btn_back(self, interaction: discord.Interaction):
        await interaction.response.edit_message(content=None, embed=get_main_embed(self.guild_id), view=MainDashboardView(self.guild_id))

# ==========================================
# ADVANCED SECURITY VIEW (ENTERPRISE HARDENING)
# ==========================================
class AdvancedSecurityView(BaseSecurityView):
    def __init__(self, guild_id: int):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        conf = get_config(guild_id)
        lang = conf.get("language", "th")

        # Row 0: Advanced Heuristics
        bot_btn = Button(label=f"Anti-Bot  [{'ON' if conf.get('anti_bot_add') else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("anti_bot_add") else discord.ButtonStyle.secondary, row=0)
        bot_btn.callback = self.toggle_anti_bot
        
        mass_btn = Button(label=f"Mass Action  [{'ON' if conf.get('anti_mass_action') else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("anti_mass_action") else discord.ButtonStyle.secondary, row=0)
        mass_btn.callback = self.toggle_anti_mass
        
        hijack_btn = Button(label=f"Server Hijack  [{'ON' if conf.get('anti_server_hijack') else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("anti_server_hijack") else discord.ButtonStyle.secondary, row=0)
        hijack_btn.callback = self.toggle_anti_hijack
        
        panic_btn = Button(label=f"Auto-Panic  [{'ON' if conf.get('auto_panic_escalation') else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("auto_panic_escalation") else discord.ButtonStyle.secondary, row=0)
        panic_btn.callback = self.toggle_auto_panic
        
        zalgo_btn = Button(label=f"Zalgo Filter  [{'ON' if conf.get('anti_zalgo') else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("anti_zalgo") else discord.ButtonStyle.secondary, row=0)
        zalgo_btn.callback = self.toggle_anti_zalgo

        # Row 1: Zero-Day Hardening
        unban_btn = Button(label=f"Unban Guard  [{'ON' if conf.get('anti_unban_guard', True) else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("anti_unban_guard", True) else discord.ButtonStyle.secondary, row=1)
        unban_btn.callback = self.toggle_anti_unban
        
        imp_btn = Button(label=f"Impersonation  [{'ON' if conf.get('anti_impersonation', True) else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("anti_impersonation", True) else discord.ButtonStyle.secondary, row=1)
        imp_btn.callback = self.toggle_anti_impersonation
        
        fp_btn = Button(label=f"Raid Fingerprint  [{'ON' if conf.get('raid_fingerprint', True) else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("raid_fingerprint", True) else discord.ButtonStyle.secondary, row=1)
        fp_btn.callback = self.toggle_raid_fingerprint
        
        dm_btn = Button(label=f"Owner Alerts  [{'ON' if conf.get('dm_owner_alert', True) else 'OFF'}]", style=discord.ButtonStyle.primary if conf.get("dm_owner_alert", True) else discord.ButtonStyle.secondary, row=1)
        dm_btn.callback = self.toggle_dm_owner

        self.add_item(bot_btn)
        self.add_item(mass_btn)
        self.add_item(hijack_btn)
        self.add_item(panic_btn)
        self.add_item(zalgo_btn)
        self.add_item(unban_btn)
        self.add_item(imp_btn)
        self.add_item(fp_btn)
        self.add_item(dm_btn)

        # Row 2 Back button
        back_btn = Button(label=t("back", lang), style=discord.ButtonStyle.secondary, row=2)
        back_btn.callback = self.btn_back
        self.add_item(back_btn)

    async def toggle_anti_bot(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_bot_add", int(not get_config(self.guild_id).get("anti_bot_add")))
        await interaction.response.edit_message(embed=get_advanced_security_embed(self.guild_id), view=AdvancedSecurityView(self.guild_id))

    async def toggle_anti_mass(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_mass_action", int(not get_config(self.guild_id).get("anti_mass_action")))
        await interaction.response.edit_message(embed=get_advanced_security_embed(self.guild_id), view=AdvancedSecurityView(self.guild_id))

    async def toggle_anti_hijack(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_server_hijack", int(not get_config(self.guild_id).get("anti_server_hijack")))
        await interaction.response.edit_message(embed=get_advanced_security_embed(self.guild_id), view=AdvancedSecurityView(self.guild_id))

    async def toggle_auto_panic(self, interaction: discord.Interaction):
        update_config(self.guild_id, "auto_panic_escalation", int(not get_config(self.guild_id).get("auto_panic_escalation")))
        await interaction.response.edit_message(embed=get_advanced_security_embed(self.guild_id), view=AdvancedSecurityView(self.guild_id))

    async def toggle_anti_zalgo(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_zalgo", int(not get_config(self.guild_id).get("anti_zalgo")))
        await interaction.response.edit_message(embed=get_advanced_security_embed(self.guild_id), view=AdvancedSecurityView(self.guild_id))

    async def toggle_anti_unban(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_unban_guard", int(not get_config(self.guild_id).get("anti_unban_guard", True)))
        await interaction.response.edit_message(embed=get_advanced_security_embed(self.guild_id), view=AdvancedSecurityView(self.guild_id))

    async def toggle_anti_impersonation(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_impersonation", int(not get_config(self.guild_id).get("anti_impersonation", True)))
        await interaction.response.edit_message(embed=get_advanced_security_embed(self.guild_id), view=AdvancedSecurityView(self.guild_id))

    async def toggle_raid_fingerprint(self, interaction: discord.Interaction):
        update_config(self.guild_id, "raid_fingerprint", int(not get_config(self.guild_id).get("raid_fingerprint", True)))
        await interaction.response.edit_message(embed=get_advanced_security_embed(self.guild_id), view=AdvancedSecurityView(self.guild_id))

    async def toggle_dm_owner(self, interaction: discord.Interaction):
        update_config(self.guild_id, "dm_owner_alert", int(not get_config(self.guild_id).get("dm_owner_alert", True)))
        await interaction.response.edit_message(embed=get_advanced_security_embed(self.guild_id), view=AdvancedSecurityView(self.guild_id))

    async def btn_back(self, interaction: discord.Interaction):
        await interaction.response.edit_message(content=None, embed=get_main_embed(self.guild_id), view=MainDashboardView(self.guild_id))

def get_advanced_security_embed(guild_id: int):
    conf = get_config(guild_id)
    lang = conf.get("language", "th")
    badge = lambda k: f"`{t('active', lang)}`" if conf.get(k, True) else f"`{t('disabled', lang)}`"
    
    embed = discord.Embed(
        title=t("hardening_title", lang),
        description=t("hardening_desc", lang),
        color=discord.Color(0x2B2D31)
    )
    if lang == "th":
        embed.add_field(name="กันบอทแปลกหน้า", value=f"{badge('anti_bot_add')} • เตะบอทที่ไม่มีสิทธิ์", inline=True)
        embed.add_field(name="กันเตะ/แบนรัว", value=f"{badge('anti_mass_action')} • หยุดยั้งการ Abuse สิทธิ์", inline=True)
        embed.add_field(name="กันยึดเซิร์ฟเวอร์", value=f"{badge('anti_server_hijack')} • คืนค่าชื่อและรูปดิสทันที", inline=True)
        embed.add_field(name="ล็อกดาวน์อัตโนมัติ", value=f"{badge('auto_panic_escalation')} • ปิดห้องทันทีเมื่อโดน Raid", inline=True)
        embed.add_field(name="กรองตัวอักษร Zalgo", value=f"{badge('anti_zalgo')} • ลบข้อความที่ทำให้ดิสค้าง", inline=True)
        embed.add_field(name="กันแอบปลดแบน", value=f"{badge('anti_unban_guard')} • แบนซ้ำทันทีหากไม่ได้รับอนุญาต", inline=True)
        embed.add_field(name="กันปลอมชื่อ Staff", value=f"{badge('anti_impersonation')} • รีเซ็ตชื่อคล้ายแอดมินทันที", inline=True)
        embed.add_field(name="ตรวจจับลายนิ้วมือ Raid", value=f"{badge('raid_fingerprint')} • จับกลุ่มไอดีบอทบุกเซิร์ฟ", inline=True)
        embed.add_field(name="DM เตือน Owner", value=f"{badge('dm_owner_alert')} • ส่งข้อความตรงเมื่อเกิดเหตุร้ายแรง", inline=True)
    else:
        embed.add_field(name="Anti-Bot Gateway", value=f"{badge('anti_bot_add')} • Rejects unverified bots", inline=True)
        embed.add_field(name="Mass Action Guard", value=f"{badge('anti_mass_action')} • Halts rapid kick/timeouts", inline=True)
        embed.add_field(name="Server Hijack", value=f"{badge('anti_server_hijack')} • Reverts name/icon edits", inline=True)
        embed.add_field(name="Auto-Panic Raid", value=f"{badge('auto_panic_escalation')} • Locks channels on raids", inline=True)
        embed.add_field(name="Zalgo / Crash Filter", value=f"{badge('anti_zalgo')} • Drops corrupt crash text", inline=True)
        embed.add_field(name="Unban Bypass Guard", value=f"{badge('anti_unban_guard')} • Re-bans unauthorized unbans", inline=True)
        embed.add_field(name="Staff Impersonation", value=f"{badge('anti_impersonation')} • Resets lookalike names", inline=True)
        embed.add_field(name="Raid Fingerprint", value=f"{badge('raid_fingerprint')} • Correlates alt raid waves", inline=True)
        embed.add_field(name="Owner DM Alerts", value=f"{badge('dm_owner_alert')} • Direct emergency alerts", inline=True)
    embed.set_footer(text="คลิกปุ่มด้านล่างเพื่อเปิด/ปิดระบบ" if lang == "th" else "Click buttons below to toggle protections")
    return embed

# ==========================================
# SERVER CONFIGURATION & HONEYPOT VIEW
# ==========================================
def get_settings_embed(guild_id: int):
    conf = get_config(guild_id)
    lang = conf.get("language", "th")
    log_ch = f"<#{conf['log_channel']}>" if conf.get('log_channel') else ("`ยังไม่ตั้งค่า`" if lang == "th" else "`Unconfigured`")
    q_role = f"<@&{conf['quarantine_role_id']}>" if conf.get('quarantine_role_id') else ("`ยังไม่ตั้งค่า`" if lang == "th" else "`Unconfigured`")
    hp_ch = f"<#{conf['honeypot_channel_id']}>" if conf.get('honeypot_channel_id') else ("`ยังไม่สร้าง`" if lang == "th" else "`Not Deployed`")
    min_age = f"{conf.get('min_account_age_days', 3)} วัน" if lang == "th" else f"{conf.get('min_account_age_days', 3)} days"
    pin_status = "`ตั้งค่าแล้ว`" if lang == "th" else "`Configured`"
    
    embed = discord.Embed(
        title=t("settings_title", lang),
        description=t("settings_desc", lang),
        color=discord.Color(0x2B2D31)
    )
    embed.add_field(name="ห้องเก็บ Log" if lang == "th" else "Audit Log Channel", value=log_ch, inline=True)
    embed.add_field(name="ยศกักกัน (Quarantine)" if lang == "th" else "Quarantine Role", value=q_role, inline=True)
    embed.add_field(name="ห้องดักบอท (Decoy)" if lang == "th" else "Decoy Honeypot", value=hp_ch, inline=True)
    embed.add_field(name="อายุไอดีขั้นต่ำ" if lang == "th" else "Min Account Age", value=f"`{min_age}`", inline=True)
    embed.add_field(name="รหัส PIN 2FA" if lang == "th" else "2FA Security PIN", value=pin_status, inline=True)
    embed.set_footer(text="ใช้ปุ่มด้านล่างเพื่อแก้ไขการตั้งค่า" if lang == "th" else "Use the buttons below to edit settings")
    return embed

class SettingsMenuView(BaseSecurityView):
    def __init__(self, guild_id: int):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        conf = get_config(guild_id)
        lang = conf.get("language", "th")

        # Row 2 Back button
        back_btn = Button(label=t("back", lang), style=discord.ButtonStyle.secondary, row=2)
        back_btn.callback = self.btn_back
        self.add_item(back_btn)
        
    @discord.ui.select(cls=RoleSelect, placeholder="Select role to add/remove from Whitelist...", max_values=1, row=0)
    async def select_whitelist(self, interaction: discord.Interaction, select: RoleSelect):
        role = select.values[0]
        if role.id in get_whitelist(interaction.guild.id):
            remove_whitelist_db(interaction.guild.id, role.id)
            await interaction.response.send_message(f"Removed {role.mention} from Whitelist.", ephemeral=True)
        else:
            add_whitelist_db(interaction.guild.id, role.id, role.name)
            await interaction.response.send_message(f"Added {role.mention} to Whitelist.", ephemeral=True)

    @discord.ui.button(label="Audit Log Channel", style=discord.ButtonStyle.secondary, row=1)
    async def btn_set_log(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("log_channel_id", "Audit Log Channel ID"))

    @discord.ui.button(label="Quarantine Role", style=discord.ButtonStyle.secondary, row=1)
    async def btn_set_q(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("quarantine_role_id", "Quarantine Role ID"))

    @discord.ui.button(label="Min Account Age", style=discord.ButtonStyle.secondary, row=1)
    async def btn_set_min_age(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("min_account_age_days", "Minimum Account Age (Days)"))

    @discord.ui.button(label="2FA Owner PIN", style=discord.ButtonStyle.secondary, row=2)
    async def btn_set_pin(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("owner_pin", "Owner 2FA PIN (6 Digits)"))

    @discord.ui.button(label="Deploy Decoy Trap", style=discord.ButtonStyle.primary, row=2)
    async def btn_create_honeypot(self, interaction: discord.Interaction, button: Button):
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        overwrites = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False),
            guild.me: discord.PermissionOverwrite(read_messages=True)
        }
        channel = await guild.create_text_channel(name="security-decoy-trap", overwrites=overwrites, reason="Created hidden honeypot trap")
        update_config(guild.id, "honeypot_channel_id", channel.id)
        await interaction.followup.send(f"Deployed honeypot decoy channel {channel.mention}. Hidden from members; unauthorized posts trigger automatic bans.", ephemeral=True)

    async def btn_back(self, interaction: discord.Interaction):
        await interaction.response.edit_message(content=None, embed=get_main_embed(self.guild_id), view=MainDashboardView(self.guild_id))

# ==========================================
# BACKUP & DISASTER RECOVERY VIEW
# ==========================================
def get_backup_embed(guild_id: int):
    conf = get_config(guild_id)
    lang = conf.get("language", "th")
    latest = get_latest_backup(guild_id)
    if latest:
        dt = datetime.datetime.fromtimestamp(latest[1]).strftime('%d/%m/%Y %H:%M')
        data = json.loads(latest[2])
        status = f"**Backup #{latest[0]}** ({dt})\n• ยศ: `{len(data.get('roles', []))}` | ห้อง: `{len(data.get('channels', []))}`" if lang == "th" else f"**Backup #{latest[0]}** ({dt})\n• Roles: `{len(data.get('roles', []))}` | Channels: `{len(data.get('channels', []))}`"
    else:
        status = "*ยังไม่มีข้อมูลสำรองในระบบ*" if lang == "th" else "*No manual backup found in database.*"
        
    embed = discord.Embed(
        title=t("backup_title", lang),
        description=f"{t('backup_desc', lang)}\n\n**ข้อมูลสำรองล่าสุด**\n{status}" if lang == "th" else f"{t('backup_desc', lang)}\n\n**Latest Snapshot**\n{status}",
        color=discord.Color(0x2B2D31)
    )
    embed.set_footer(text="กดปุ่มด้านล่างเพื่อบันทึกหรือกู้คืนโครงสร้าง" if lang == "th" else "Use buttons below to save or restore")
    return embed

class BackupMenuView(BaseSecurityView):
    def __init__(self, guild_id: int = 0):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        conf = get_config(guild_id) if guild_id else {}
        lang = conf.get("language", "th")

        back_btn = Button(label=t("back", lang), style=discord.ButtonStyle.secondary)
        back_btn.callback = self.btn_back
        self.add_item(back_btn)

    @discord.ui.button(label="Save Snapshot", style=discord.ButtonStyle.primary)
    async def btn_create_backup(self, interaction: discord.Interaction, button: Button):
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        
        backup_data = {
            "name": guild.name,
            "roles": [{"name": r.name, "permissions": r.permissions.value, "color": r.color.value} for r in guild.roles if not r.is_default()],
            "categories": [{"name": c.name} for c in guild.categories],
            "channels": [{"name": ch.name, "type": str(ch.type), "category": ch.category.name if ch.category else None} for ch in guild.channels]
        }
        
        save_backup_to_db(guild.id, json.dumps(backup_data))
        await interaction.followup.send(f"Saved structure snapshot successfully ({len(backup_data['roles'])} roles, {len(backup_data['channels'])} channels).", ephemeral=True)

    @discord.ui.button(label="Restore from Snapshot", style=discord.ButtonStyle.danger)
    async def btn_restore_backup(self, interaction: discord.Interaction, button: Button):
        async def do_restore(inter: discord.Interaction):
            await inter.response.defer(ephemeral=True)
            backup_row = get_latest_backup(inter.guild.id)
            if not backup_row:
                return await inter.followup.send("No snapshot file found in system.", ephemeral=True)

            backup_id, ts, raw_json = backup_row
            dt = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            data = json.loads(raw_json)

            await inter.followup.send(f"**Owner 2FA Verified.**\nLoaded Backup #{backup_id} ({dt})\nStructure: {len(data.get('roles', []))} roles, {len(data.get('channels', []))} channels.\n*Ready for structure rebuild.*", ephemeral=True)

        await interaction.response.send_modal(OwnerPinModal("Restore Backup", do_restore))

    async def btn_back(self, interaction: discord.Interaction):
        g_id = interaction.guild.id if interaction.guild else self.guild_id
        await interaction.response.edit_message(content=None, embed=get_main_embed(g_id), view=MainDashboardView(g_id))

# ==========================================
# MAIN DASHBOARD EMBED & VIEW
# ==========================================
def get_main_embed(guild_id: int = 0, bot: discord.Client = None):
    conf = get_config(guild_id) if guild_id else {}
    lang = conf.get("language", "th")
    
    is_panic = conf.get("global_panic", False)
    panic_status = ("🔴 เปิดใช้งาน (Lockdown)" if lang == "th" else "🔴 Active (Lockdown)") if is_panic else ("🟢 ปกติ" if lang == "th" else "🟢 Inactive")
    defense_status = "🟢 พร้อมทำงาน" if lang == "th" else "🟢 Active"
    lang_name = "ไทย 🇹🇭" if lang == "th" else "English 🇬🇧"
    
    defense_lbl = "ระบบป้องกัน" if lang == "th" else "Protection"
    panic_lbl = "ล็อกดาวน์" if lang == "th" else "Lockdown"
    lang_lbl = "ภาษา" if lang == "th" else "Language"
    blocked_lbl = "บล็อกสะสม" if lang == "th" else "Total Mitigated"
    latest_lbl = "ล่าสุด" if lang == "th" else "Latest"
    unit_lbl = "ครั้ง" if lang == "th" else "threats"

    embed = discord.Embed(
        title=t("main_title", lang),
        description=t("main_desc", lang),
        color=discord.Color(0x2B2D31)
    )

    stats = get_security_stats(guild_id) if guild_id else {}
    total_blocked = sum(data.get("count", 0) for data in stats.values())

    embed.add_field(
        name="สถานะระบบ" if lang == "th" else "System Status",
        value=(
            f"• {defense_lbl}: `{defense_status}`\n"
            f"• {panic_lbl}: `{panic_status}`\n"
            f"• {lang_lbl}: `{lang_name}`"
        ),
        inline=True
    )

    incidents = get_recent_incidents(guild_id, limit=1) if guild_id else []
    if incidents:
        inc = incidents[0]
        t_str = datetime.datetime.fromtimestamp(inc["timestamp"]).strftime("%H:%M")
        desc = inc["description"]
        if len(desc) > 35:
            desc = desc[:32] + "..."
        recent_str = f"`[{t_str}]` {desc}"
    else:
        recent_str = "`ยังไม่พบภัยคุกคาม`" if lang == "th" else "`No threats recorded`"

    embed.add_field(
        name="สถิติการป้องกัน" if lang == "th" else "Mitigation Activity",
        value=(
            f"• {blocked_lbl}: `{total_blocked:,} {unit_lbl}`\n"
            f"• {latest_lbl}: {recent_str}"
        ),
        inline=True
    )

    embed.set_footer(text="พิมพ์ /security เพื่อเปิดแผงควบคุม" if lang == "th" else "Type /security to open this panel")
    return embed

class MainDashboardNavSelect(Select):
    def __init__(self, lang: str = "th"):
        options = [
            discord.SelectOption(
                label=t("sec_engine", lang),
                value="sec_engine",
                description="Anti-Nuke, กรองข้อความ, มัลแวร์, สแปม" if lang == "th" else "Anti-Nuke, content filter, anti-spam",
                emoji="🛡️"
            ),
            discord.SelectOption(
                label=t("hardening", lang),
                value="hardening",
                description="กันบอทแปลกหน้า, กันยึดเซิร์ฟ, ปลอมชื่อ Staff" if lang == "th" else "Anti-bot, anti-hijack, impersonation guard",
                emoji="⚡"
            ),
            discord.SelectOption(
                label=t("verify_access", lang),
                value="verify_access",
                description="เว็บ Verify แคปช่า, ดักจับ IP และ VPN" if lang == "th" else "Web captcha verification, IP & VPN guard",
                emoji="🔐"
            ),
            discord.SelectOption(
                label=t("member_controls", lang),
                value="member_controls",
                description="เตือน, มิวท์, กักกัน (Quarantine), แบน" if lang == "th" else "Warn, timeout, quarantine, ban",
                emoji="👥"
            ),
            discord.SelectOption(
                label=t("configuration", lang),
                value="configuration",
                description="ห้อง Log, ห้อง Decoy Trap, รหัส PIN" if lang == "th" else "Audit log channel, decoy trap, owner PIN",
                emoji="⚙️"
            ),
            discord.SelectOption(
                label=t("backup_restore", lang),
                value="backup_restore",
                description="บันทึก Snapshot โครงสร้างห้องและยศ" if lang == "th" else "Server structure snapshot & restore",
                emoji="💾"
            ),
        ]
        super().__init__(placeholder=t("nav_placeholder", lang), min_values=1, max_values=1, options=options, row=0)

    async def callback(self, interaction: discord.Interaction):
        selected = self.values[0]
        g_id = interaction.guild.id
        if selected == "sec_engine":
            await interaction.response.edit_message(embed=get_security_menu_embed(g_id), view=SecurityMenuView(g_id))
        elif selected == "hardening":
            await interaction.response.edit_message(embed=get_advanced_security_embed(g_id), view=AdvancedSecurityView(g_id))
        elif selected == "verify_access":
            await interaction.response.edit_message(embed=get_verify_embed(g_id), view=VerifyMenuView(g_id))
        elif selected == "member_controls":
            await interaction.response.edit_message(embed=get_moderation_embed(g_id), view=ModerationMenuView(g_id))
        elif selected == "configuration":
            await interaction.response.edit_message(embed=get_settings_embed(g_id), view=SettingsMenuView(g_id))
        elif selected == "backup_restore":
            await interaction.response.edit_message(embed=get_backup_embed(g_id), view=BackupMenuView(g_id))

class MainDashboardView(BaseSecurityView):
    def __init__(self, guild_id: int = 0):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        conf = get_config(guild_id) if guild_id else {}
        lang = conf.get("language", "th")

        # Row 0: Clean Navigation Dropdown
        self.add_item(MainDashboardNavSelect(lang))

        # Row 1: Clean Action Buttons (Only 3 essential buttons)
        is_panic = conf.get("global_panic", False)
        lockdown_label = t("unlock_btn", lang) if is_panic else t("lockdown_btn", lang)
        lockdown_style = discord.ButtonStyle.success if is_panic else discord.ButtonStyle.danger
        btn_lockdown = Button(label=lockdown_label, style=lockdown_style, row=1)
        btn_lockdown.callback = self.btn_toggle_lockdown
        self.add_item(btn_lockdown)

        btn_lang = Button(label=t("lang_toggle", lang), style=discord.ButtonStyle.secondary, row=1)
        btn_lang.callback = self.btn_language_toggle
        self.add_item(btn_lang)

        btn_refresh = Button(label=t("refresh_btn", lang), style=discord.ButtonStyle.secondary, row=1)
        btn_refresh.callback = self.btn_refresh_soc
        self.add_item(btn_refresh)

    async def btn_toggle_lockdown(self, interaction: discord.Interaction):
        conf = get_config(interaction.guild.id)
        curr = conf.get("global_panic", False)
        new_val = not curr
        update_config(interaction.guild.id, "global_panic", int(new_val))
        log_security_incident(interaction.guild.id, "EMERGENCY_LOCKDOWN", f"Lockdown set to {new_val} by {interaction.user.name}")
        await interaction.response.edit_message(embed=get_main_embed(interaction.guild.id, interaction.client), view=MainDashboardView(interaction.guild.id))

    async def btn_refresh_soc(self, interaction: discord.Interaction):
        await interaction.response.edit_message(embed=get_main_embed(interaction.guild.id, interaction.client), view=MainDashboardView(interaction.guild.id))

    async def btn_language_toggle(self, interaction: discord.Interaction):
        current_lang = get_config(interaction.guild.id).get("language", "th")
        new_lang = "en" if current_lang == "th" else "th"
        update_config(interaction.guild.id, "language", new_lang)
        await interaction.response.edit_message(embed=get_main_embed(interaction.guild.id, interaction.client), view=MainDashboardView(interaction.guild.id))

# ==========================================
# COMMANDS COG
# ==========================================
class DashboardCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command(name="security", aliases=["panel"])
    @commands.has_permissions(manage_messages=True)
    async def open_dashboard(self, ctx):
        g_id = ctx.guild.id if ctx.guild else 0
        await ctx.send(embed=get_main_embed(g_id, self.bot), view=MainDashboardView(g_id))

    @app_commands.command(name="security", description="Open the Security Control Center dashboard")
    @app_commands.checks.has_permissions(manage_messages=True)
    async def slash_security(self, interaction: discord.Interaction):
        g_id = interaction.guild.id if interaction.guild else 0
        await interaction.response.send_message(embed=get_main_embed(g_id, interaction.client), view=MainDashboardView(g_id))

    @commands.command(name="purge")
    @commands.has_permissions(manage_messages=True)
    async def command_purge(self, ctx, amount: int = 10):
        await ctx.message.delete()
        deleted = await ctx.channel.purge(limit=amount)
        await ctx.send(f"Purged **{len(deleted)}** messages.", delete_after=5)

    @app_commands.command(name="purge", description="Purge messages in the current channel")
    @app_commands.describe(amount="Number of messages to delete (1-100)")
    @app_commands.checks.has_permissions(manage_messages=True)
    async def slash_purge(self, interaction: discord.Interaction, amount: int = 10):
        await interaction.response.defer(ephemeral=True)
        deleted = await interaction.channel.purge(limit=amount)
        await interaction.followup.send(f"Purged **{len(deleted)}** messages.", ephemeral=True)

async def setup(bot):
    await bot.add_cog(DashboardCog(bot))