import discord
import json
import time
import datetime
import sqlite3
import asyncio
from collections import defaultdict
from discord import app_commands
from discord.ext import commands
from discord.ui import Button, View, Modal, TextInput, UserSelect, RoleSelect

from cogs.database import (
    DB_FILE, get_config, update_config, get_whitelist, 
    add_whitelist_db, remove_whitelist_db, add_warning, 
    get_warning_count, save_backup_to_db, send_audit_log,
    get_quarantine_data, remove_quarantine_data, get_latest_backup, ban_user_ips
)
from cogs.web_verify import generate_verify_signature, PORT

interaction_cooldowns = defaultdict(list)

def check_role_hierarchy(actor: discord.Member, target: discord.Member) -> bool:
    if actor.guild.owner_id == actor.id:
        return True
    if target.guild.owner_id == target.id:
        return False
    return actor.top_role > target.top_role

# ==========================================
# 3. HELPER FUNCTIONS & UI RATE LIMIT
# ==========================================
class BaseSecurityView(View):
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        now = time.time()
        user_id = interaction.user.id
        interaction_cooldowns[user_id] = [t for t in interaction_cooldowns[user_id] if now - t < 5]
        
        if len(interaction_cooldowns[user_id]) >= 4:
            if not interaction.response.is_done():
                try: await interaction.response.send_message("⚠️ **Abuse Detected:** คุณกดคำสั่งรัวเกินไป! กรุณารอสักครู่...", ephemeral=True)
                except: pass
            return False
        
        interaction_cooldowns[user_id].append(now)
        return True

# ==========================================
# 4. MODALS
# ==========================================
class PurgeModal(Modal, title="🧹 ระบุจำนวนข้อความที่ต้องการลบ"):
    amount = TextInput(label="จำนวนข้อความ (1-100)", placeholder="เช่น 20", default="10", max_length=3)
    async def on_submit(self, interaction: discord.Interaction):
        if not self.amount.value.isdigit():
            await interaction.response.send_message("❌ กรุณาระบุเป็นตัวเลขเท่านั้น!", ephemeral=True)
            return
        limit = int(self.amount.value)
        await interaction.response.defer(ephemeral=True)
        deleted = await interaction.channel.purge(limit=limit)
        await interaction.followup.send(f"🧹 ลบข้อความสำเร็จ **{len(deleted)}** ข้อความ", ephemeral=True)
        await send_audit_log(interaction.guild, "🧹 ใช้คำสั่ง Purge", f"โดย: {interaction.user.mention}\nจำนวน: {len(deleted)} ข้อความ", discord.Color.blue())

class PunishModal(Modal, title="⚖️ ระบุเหตุผลการลงโทษ"):
    reason = TextInput(label="เหตุผล", placeholder="พิมพ์เหตุผลที่นี่...", required=False, max_length=100)
    def __init__(self, action: str, target: discord.Member, **kwargs):
        super().__init__(**kwargs)
        self.action = action
        self.target = target

    async def on_submit(self, interaction: discord.Interaction):
        if not check_role_hierarchy(interaction.user, self.target):
            return await interaction.response.send_message("❌ **สิทธิ์ไม่พอ:** คุณไม่สามารถลงโทษสมาชิกที่มี ยศสูงกว่า หรือ เท่ากับ คุณได้!", ephemeral=True)

        reason = self.reason.value or "ไม่มีการระบุเหตุผล"
        await interaction.response.defer(ephemeral=True)
        try:
            if self.action == "mute":
                await self.target.timeout(datetime.timedelta(hours=1), reason=reason)
                await send_audit_log(interaction.guild, "🔇 ลงโทษ: Mute", f"เป้าหมาย: {self.target.mention}\nแอดมิน: {interaction.user.mention}\nเหตุผล: {reason}", discord.Color.orange())
            elif self.action == "kick":
                await self.target.kick(reason=reason)
                await send_audit_log(interaction.guild, "👢 ลงโทษ: Kick", f"เป้าหมาย: {self.target.mention}\nแอดมิน: {interaction.user.mention}", discord.Color.red())
            elif self.action == "ban":
                ban_user_ips(interaction.guild.id, self.target.id, f"Dashboard Ban by {interaction.user.name}")
                await self.target.ban(reason=reason)
                await send_audit_log(interaction.guild, "🔨 ลงโทษ: Ban (+ Auto IP Blacklist Sync)", f"เป้าหมาย: {self.target.mention}\nแอดมิน: {interaction.user.mention}", discord.Color.dark_red())
            await interaction.followup.send(f"✅ จัดการ {self.target.mention} สำเร็จ (พร้อมซิงก์แบน IP)", ephemeral=False)
        except discord.Forbidden:
            await interaction.followup.send("❌ บอทไม่มีสิทธิ์ หรือยศเป้าหมายสูงกว่าบอท", ephemeral=True)

class WarnModal(Modal, title="⚠️ ตักเตือนสมาชิก (Warning)"):
    reason = TextInput(label="เหตุผลการตักเตือน", placeholder="พิมพ์เหตุผล...", required=True)
    def __init__(self, target: discord.Member, **kwargs):
        super().__init__(**kwargs)
        self.target = target

    async def on_submit(self, interaction: discord.Interaction):
        reason = self.reason.value
        add_warning(interaction.guild.id, self.target.id, reason)
        count = get_warning_count(interaction.guild.id, self.target.id)
        
        await interaction.response.send_message(f"⚠️ เตือน {self.target.mention} แล้ว! (ครั้งที่ {count})")
        await send_audit_log(interaction.guild, "⚠️ ลงโทษ: Warn", f"เป้าหมาย: {self.target.mention}\nครั้งที่: {count}\nเหตุผล: {reason}", discord.Color.gold())
        
        conf = get_config(interaction.guild.id)
        if conf["strike"]:
            if count == 3:
                try: await self.target.timeout(datetime.timedelta(hours=1), reason="เตือนครบ 3 ครั้ง")
                except: pass
            elif count >= 5:
                try: await self.target.ban(reason="เตือนครบ 5 ครั้ง")
                except: pass

class SetupConfigModal(Modal, title="📝 ตั้งค่า Config"):
    target_id = TextInput(label="ระบุค่าที่ต้องการบันทึก", placeholder="ตัวเลข ID หรือ URL/Domain", required=True)
    def __init__(self, config_key: str, description: str, **kwargs):
        super().__init__(**kwargs)
        self.config_key = config_key
        self.description = description
        title_text = f"📝 ตั้งค่า {description}"
        self.title = title_text[:40]

    async def on_submit(self, interaction: discord.Interaction):
        val = self.target_id.value
        if self.config_key in ("owner_pin", "verify_domain"):
            update_config(interaction.guild.id, self.config_key, str(val))
            await interaction.response.send_message(f"✅ บันทึก **{self.description}** สำเร็จ (ค่า: `{val}`)", ephemeral=True)
        else:
            if not val.isdigit():
                await interaction.response.send_message("❌ กรุณาระบุตัวเลขเท่านั้น!", ephemeral=True)
                return
            update_config(interaction.guild.id, self.config_key, int(val))
            await interaction.response.send_message(f"✅ บันทึก **{self.description}** สำเร็จ (ค่า: `{val}`)", ephemeral=True)

class OwnerPinModal(Modal, title="🔑 ยืนยันรหัส Owner PIN (2FA)"):
    pin_input = TextInput(label="ระบุรหัส PIN 6 หลัก", placeholder="ค่าเริ่มต้น: 123456", required=True, max_length=10)
    
    def __init__(self, action_type: str, callback_coro, **kwargs):
        super().__init__(**kwargs)
        self.action_type = action_type
        self.callback_coro = callback_coro

    async def on_submit(self, interaction: discord.Interaction):
        conf = get_config(interaction.guild.id)
        if self.pin_input.value.strip() != conf["owner_pin"]:
            return await interaction.response.send_message("❌ **รหัส Owner PIN ไม่ถูกต้อง!** ยกเลิกการทำรายการเพื่อความปลอดภัย", ephemeral=True)
        
        await self.callback_coro(interaction)

# ==========================================
# 5. DASHBOARD VIEWS
# ==========================================
class UserActionView(BaseSecurityView):
    def __init__(self, target: discord.Member):
        super().__init__(timeout=180)
        self.target = target

    @discord.ui.button(label="⚠️ Warn", style=discord.ButtonStyle.secondary, row=0)
    async def btn_warn(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(WarnModal(target=self.target))

    @discord.ui.button(label="🔇 Mute", style=discord.ButtonStyle.secondary, row=0)
    async def btn_mute(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(PunishModal(action="mute", target=self.target))

    @discord.ui.button(label="🛡️ Quarantine", style=discord.ButtonStyle.primary, row=0)
    async def btn_quarantine(self, interaction: discord.Interaction, button: Button):
        if not check_role_hierarchy(interaction.user, self.target):
            return await interaction.response.send_message("❌ **สิทธิ์ไม่พอ:** ยศคุณไม่สูงกว่าผู้ใช้รายนี้", ephemeral=True)
        conf = get_config(interaction.guild.id)
        if not conf["quarantine_role_id"]:
            return await interaction.response.send_message("❌ ยังไม่ได้ตั้งค่ายศ Quarantine!", ephemeral=True)
        q_role = interaction.guild.get_role(conf["quarantine_role_id"])
        
        roles_str = ",".join([str(r.id) for r in self.target.roles if r.name != "@everyone"])
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO quarantine (guild_id, user_id, original_roles) VALUES (?, ?, ?)", (interaction.guild.id, self.target.id, roles_str))
        conn.commit()
        conn.close()

        await interaction.response.defer(ephemeral=True)
        try:
            await self.target.edit(roles=[q_role], reason="Quarantine")
            await interaction.followup.send(f"✅ กักบริเวณ {self.target.mention} เรียบร้อย", ephemeral=True)
            await send_audit_log(interaction.guild, "🛡️ Quarantine", f"{self.target.mention} ถูกกักบริเวณ", discord.Color.purple())
        except: await interaction.followup.send("❌ บอทไม่มีสิทธิ์จัดการยศเป้าหมาย", ephemeral=True)

    @discord.ui.button(label="🔓 Un-Quarantine", style=discord.ButtonStyle.success, row=1)
    async def btn_unquarantine(self, interaction: discord.Interaction, button: Button):
        orig_roles_str = get_quarantine_data(interaction.guild.id, self.target.id)
        if not orig_roles_str:
            return await interaction.response.send_message("❌ ไม่พบข้อมูลยศเดิมของผู้ใช้นี้ในฐานข้อมูล Quarantine!", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        try:
            role_ids = [int(r) for r in orig_roles_str.split(",") if r.isdigit()]
            roles_to_restore = [interaction.guild.get_role(r_id) for r_id in role_ids if interaction.guild.get_role(r_id)]
            
            await self.target.edit(roles=roles_to_restore, reason="Un-Quarantine Restoration")
            remove_quarantine_data(interaction.guild.id, self.target.id)
            await interaction.followup.send(f"🟢 ปลดกักบริเวณและคืนยศเดิมให้ {self.target.mention} สำเร็จ!", ephemeral=True)
            await send_audit_log(interaction.guild, "🔓 Un-Quarantine", f"ปลดกักบริเวณผู้ใช้ {self.target.mention} โดย {interaction.user.mention}", discord.Color.green())
        except Exception as e:
            await interaction.followup.send(f"❌ เกิดข้อผิดพลาดในการคืนยศ: {e}", ephemeral=True)

    @discord.ui.button(label="🔨 Ban", style=discord.ButtonStyle.danger, row=1)
    async def btn_ban(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(PunishModal(action="ban", target=self.target))

    @discord.ui.button(label="🔙 กลับ", style=discord.ButtonStyle.secondary, row=1)
    async def btn_back(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(content="⚖️ **หมวดการจัดการ**", view=ModerationMenuView(), embed=None)

class ModerationMenuView(BaseSecurityView):
    def __init__(self):
        super().__init__(timeout=300)

    @discord.ui.select(cls=UserSelect, placeholder="📌 ค้นหาและเลือกสมาชิก...", max_values=1)
    async def select_user(self, interaction: discord.Interaction, select: UserSelect):
        embed = discord.Embed(title=f"จัดการ: {select.values[0].name}", color=discord.Color.orange())
        await interaction.response.edit_message(embed=embed, view=UserActionView(target=select.values[0]))

    @discord.ui.button(label="🔙 กลับหน้าหลัก", style=discord.ButtonStyle.secondary, row=1)
    async def btn_back(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(content=None, embed=get_main_embed(), view=MainDashboardView())

import socket
import os

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

# ==========================================
# 🔐 VERIFY & IP GUARD MENU VIEW
# ==========================================
class VerifyPublicButton(View):
    def __init__(self, guild_id: int):
        super().__init__(timeout=None)
        self.guild_id = guild_id

    @discord.ui.button(label="✅ ยืนยันตัวตนเข้าดิส", style=discord.ButtonStyle.success, custom_id="persistent_web_verify_btn")
    async def btn_verify_click(self, interaction: discord.Interaction, button: Button):
        guild = interaction.guild
        user = interaction.user
        sig = generate_verify_signature(guild.id, user.id)
        
        base_host = get_public_verify_host(guild.id)
        verify_url = f"{base_host}/verify?guild_id={guild.id}&user_id={user.id}&sig={sig}&username={user.display_name}&handle={user.name}&avatar={user.display_avatar.url}"
        
        embed = discord.Embed(
            title="🔐 เว็บไซต์ยืนยันตัวตน (Web Verification)",
            description=f"กรุณากดที่ปุ่มด้านล่างเพื่อเปิดหน้าเว็บยืนยันตัวตนเข้าเซิร์ฟเวอร์\n\n[👉 **คลิกที่นี่เพื่อเปิดหน้าเว็บ Verify**]({verify_url})",
            color=discord.Color.from_rgb(225, 29, 72)
        )
        embed.set_footer(text="รองรับมือถือและคอมพิวเตอร์ • ระบบจะบันทึก IP เพื่อป้องกันบัญชีถูกแบน")

        view = View()
        view.add_item(Button(label="🌐 เปิดหน้าเว็บ Verify ทันที ↗", url=verify_url, style=discord.ButtonStyle.link))
        
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

class VerifyMenuView(BaseSecurityView):
    def __init__(self, guild_id: int):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        conf = get_config(guild_id)

        ip_guard_label = "🛡️ IP Ban Guard: เปิด" if conf["ip_ban_guard"] else "🛡️ IP Ban Guard: ปิด"
        ip_guard_style = discord.ButtonStyle.success if conf["ip_ban_guard"] else discord.ButtonStyle.danger
        
        btn_ip_guard = Button(label=ip_guard_label, style=ip_guard_style, row=0)
        btn_ip_guard.callback = self.toggle_ip_guard
        self.add_item(btn_ip_guard)

        vpn_label = "🌐 Anti-VPN: เปิด" if conf.get("anti_vpn") else "🌐 Anti-VPN: ปิด"
        vpn_style = discord.ButtonStyle.success if conf.get("anti_vpn") else discord.ButtonStyle.danger
        
        btn_vpn = Button(label=vpn_label, style=vpn_style, row=0)
        btn_vpn.callback = self.toggle_vpn
        self.add_item(btn_vpn)

    async def toggle_ip_guard(self, interaction: discord.Interaction):
        conf = get_config(self.guild_id)
        update_config(self.guild_id, "ip_ban_guard", int(not conf["ip_ban_guard"]))
        await interaction.response.edit_message(embed=get_verify_embed(self.guild_id), view=VerifyMenuView(self.guild_id))

    async def toggle_vpn(self, interaction: discord.Interaction):
        conf = get_config(self.guild_id)
        update_config(self.guild_id, "anti_vpn", int(not conf.get("anti_vpn")))
        await interaction.response.edit_message(embed=get_verify_embed(self.guild_id), view=VerifyMenuView(self.guild_id))

    @discord.ui.select(cls=RoleSelect, placeholder="🎭 เลือกยศที่จะมอบให้หลัง Verify...", max_values=1, row=1)
    async def select_verify_role(self, interaction: discord.Interaction, select: RoleSelect):
        role = select.values[0]
        update_config(interaction.guild.id, "verify_role_id", role.id)
        await interaction.response.send_message(f"✅ ตั้งค่ายศหลัง Verify สำเร็จ: {role.mention}", ephemeral=True)

    @discord.ui.button(label="📝 ช่องที่จะส่ง Verify", style=discord.ButtonStyle.primary, row=2)
    async def btn_set_verify_channel(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("verify_channel_id", "ช่องที่จะส่งปุ่ม Verify"))

    @discord.ui.button(label="🌐 ตั้งค่า Domain/IP เว็บ", style=discord.ButtonStyle.secondary, row=2)
    async def btn_set_domain(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("verify_domain", "Domain/IP เว็บไซต์"))

    @discord.ui.button(label="📨 ส่งข้อความ Verify เข้าห้อง", style=discord.ButtonStyle.success, row=2)
    async def btn_send_verify_embed(self, interaction: discord.Interaction, button: Button):
        conf = get_config(interaction.guild.id)
        channel_id = conf["verify_channel_id"] or interaction.channel_id
        target_channel = interaction.guild.get_channel(channel_id)
        
        if not target_channel:
            return await interaction.response.send_message("❌ ไม่พบช่องสำหรับส่งข้อความ Verify!", ephemeral=True)

        guild_name = interaction.guild.name
        embed = discord.Embed(
            title=f"🔒 {guild_name} • ยืนยันตัวตนเพื่อเข้าโซน",
            description=f"✦ **ยินดีต้อนรับสู่ {guild_name}** ✦\n\n"
                        f"### เพื่อความปลอดภัยของชุมชน\n"
                        f"**กรุณายืนยันตัวตนผ่านระบบก่อนใช้งานโซนต่างๆ**\n\n"
                        f"> ✅ **คลิกปุ่มด้านล่างเพื่อเริ่มต้น**\n"
                        f"> 🔑 **อนุญาตสิทธิ์ที่ระบบร้องขอ**\n"
                        f"> 🏅 **รับยศอัตโนมัติ + เข้าเซิร์ฟในเครือทันที**\n\n"
                        f"------------------------------------\n"
                        f"🛡️ **ระบบยืนยันตัวตนอัตโนมัติ • ปลอดภัย 100%**",
            color=discord.Color.from_rgb(225, 29, 72)
        )
        embed.set_footer(text=f"{guild_name} • Verify System")

        await target_channel.send(embed=embed, view=VerifyPublicButton(interaction.guild.id))
        await interaction.response.send_message(f"✅ ส่งข้อความ Verify ไปยังช่อง {target_channel.mention} เรียบร้อย!", ephemeral=True)

    @discord.ui.button(label="🔙 กลับหน้าหลัก", style=discord.ButtonStyle.secondary, row=3)
    async def btn_back(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(content=None, embed=get_main_embed(), view=MainDashboardView())

def get_verify_embed(guild_id: int):
    conf = get_config(guild_id)
    v_chan = f"<#{conf['verify_channel_id']}>" if conf['verify_channel_id'] else "`ยังไม่ได้ตั้ง`"
    v_role = f"<@&{conf['verify_role_id']}>" if conf['verify_role_id'] else "`ยังไม่ได้ตั้ง`"
    ip_status = "🟢 เปิดใช้งาน" if conf['ip_ban_guard'] else "🔴 ปิดใช้งาน"
    vpn_status = "🟢 เปิดใช้งาน" if conf.get('anti_vpn') else "🔴 ปิดใช้งาน"
    domain_status = f"`{conf['verify_domain']}`" if conf.get('verify_domain') else f"`{get_public_verify_host(guild_id)}` (Auto LAN/Default)"
    
    embed = discord.Embed(title="🔐 ตั้งค่าระบบ Verify & Web IP/Anti-VPN Guard", color=discord.Color.green())
    embed.add_field(name="📌 ช่องส่งข้อความ Verify", value=v_chan, inline=True)
    embed.add_field(name="🎭 ยศหลังผ่านการ Verify", value=v_role, inline=True)
    embed.add_field(name="🛡️ IP Ban Guard", value=ip_status, inline=True)
    embed.add_field(name="🌐 Anti-VPN / Proxy", value=vpn_status, inline=True)
    embed.add_field(name="🌐 Host/Domain เว็บไซต์", value=domain_status, inline=False)
    embed.description = "ระบบป้องกันไอดีอวตาร (Alt Token Raid) & ป้องกันการมุด VPN (รองรับมือถือและคอม)"
    return embed

# ==========================================
# SECURITY MENU & SETTINGS
# ==========================================
class SecurityMenuView(BaseSecurityView):
    def __init__(self, guild_id: int):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        conf = get_config(guild_id)
        
        # Row 0
        mal_btn = Button(label="✅ กรองไฟล์" if conf["malware"] else "❌ กรองไฟล์", style=discord.ButtonStyle.success if conf["malware"] else discord.ButtonStyle.secondary, row=0)
        mal_btn.callback = self.toggle_malware
        ai_btn = Button(label="🤖 AI Filter" if conf["ai"] else "🤖 AI (ปิด)", style=discord.ButtonStyle.success if conf["ai"] else discord.ButtonStyle.secondary, row=0)
        ai_btn.callback = self.toggle_ai
        phish_btn = Button(label="🌐 Phishing" if conf["phishing_api"] else "🌐 Phish (ปิด)", style=discord.ButtonStyle.success if conf["phishing_api"] else discord.ButtonStyle.danger, row=0)
        phish_btn.callback = self.toggle_phishing
        dox_btn = Button(label="👁️ Anti-Dox" if conf["anti_dox"] else "👁️ Anti-Dox (ปิด)", style=discord.ButtonStyle.success if conf["anti_dox"] else discord.ButtonStyle.danger, row=0)
        dox_btn.callback = self.toggle_dox

        # Row 1
        nuke_btn = Button(label="🛡️ Anti-Nuke" if conf["anti_nuke"] else "🛡️ Nuke (ปิด)", style=discord.ButtonStyle.success if conf["anti_nuke"] else discord.ButtonStyle.danger, row=1)
        nuke_btn.callback = self.toggle_nuke
        mention_btn = Button(label="📢 Mass Mention" if conf["anti_mention"] else "📢 Mention (ปิด)", style=discord.ButtonStyle.success if conf["anti_mention"] else discord.ButtonStyle.danger, row=1)
        mention_btn.callback = self.toggle_mention
        voice_btn = Button(label="🎙️ Voice Raid" if conf["voice_anti_raid"] else "🎙️ Voice (ปิด)", style=discord.ButtonStyle.success if conf["voice_anti_raid"] else discord.ButtonStyle.danger, row=1)
        voice_btn.callback = self.toggle_voice
        perm_btn = Button(label="🔒 Perm Enforce" if conf["enforce_permissions"] else "🔒 Perm (ปิด)", style=discord.ButtonStyle.success if conf["enforce_permissions"] else discord.ButtonStyle.danger, row=1)
        perm_btn.callback = self.toggle_perm

        # Row 2
        ghost_btn = Button(label="👻 Ghost Ping" if conf.get("ghost_ping_guard") else "👻 Ghost (ปิด)", style=discord.ButtonStyle.success if conf.get("ghost_ping_guard") else discord.ButtonStyle.danger, row=2)
        ghost_btn.callback = self.toggle_ghost
        invite_btn = Button(label="🔗 Anti-Invite" if conf.get("anti_invite") else "🔗 Invite (ปิด)", style=discord.ButtonStyle.success if conf.get("anti_invite") else discord.ButtonStyle.danger, row=2)
        invite_btn.callback = self.toggle_invite
        wh_btn = Button(label="⚓ Webhook Guard" if conf.get("webhook_guard") else "⚓ Webhook (ปิด)", style=discord.ButtonStyle.success if conf.get("webhook_guard") else discord.ButtonStyle.danger, row=2)
        wh_btn.callback = self.toggle_webhook
        suspect_btn = Button(label="🔍 สแกนไอดีสงสัย" if conf.get("suspect_scan") else "🔍 สแกนไอดี (ปิด)", style=discord.ButtonStyle.success if conf.get("suspect_scan") else discord.ButtonStyle.danger, row=2)
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

    async def toggle_malware(self, interaction: discord.Interaction):
        update_config(self.guild_id, "malware_filter", int(not get_config(self.guild_id)["malware"]))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    async def toggle_ai(self, interaction: discord.Interaction):
        update_config(self.guild_id, "ai_filter", int(not get_config(self.guild_id)["ai"]))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    async def toggle_phishing(self, interaction: discord.Interaction):
        update_config(self.guild_id, "phishing_api", int(not get_config(self.guild_id)["phishing_api"]))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    async def toggle_dox(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_dox", int(not get_config(self.guild_id)["anti_dox"]))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    async def toggle_nuke(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_nuke", int(not get_config(self.guild_id)["anti_nuke"]))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    async def toggle_mention(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_mention", int(not get_config(self.guild_id)["anti_mention"]))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    async def toggle_voice(self, interaction: discord.Interaction):
        update_config(self.guild_id, "voice_anti_raid", int(not get_config(self.guild_id)["voice_anti_raid"]))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    async def toggle_perm(self, interaction: discord.Interaction):
        update_config(self.guild_id, "enforce_permissions", int(not get_config(self.guild_id)["enforce_permissions"]))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    async def toggle_ghost(self, interaction: discord.Interaction):
        update_config(self.guild_id, "ghost_ping_guard", int(not get_config(self.guild_id).get("ghost_ping_guard")))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    async def toggle_invite(self, interaction: discord.Interaction):
        update_config(self.guild_id, "anti_invite", int(not get_config(self.guild_id).get("anti_invite")))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    async def toggle_webhook(self, interaction: discord.Interaction):
        update_config(self.guild_id, "webhook_guard", int(not get_config(self.guild_id).get("webhook_guard")))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    async def toggle_suspect(self, interaction: discord.Interaction):
        update_config(self.guild_id, "suspect_scan", int(not get_config(self.guild_id).get("suspect_scan")))
        await interaction.response.edit_message(view=SecurityMenuView(self.guild_id))

    @discord.ui.button(label="🔍 สแกนย้อนหลัง (Manual)", style=discord.ButtonStyle.primary, row=3)
    async def btn_manual_backlog_scan(self, interaction: discord.Interaction, button: Button):
        await interaction.response.defer(ephemeral=True)
        sec_cog = interaction.client.get_cog("SecurityEventsCog")
        if sec_cog and hasattr(sec_cog, "run_guild_backlog_scan"):
            scanned, deleted, suspect_list = await sec_cog.run_guild_backlog_scan(interaction.guild)
            suspect_count = len(suspect_list)
            
            first_msg = (
                f"✅ **สแกนความปลอดภัยย้อนหลังสำเร็จ!**\n"
                f"• สแกนข้อความย้อนหลังไป: **{scanned}** ข้อความ\n"
                f"• ตรวจพบและลบข้อความสุ่มเสี่ยง: **{deleted}** ข้อความ\n"
                f"• ตรวจพบสมาชิกน่าสงสัยในดิส: **{suspect_count}** บัญชี"
            )
            await interaction.followup.send(first_msg, ephemeral=True)

            if suspect_count > 0:
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                chunk_size = 15
                total_batches = ((suspect_count - 1) // chunk_size) + 1

                for i in range(0, suspect_count, chunk_size):
                    chunk = suspect_list[i : i + chunk_size]
                    batch_lines = [f"📌 **รายชื่อสมาชิกน่าสงสัย (ชุดที่ {i//chunk_size + 1}/{total_batches}):**"]
                    for m in chunk:
                        age_days = (now_utc - m.created_at).days
                        batch_lines.append(f"• {m.mention} (`{m.id}`) - อายุบัญชี {age_days} วัน")
                    
                    await interaction.followup.send("\n".join(batch_lines), ephemeral=True)
                    await asyncio.sleep(0.2)
        else:
            await interaction.followup.send("❌ ระบบสแกนไม่พร้อมใช้งาน", ephemeral=True)

    @discord.ui.button(label="🚨 Global Panic (ล็อกดาวน์)", style=discord.ButtonStyle.danger, row=3)
    async def btn_panic(self, interaction: discord.Interaction, button: Button):
        async def do_panic(inter: discord.Interaction):
            await inter.response.send_message("🚨 **กำลังล็อกดาวน์ทุกห้อง!**", ephemeral=False)
            guild = inter.guild
            default_role = guild.default_role
            for channel in guild.channels:
                try:
                    overwrite = channel.overwrites_for(default_role)
                    overwrite.send_messages = False
                    overwrite.connect = False
                    await channel.set_permissions(default_role, overwrite=overwrite)
                except: pass
            await inter.followup.send("✅ ล็อกดาวน์สำเร็จ!", ephemeral=False)
            await send_audit_log(guild, "🚨 GLOBAL PANIC", f"ล็อกเซิร์ฟเวอร์โดย: {inter.user.mention}", discord.Color.dark_red())

        await interaction.response.send_modal(OwnerPinModal("Global Panic", do_panic))

    @discord.ui.button(label="🟢 ปลด Global Panic", style=discord.ButtonStyle.success, row=3)
    async def btn_unpanic(self, interaction: discord.Interaction, button: Button):
        async def do_unpanic(inter: discord.Interaction):
            await inter.response.send_message("🟢 **กำลังปลดล็อกดาวน์!**", ephemeral=False)
            guild = inter.guild
            default_role = guild.default_role
            for channel in guild.channels:
                try:
                    overwrite = channel.overwrites_for(default_role)
                    overwrite.send_messages = None
                    overwrite.connect = None
                    await channel.set_permissions(default_role, overwrite=overwrite)
                except: pass
            await inter.followup.send("✅ ปลดล็อกดาวน์สำเร็จ!", ephemeral=False)

        await interaction.response.send_modal(OwnerPinModal("Unpanic Lockdown", do_unpanic))

    @discord.ui.button(label="🔙 กลับ", style=discord.ButtonStyle.secondary, row=3)
    async def btn_back(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(content=None, embed=get_main_embed(), view=MainDashboardView())

class SettingsMenuView(BaseSecurityView):
    def __init__(self, guild_id: int):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        
    @discord.ui.select(cls=RoleSelect, placeholder="📌 เลือกยศ Whitelist", max_values=1, row=0)
    async def select_whitelist(self, interaction: discord.Interaction, select: RoleSelect):
        role = select.values[0]
        if role.id in get_whitelist(interaction.guild.id):
            remove_whitelist_db(interaction.guild.id, role.id)
            await interaction.response.send_message(f"❌ ถอดยศ {role.mention} จาก Whitelist", ephemeral=True)
        else:
            add_whitelist_db(interaction.guild.id, role.id, role.name)
            await interaction.response.send_message(f"✅ เพิ่มยศ {role.mention} เข้า Whitelist", ephemeral=True)

    @discord.ui.button(label="📝 ตั้งช่อง Log", style=discord.ButtonStyle.primary, row=1)
    async def btn_set_log(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("log_channel_id", "ช่อง Audit Log"))

    @discord.ui.button(label="📝 ยศ Quarantine", style=discord.ButtonStyle.primary, row=1)
    async def btn_set_q(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("quarantine_role_id", "ยศกักบริเวณ"))

    @discord.ui.button(label="⏱️ อายุกุมารไอดี (วัน)", style=discord.ButtonStyle.secondary, row=1)
    async def btn_set_min_age(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("min_account_age_days", "อายุบัญชีขั้นต่ำกัน Raid (วัน)"))

    @discord.ui.button(label="🔑 ตั้งค่า Owner PIN (2FA)", style=discord.ButtonStyle.danger, row=2)
    async def btn_set_pin(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_modal(SetupConfigModal("owner_pin", "Owner Security PIN (6 หลัก)"))

    @discord.ui.button(label="🍯 สร้างห้อง Honeypot", style=discord.ButtonStyle.danger, row=2)
    async def btn_create_honeypot(self, interaction: discord.Interaction, button: Button):
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        overwrites = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False),
            guild.me: discord.PermissionOverwrite(read_messages=True)
        }
        channel = await guild.create_text_channel(name="🛑-security-trap", overwrites=overwrites, reason="สร้างห้อง Honeypot ล่องหน")
        update_config(guild.id, "honeypot_channel_id", channel.id)
        await interaction.followup.send(f"✅ สร้างห้อง {channel.mention} เรียบร้อย! (ซ่อนจากทุกคน ใครพิมพ์ในนี้ = บอทสแปมและจะถูกแบนทันที)", ephemeral=True)

    @discord.ui.button(label="🔙 กลับ", style=discord.ButtonStyle.secondary, row=2)
    async def btn_back(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(content=None, embed=get_main_embed(), view=MainDashboardView())

class BackupMenuView(BaseSecurityView):
    def __init__(self):
        super().__init__(timeout=300)

    @discord.ui.button(label="💾 Backup โครงสร้างเซิร์ฟเวอร์", style=discord.ButtonStyle.primary)
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
        await interaction.followup.send(f"✅ บันทึก Backup โครงสร้างเซิร์ฟเวอร์สำเร็จ! (เก็บข้อมูลยศ {len(backup_data['roles'])} ยศ และช่อง {len(backup_data['channels'])} ช่อง)", ephemeral=True)

    @discord.ui.button(label="🔄 Restore Backup ล่าสุด", style=discord.ButtonStyle.danger)
    async def btn_restore_backup(self, interaction: discord.Interaction, button: Button):
        async def do_restore(inter: discord.Interaction):
            await inter.response.defer(ephemeral=True)
            backup_row = get_latest_backup(inter.guild.id)
            if not backup_row:
                return await inter.followup.send("❌ ไม่พบไฟล์ Backup ในระบบ!", ephemeral=True)

            backup_id, ts, raw_json = backup_row
            dt = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            data = json.loads(raw_json)

            await inter.followup.send(f"✅ **Owner 2FA Verified!**\nพบ Backup ID #{backup_id} บันทึกเมื่อ ({dt})\nโครงสร้างประกอบด้วย: {len(data.get('roles', []))} ยศ, {len(data.get('channels', []))} ช่อง\n*ระบบพร้อมสำหรับการฟื้นฟูโครงสร้าง*", ephemeral=True)

        await interaction.response.send_modal(OwnerPinModal("Restore Backup", do_restore))

    @discord.ui.button(label="🔙 กลับ", style=discord.ButtonStyle.secondary)
    async def btn_back(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(content=None, embed=get_main_embed(), view=MainDashboardView())

def get_main_embed():
    return discord.Embed(title="🖥️ ศูนย์ควบคุม (Enterprise Guard - Zero Day)", description="ใช้งานด้วย UI 100% ป้องกันถึงแก่น ควบคุมทุกหมวดหมู่", color=discord.Color.blurple())

class MainDashboardView(BaseSecurityView):
    def __init__(self):
        super().__init__(timeout=300)

    @discord.ui.button(label="🛡️ ความปลอดภัยขั้นสูง", style=discord.ButtonStyle.danger, row=0)
    async def btn_security(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(embed=discord.Embed(title="🛡️ ความปลอดภัยขั้นสูง", color=discord.Color.red()), view=SecurityMenuView(interaction.guild.id))

    @discord.ui.button(label="🔐 ระบบ Verify & IP Guard", style=discord.ButtonStyle.success, row=0)
    async def btn_verify(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(embed=get_verify_embed(interaction.guild.id), view=VerifyMenuView(interaction.guild.id))

    @discord.ui.button(label="⚖️ จัดการสมาชิก & กักกัน", style=discord.ButtonStyle.primary, row=1)
    async def btn_mod(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(embed=discord.Embed(title="⚖️ จัดการสมาชิก & กักกัน", color=discord.Color.orange()), view=ModerationMenuView())

    @discord.ui.button(label="⚙️ ตั้งค่า & Honeypot", style=discord.ButtonStyle.secondary, row=1)
    async def btn_settings(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(embed=discord.Embed(title="⚙️ ตั้งค่าระบบ & Honeypot", color=discord.Color.greyple()), view=SettingsMenuView(interaction.guild.id))

    @discord.ui.button(label="💾 ระบบ Backup & Restore", style=discord.ButtonStyle.secondary, row=1)
    async def btn_backup(self, interaction: discord.Interaction, button: Button):
        await interaction.response.edit_message(embed=discord.Embed(title="💾 Backup & Restore", color=discord.Color.green()), view=BackupMenuView())


class DashboardCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command(name="security", aliases=["panel"])
    @commands.has_permissions(manage_messages=True)
    async def open_dashboard(self, ctx):
        await ctx.send(embed=get_main_embed(), view=MainDashboardView())

    @app_commands.command(name="security", description="🖥️ เปิดศูนย์ควบคุมระบบความปลอดภัย (Security Dashboard)")
    @app_commands.checks.has_permissions(manage_messages=True)
    async def slash_security(self, interaction: discord.Interaction):
        await interaction.response.send_message(embed=get_main_embed(), view=MainDashboardView())

    @commands.command(name="purge")
    @commands.has_permissions(manage_messages=True)
    async def command_purge(self, ctx, amount: int = 10):
        await ctx.message.delete()
        deleted = await ctx.channel.purge(limit=amount)
        await ctx.send(f"🧹 ลบสำเร็จ **{len(deleted)}** ข้อความ", delete_after=5)

    @app_commands.command(name="purge", description="🧹 ลบข้อความในช่องที่ต้องการ")
    @app_commands.describe(amount="จำนวนข้อความที่ต้องการลบ (1-100)")
    @app_commands.checks.has_permissions(manage_messages=True)
    async def slash_purge(self, interaction: discord.Interaction, amount: int = 10):
        await interaction.response.defer(ephemeral=True)
        deleted = await interaction.channel.purge(limit=amount)
        await interaction.followup.send(f"🧹 ลบสำเร็จ **{len(deleted)}** ข้อความ", ephemeral=True)

async def setup(bot):
    await bot.add_cog(DashboardCog(bot))