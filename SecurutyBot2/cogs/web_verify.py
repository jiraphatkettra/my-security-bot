import os
import time
import hmac
import hashlib
import json
import random
import aiohttp
import discord
from discord.ext import commands
from aiohttp import web

from cogs.database import (
    get_config, add_ip_log, check_user_ip_banned, ban_ip, send_audit_log
)

SECRET_KEY = os.getenv("VERIFY_SECRET", "super_secret_security_key_rover_2026")
PORT = int(os.getenv("PORT", os.getenv("VERIFY_PORT", "8080")))

vpn_cache = {}

async def is_vpn_or_proxy(ip: str) -> bool:
    if ip in ("127.0.0.1", "localhost", "::1") or ip.startswith("192.168.") or ip.startswith("10."):
        return False
    if ip in vpn_cache:
        return vpn_cache[ip]
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://ip-api.com/json/{ip}?fields=status,hosting,proxy", timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        is_vpn = bool(data.get("hosting") or data.get("proxy"))
                        vpn_cache[ip] = is_vpn
                        return is_vpn
    except:
        pass
    return False

def generate_verify_signature(guild_id: int, user_id: int) -> str:
    message = f"{guild_id}:{user_id}".encode()
    return hmac.new(SECRET_KEY.encode(), message, hashlib.sha256).hexdigest()

def verify_signature(guild_id: int, user_id: int, signature: str) -> bool:
    expected = generate_verify_signature(guild_id, user_id)
    return hmac.compare_digest(expected, signature)

# ==========================================
# 🎨 HTML TEMPLATE (EXACT UI MATCH FROM SCREENSHOT)
# ==========================================
SUCCESS_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ยืนยันตัวตนสำเร็จ</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Prompt:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Prompt', sans-serif;
        }
        body {
            background-color: #0b0d14;
            background-image: 
                radial-gradient(circle at 50% 30%, rgba(16, 185, 129, 0.08) 0%, transparent 60%),
                radial-gradient(circle at 80% 80%, rgba(30, 41, 59, 0.5) 0%, transparent 50%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #ffffff;
            padding: 20px;
        }
        .card {
            background: #121621;
            border: 1px solid #1e2638;
            border-radius: 24px;
            width: 100%;
            max-width: 440px;
            padding: 40px 32px;
            text-align: center;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6), 0 0 30px rgba(16, 185, 129, 0.05);
            animation: fadeIn 0.4s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(12px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .icon-circle {
            width: 80px;
            height: 80px;
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px auto;
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.2);
        }
        .icon-circle svg {
            width: 42px;
            height: 42px;
            stroke: #10b981;
            stroke-width: 3;
            stroke-linecap: round;
            stroke-linejoin: round;
            fill: none;
        }
        h1 {
            font-size: 26px;
            font-weight: 700;
            color: #10b981;
            margin-bottom: 24px;
            letter-spacing: 0.5px;
        }
        .user-box {
            background: #181f2f;
            border: 1px solid #253046;
            border-radius: 16px;
            padding: 16px 20px;
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 24px;
            text-align: left;
        }
        .avatar {
            width: 54px;
            height: 54px;
            border-radius: 50%;
            object-fit: cover;
            border: 2px solid #10b981;
        }
        .user-info {
            overflow: hidden;
        }
        .display-name {
            font-size: 16px;
            font-weight: 600;
            color: #ffffff;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .handle {
            font-size: 13px;
            color: #94a3b8;
            margin-top: 2px;
        }
        .status-text {
            font-size: 15px;
            font-weight: 600;
            color: #10b981;
            margin-bottom: 24px;
        }
        .btn-discord {
            display: block;
            width: 100%;
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: #ffffff;
            font-size: 16px;
            font-weight: 600;
            padding: 16px;
            border-radius: 14px;
            text-decoration: none;
            border: none;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }
        .btn-discord:hover {
            background: linear-gradient(135deg, #34d399 0%, #10b981 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
        }
        .footer-note {
            font-size: 12px;
            color: #64748b;
            margin-top: 24px;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon-circle">
            <svg viewBox="0 0 24 24">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
        </div>
        <h1>ยืนยันตัวตนสำเร็จ</h1>
        <div class="user-box">
            <img class="avatar" src="{avatar_url}" alt="Avatar">
            <div class="user-info">
                <div class="display-name">{display_name}</div>
                <div class="handle">@{username}</div>
            </div>
        </div>
        <div class="status-text">ระบบเพิ่มคุณเข้าระบบเรียบร้อยแล้ว</div>
        <a href="discord://" class="btn-discord" onclick="openDiscord(event)">กลับไปที่ Discord</a>
        <div class="footer-note">ข้อมูลของคุณถูกบันทึกในฐานข้อมูลเรียบร้อย</div>
    </div>

    <script>
        function openDiscord(e) {
            e.preventDefault();
            window.location.href = "discord://";
            setTimeout(function() {
                window.location.href = "https://discord.com/channels/@me";
            }, 1000);
        }
    </script>
</body>
</html>
"""

ERROR_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>การยืนยันตัวตนไม่สำเร็จ</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Prompt:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Prompt', sans-serif; }
        body {
            background-color: #0b0d14;
            min-height: 100vh;
            display: flex; justify-content: center; align-items: center;
            color: #ffffff; padding: 20px;
        }
        .card {
            background: #121621; border: 1px solid #3b1d28; border-radius: 24px;
            width: 100%; max-width: 440px; padding: 40px 32px; text-align: center;
            box-shadow: 0 20px 50px rgba(0,0,0,0.6), 0 0 30px rgba(239, 68, 68, 0.1);
        }
        .icon-circle {
            width: 80px; height: 80px; background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 50%;
            display: flex; align-items: center; justify-content: center; margin: 0 auto 24px auto;
        }
        .icon-circle svg { width: 42px; height: 42px; stroke: #ef4444; stroke-width: 3; fill: none; }
        h1 { font-size: 24px; font-weight: 700; color: #ef4444; margin-bottom: 16px; }
        p { color: #94a3b8; font-size: 15px; margin-bottom: 24px; line-height: 1.6; }
        .btn-retry {
            display: block; width: 100%; background: #252e42; color: #ffffff;
            font-size: 15px; font-weight: 600; padding: 14px; border-radius: 12px;
            text-decoration: none; border: none; cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon-circle">
            <svg viewBox="0 0 24 24">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
        </div>
        <h1>การยืนยันตัวตนปฏิเสธ</h1>
        <p>{error_message}</p>
        <button class="btn-retry" onclick="window.close()">ปิดหน้านี้</button>
    </div>
</body>
</html>
"""

CAPTCHA_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ยืนยันสิทธิ์มนุษย์ (Captcha Verification)</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Prompt:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Prompt', sans-serif; }
        body {
            background-color: #0b0d14;
            min-height: 100vh; display: flex; justify-content: center; align-items: center;
            color: #ffffff; padding: 20px;
        }
        .card {
            background: #121621; border: 1px solid #1e2638; border-radius: 24px;
            width: 100%; max-width: 440px; padding: 40px 32px; text-align: center;
            box-shadow: 0 20px 50px rgba(0,0,0,0.6);
        }
        .icon-circle {
            width: 80px; height: 80px; background: rgba(59, 130, 246, 0.12);
            border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 50%;
            display: flex; align-items: center; justify-content: center; margin: 0 auto 24px auto;
        }
        .icon-circle svg { width: 42px; height: 42px; stroke: #3b82f6; stroke-width: 3; fill: none; }
        h1 { font-size: 24px; font-weight: 700; color: #3b82f6; margin-bottom: 16px; }
        p { color: #94a3b8; font-size: 15px; margin-bottom: 24px; }
        .captcha-box {
            background: #181f2f; border: 1px solid #253046; border-radius: 16px;
            padding: 20px; margin-bottom: 24px; text-align: center;
        }
        .math-question { font-size: 22px; font-weight: 700; color: #60a5fa; margin-bottom: 12px; }
        .captcha-input {
            width: 100%; background: #0f172a; border: 1px solid #334155; border-radius: 12px;
            padding: 14px; color: #ffffff; font-size: 18px; text-align: center; font-weight: 600;
        }
        .captcha-input:focus { border-color: #3b82f6; outline: none; }
        .btn-submit {
            display: block; width: 100%; background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: #ffffff; font-size: 16px; font-weight: 600; padding: 16px; border-radius: 14px;
            border: none; cursor: pointer; transition: all 0.2s ease;
        }
        .btn-submit:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4); }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon-circle">
            <svg viewBox="0 0 24 24">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
        </div>
        <h1>ยืนยันสิทธิ์มนุษย์ (Captcha)</h1>
        <p>กรุณาตอบคำถามคณิตศาสตร์สั้นๆ เพื่อยืนยันว่าคุณไม่ใช่ระบบอัตโนมัติ</p>
        <form method="GET" action="/verify">
            <input type="hidden" name="guild_id" value="{guild_id}">
            <input type="hidden" name="user_id" value="{user_id}">
            <input type="hidden" name="sig" value="{sig}">
            <input type="hidden" name="username" value="{username}">
            <input type="hidden" name="handle" value="{handle}">
            <input type="hidden" name="avatar" value="{avatar}">
            <input type="hidden" name="captcha_expected" value="{captcha_expected}">
            <div class="captcha-box">
                <div class="math-question">{num1} + {num2} = ?</div>
                <input type="number" name="captcha_ans" placeholder="พิมพ์ผลลัพธ์ที่นี่..." required class="captcha-input" autofocus>
            </div>
            <button type="submit" class="btn-submit">กดยืนยันตัวตน ➔</button>
        </form>
    </div>
</body>
</html>
"""

class WebVerifyCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.site = None
        self.runner = None

    async def handle_root(self, request):
        """เส้นทางสำหรับ Render Health Check (ต้องตอบ 200 เพื่อให้ Deploy ผ่าน 100%)"""
        return web.Response(text="OK - Enterprise Security Bot is Active 24/7", status=200)

    async def handle_health(self, request):
        """เส้นทางสำหรับ UptimeRobot ตรวจสุขภาพบอท"""
        status_text = "Gateway Connected" if (self.bot.is_ready() and not self.bot.is_closed()) else "Gateway Connecting"
        return web.Response(text=f"OK - Enterprise Security Bot ({status_text})", status=200)

    async def cog_load(self):
        app = web.Application()
        app.router.add_get('/', self.handle_root)
        app.router.add_get('/health', self.handle_health)
        app.router.add_get('/verify', self.handle_verify)
        app.router.add_get('/success.html', self.handle_verify)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '0.0.0.0', PORT)
        try:
            await self.site.start()
            print(f"🌐 Web Verification Server is live on http://0.0.0.0:{PORT}")
        except Exception as e:
            print(f"⚠️ Web Verify Server Error: {e}")

    async def cog_unload(self):
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

    async def handle_verify(self, request):
        guild_id_str = request.query.get("guild_id")
        user_id_str = request.query.get("user_id")
        sig = request.query.get("sig")
        username_query = request.query.get("username") or ""
        handle_query = request.query.get("handle") or ""
        avatar_query = request.query.get("avatar") or ""
        
        captcha_ans = request.query.get("captcha_ans")
        captcha_expected = request.query.get("captcha_expected")

        if not guild_id_str or not user_id_str:
            error_html = ERROR_HTML_TEMPLATE.replace("{error_message}", "ลิงก์ไม่ถูกต้อง หรือพารามิเตอร์ไม่ครบถ้วน")
            return web.Response(text=error_html, content_type='text/html')

        try:
            guild_id = int(guild_id_str)
            user_id = int(user_id_str)
        except ValueError:
            error_html = ERROR_HTML_TEMPLATE.replace("{error_message}", "ID ข้อมูลไม่ถูกต้อง")
            return web.Response(text=error_html, content_type='text/html')

        if sig and not verify_signature(guild_id, user_id, sig):
            error_html = ERROR_HTML_TEMPLATE.replace("{error_message}", "ลายเซ็นความปลอดภัย (Signature) ไม่ถูกต้อง หรือลิงก์หมดอายุ")
            return web.Response(text=error_html, content_type='text/html')

        # 🧩 Math Captcha Validation
        if captcha_ans is None or captcha_expected is None:
            num1 = random.randint(1, 9)
            num2 = random.randint(1, 9)
            expected_sum = num1 + num2
            captcha_sig = hmac.new(SECRET_KEY.encode(), f"{guild_id}:{user_id}:{expected_sum}".encode(), hashlib.sha256).hexdigest()
            
            captcha_html = (
                CAPTCHA_HTML_TEMPLATE
                .replace("{guild_id}", str(guild_id))
                .replace("{user_id}", str(user_id))
                .replace("{sig}", sig or "")
                .replace("{username}", username_query)
                .replace("{handle}", handle_query)
                .replace("{avatar}", avatar_query)
                .replace("{captcha_expected}", f"{expected_sum}:{captcha_sig}")
                .replace("{num1}", str(num1))
                .replace("{num2}", str(num2))
            )
            return web.Response(text=captcha_html, content_type='text/html')
        else:
            try:
                exp_sum_str, exp_sig = captcha_expected.split(":")
                expected_sig = hmac.new(SECRET_KEY.encode(), f"{guild_id}:{user_id}:{exp_sum_str}".encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(exp_sig, expected_sig) or int(captcha_ans) != int(exp_sum_str):
                    error_html = ERROR_HTML_TEMPLATE.replace("{error_message}", "❌ คำตอบ Captcha ไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง")
                    return web.Response(text=error_html, content_type='text/html')
            except Exception:
                error_html = ERROR_HTML_TEMPLATE.replace("{error_message}", "❌ ข้อมูล Captcha ไม่ถูกต้อง")
                return web.Response(text=error_html, content_type='text/html')

        # Get Client IP
        client_ip = request.headers.get('X-Forwarded-For', request.remote or '127.0.0.1').split(',')[0].strip()
        user_agent = request.headers.get('User-Agent', 'Unknown')

        conf = get_config(guild_id)

        # 🌐 Anti-VPN & Proxy Check
        if conf.get("anti_vpn"):
            if await is_vpn_or_proxy(client_ip):
                error_html = ERROR_HTML_TEMPLATE.replace("{error_message}", "🚨 **Anti-VPN Security Guard:** ตรวจพบการใช้งาน VPN/Proxy หรือ Datacenter IP กรุณาปิด VPN แล้วลองใหม่อีกครั้ง")
                return web.Response(text=error_html, content_type='text/html')

        # 🛡️ IP Ban Check
        if conf.get("ip_ban_guard"):
            if check_user_ip_banned(guild_id, user_id, client_ip):
                error_html = ERROR_HTML_TEMPLATE.replace("{error_message}", "🚨 ตรวจพบ IP Address นี้เคยลงทะเบียนกับบัญชีที่ถูกแบน ไม่สามารถยืนยันตัวตนได้")
                return web.Response(text=error_html, content_type='text/html')

        # Record IP Log
        add_ip_log(guild_id, user_id, client_ip, user_agent)

        # Discord Role Granting
        display_name = username_query or "Discord User"
        handle_name = handle_query or f"user_{user_id}"
        avatar_url = avatar_query or "https://cdn.discordapp.com/embed/avatars/0.png"

        guild = self.bot.get_guild(guild_id)
        if guild:
            member = guild.get_member(user_id)
            if not member:
                try:
                    member = await guild.fetch_member(user_id)
                except:
                    member = None

            if member:
                display_name = member.display_name
                handle_name = member.name
                avatar_url = member.display_avatar.url

                # Give Verified Role if configured
                verify_role_id = conf.get("verify_role_id")
                if verify_role_id:
                    v_role = guild.get_role(verify_role_id)
                    if v_role and v_role not in member.roles:
                        try:
                            await member.add_roles(v_role, reason="[Web Verify] ยืนยันตัวตนผ่านเว็บสำเร็จ")
                        except Exception as e:
                            print(f"Failed to add verify role: {e}")

                await send_audit_log(
                    guild,
                    "🔐 ยืนยันตัวตนสำเร็จ (Web IP & Anti-VPN Guard)",
                    f"ผู้ใช้: {member.mention} (`{member.id}`)\nIP Address: `{client_ip}`\nUser-Agent: `{user_agent}`",
                    discord.Color.green()
                )

        html_content = (
            SUCCESS_HTML_TEMPLATE
            .replace("{avatar_url}", avatar_url)
            .replace("{display_name}", display_name)
            .replace("{username}", handle_name)
        )
        return web.Response(text=html_content, content_type='text/html')

async def setup(bot):
    await bot.add_cog(WebVerifyCog(bot))
