import os
import sys
import functools
import asyncio
import discord
from discord.ext import commands
from dotenv import load_dotenv

# ป้องกัน UnicodeEncodeError และบังคับให้แสดง Log บน Render ทันที (Unbuffered Output)
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try: sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
    except: pass
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    try: sys.stderr.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
    except: pass

print = functools.partial(print, flush=True)

# ==========================================
# 1. โหลดค่า ENVIRONMENT & ตั้งค่า INTENTS
# ==========================================
load_dotenv()

def create_bot():
    intents = discord.Intents.default()
    intents.message_content = True
    intents.members = True
    intents.guilds = True
    intents.moderation = True
    intents.bans = True

    b = commands.Bot(
        command_prefix="bang!",
        intents=intents,
        heartbeat_timeout=120.0,
        max_messages=500
    )

    async def load_cogs():
        await b.load_extension("cogs.database")
        await b.load_extension("cogs.web_verify")
        await b.load_extension("cogs.dashboard")
        await b.load_extension("cogs.security_events")

    b.setup_hook = load_cogs

    @b.event
    async def on_ready():
        print(f"✅ Ultimate Enterprise Security Bot is ONLINE as {b.user}!")
        try:
            await b.tree.sync()
            for guild in b.guilds:
                b.tree.copy_global_to(guild=guild)
                await b.tree.sync(guild=guild)
            print(f"⚡ Slash Commands synced INSTANTLY across {len(b.guilds)} guilds!")
        except Exception as e:
            print(f"⚠️ Slash Sync Warning: {e}")

    @b.tree.error
    async def on_app_command_error(interaction: discord.Interaction, error: discord.app_commands.AppCommandError):
        if isinstance(error, discord.app_commands.MissingPermissions):
            msg = "❌ **สิทธิ์ไม่เพียงพอ:** คุณต้องมีสิทธิ์ `Manage Messages` (จัดการข้อความ) ในการใช้งานคำสั่งนี้!"
        elif isinstance(error, discord.app_commands.BotMissingPermissions):
            msg = f"❌ **บอทสิทธิ์ไม่พอ:** บอทต้องการสิทธิ์ `{', '.join(error.missing_permissions)}`"
        else:
            msg = f"⚠️ **เกิดข้อผิดพลาด:** {error}"

        try:
            if interaction.response.is_done():
                await interaction.followup.send(msg, ephemeral=True)
            else:
                await interaction.response.send_message(msg, ephemeral=True)
        except Exception:
            pass

    @b.event
    async def on_command_error(ctx: commands.Context, error: commands.CommandError):
        if isinstance(error, commands.MissingPermissions):
            await ctx.send(f"❌ {ctx.author.mention} **สิทธิ์ไม่เพียงพอ:** คุณต้องมีสิทธิ์ `Manage Messages` (จัดการข้อความ) ในการใช้งานคำสั่งนี้!", delete_after=10)
        elif isinstance(error, commands.CommandNotFound):
            pass
        else:
            await ctx.send(f"⚠️ เกิดข้อผิดพลาด: {error}", delete_after=10)

    return b

from cogs.web_verify import start_web_server, update_web_bot, PORT

TOKEN = os.getenv("DISCORD_TOKEN")
if not TOKEN and os.path.exists(".env"):
    try:
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("DISCORD_TOKEN="):
                    TOKEN = line.split("=", 1)[1].strip()
                    break
    except: pass

async def main():
    if not TOKEN:
        print("❌ ไม่พบ DISCORD_TOKEN ในระบบ กรุณาตรวจสอบ .env หรือ Environment Variable")
        return

    # 1. รัน Web Server ทันที เพื่อให้ Render Health Check ผ่าน 100% ภายใน 5 วินาทีแรก (แก้ปัญหา Deploy Timed Out)
    print("🌐 Initializing Web Service for Render Deployment...")
    try:
        await start_web_server(None, PORT)
    except Exception as e:
        print(f"⚠️ Web Server Startup Notice: {e}")

    # 2. เริ่มต้นเชื่อมต่อบอทพร้อมระบบ Smart Auto-Reconnect & 429 Rate Limit Handler
    print("🚀 Starting Enterprise Security Bot (High-Availability Gateway Defense)...")
    retry_delay = 30
    while True:
        b = create_bot()
        update_web_bot(b)
        try:
            async with b:
                await b.start(TOKEN, reconnect=True)
            break
        except discord.errors.HTTPException as e:
            if e.status == 429:
                print(f"🚨 [Discord 429 Rate Limit] IP บน Render โดน Discord บล็อกชั่วคราว (Shared IP Pool Exceeded)")
                print(f"💡 คำแนะนำในการแก้ปัญหา:")
                print(f"   1. บน Render: แนะนำเปลี่ยน Region ใน Render Settings (เช่น Oregon -> Frankfurt หรือ Singapore)")
                print(f"   2. หรือรันบน Discloud / Square Cloud (discloud.config มีพร้อมแล้ว ไม่ติดบล็อก 429 แน่นอน)")
                print(f"   3. หรือรันบนเครื่องตัวเองผ่าน start.bat (เปิดใช้งานได้ทันที 100%)")
                print(f"🌐 [Status] Render Web Server ยังคงทำงานปกติ (Health Check ตอบ 200 OK Deploy จะไม่ติด Timed Out)")
                print(f"⏳ กำลังรอ {retry_delay} วินาทีเพื่อลองเชื่อมต่อใหม่อีกครั้ง...")
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay + 30, 300)
            else:
                print(f"⚠️ Discord HTTP Error: {e} - กำลังลองใหม่ใน 15 วินาที...")
                await asyncio.sleep(15)
        except (discord.errors.GatewayNotFound, asyncio.TimeoutError) as e:
            print(f"⚠️ Gateway Disconnect: {e} - กำลังลองใหม่ใน 10 วินาที...")
            await asyncio.sleep(10)
        except Exception as e:
            print(f"⚠️ Bot Exception: {e} - กำลังลองใหม่ใน 15 วินาที...")
            await asyncio.sleep(15)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("🛑 ปิดการทำงานของบอทเรียบร้อยแล้ว")