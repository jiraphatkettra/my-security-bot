import os
import asyncio
import discord
from discord.ext import commands
from dotenv import load_dotenv

# ==========================================
# 1. โหลดค่า ENVIRONMENT & ตั้งค่า INTENTS
# ==========================================
load_dotenv()

intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True
intents.moderation = True
intents.bans = True

# ตั้งค่า heartbeat_timeout=120.0 และ max_messages=500 เพื่อป้องกัน Gateway Timeout
bot = commands.Bot(
    command_prefix="bang!",
    intents=intents,
    heartbeat_timeout=120.0,
    max_messages=500
)

async def load_cogs():
    await bot.load_extension("cogs.database")
    await bot.load_extension("cogs.web_verify")
    await bot.load_extension("cogs.dashboard")
    await bot.load_extension("cogs.security_events")
    try:
        synced = await bot.tree.sync()
        print(f"✅ Synced {len(synced)} Slash Commands with Discord!")
    except Exception as e:
        print(f"⚠️ Slash Command Sync Error: {e}")

bot.setup_hook = load_cogs

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

    print("🚀 Starting Enterprise Security Bot (High-Availability Gateway Defense)...")
    retry_delay = 5
    while True:
        try:
            async with bot:
                await bot.start(TOKEN, reconnect=True)
        except (discord.errors.GatewayNotFound, discord.errors.HTTPException, asyncio.TimeoutError, Exception) as e:
            print(f"⚠️ เกิดข้อผิดพลาดในการเชื่อมต่อ Gateway ({e}) - กำลังพยายาม Reconnect ใน {retry_delay} วินาที...")
            await asyncio.sleep(retry_delay)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("🛑 ปิดการทำงานของบอทเรียบร้อยแล้ว")