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

bot.setup_hook = load_cogs

@bot.event
async def on_ready():
    print(f"✅ Ultimate Enterprise Security Bot is ONLINE as {bot.user}!")
    try:
        await bot.tree.sync()
        for guild in bot.guilds:
            bot.tree.copy_global_to(guild=guild)
            await bot.tree.sync(guild=guild)
        print(f"⚡ Slash Commands synced INSTANTLY across {len(bot.guilds)} guilds!")
    except Exception as e:
        print(f"⚠️ Slash Sync Warning: {e}")

@bot.tree.error
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

@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send(f"❌ {ctx.author.mention} **สิทธิ์ไม่เพียงพอ:** คุณต้องมีสิทธิ์ `Manage Messages` (จัดการข้อความ) ในการใช้งานคำสั่งนี้!", delete_after=10)
    elif isinstance(error, commands.CommandNotFound):
        pass
    else:
        await ctx.send(f"⚠️ เกิดข้อผิดพลาด: {error}", delete_after=10)

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
    async with bot:
        await bot.start(TOKEN, reconnect=True)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("🛑 ปิดการทำงานของบอทเรียบร้อยแล้ว")