# 🤖 AI CONTEXT & MASTER BRIEFING: DISCORD ENTERPRISE SECURITY BOT

> **คำแนะนำสำหรับผู้ใช้ (How to use with any AI):**
> หากคุณเปลี่ยนไปใช้ AI ตัวอื่น (เช่น Claude, ChatGPT, Gemini, Cursor, Copilot ฯลฯ) ให้คัดลอกข้อความด้านล่างนี้ไปสั่ง AI ตัวใหม่ได้ทันที:
> 
> ```text
> คุณคือ AI ผู้ช่วยเขียนโปรแกรม กรุณาอ่านไฟล์ AI_INSTRUCTIONS.md, PROJECT_SUMMARY_AND_TODO.txt และ README.md ในโปรเจกต์นี้ทั้งหมด เพื่อทำความเข้าใจสถาปัตยกรรมระบบ, โครงสร้างโค้ด, Database Schema และระบบความปลอดภัยทั้งหมดก่อนเริ่มงาน จากนั้นรายงานสถานะพร้อมรับคำสั่งต่อไป
> ```

---

## 📌 1. ข้อมูลพื้นฐานของโปรเจกต์ (Project Overview)
- **ชื่อโปรเจกต์:** Discord Enterprise Security Bot (Zero-Trust & Anti-Nuke Architecture)
- **ภาษา & Framework:** Python 3.10+ / `discord.py` >= 2.3.2
- **ฐานข้อมูล:** SQLite (`security_bot.db`)
- **เว็บเซิร์ฟเวอร์:** `aiohttp` ในตัวสำหรับ Web Verification / IP Blacklist Guard
- **เป้าหมายหลัก:** ป้องกันเซิร์ฟเวอร์ Discord ระดับสูงสุด (Enterprise Hardening, Zero False Positives, Zero-Trust Access Control, Heuristics-based Anti-Raid & Anti-Phishing)

---

## 📁 2. โครงสร้างไฟล์และหน้าที่ของแต่ละส่วน (File Structure)

```
d:\BOTBANG\SecurutyBot - Copy\SecurutyBot2\
│
├── main.py                        # ทางเข้าหลัก (Entry point), โหลด Cogs, Sync Slash Commands, Unbuffered stdout
├── requirements.txt               # Dependencies (discord.py, aiohttp, python-dotenv, pytesseract, Pillow)
├── security_bot.db                # ฐานข้อมูล SQLite ในเครื่อง
├── start.bat                      # สคริปต์รันบน Windows พร้อม Auto-restart
├── .env                           # เก็บ DISCORD_TOKEN, GEMINI_API_KEY, ฯลฯ
├── discloud.config / squarecloud  # คอนฟิกสำหรับการโฮสต์บนคลาวด์
├── AI_INSTRUCTIONS.md             # [ไฟล์นี้] คู่มือสรุปบริบทสำหรับ AI ทุกตัว
├── README.md                      # สรุปฟังก์ชันและคำสั่งการใช้งาน
├── PROJECT_SUMMARY_AND_TODO.txt   # ประวัติการพัฒนาและแผนงานในอนาคต
│
└── cogs/
    ├── database.py                # ระบบ DB Schema, Config CRUD, Audit Log, IP Ban, Security Stats
    ├── dashboard.py               # Discord UI (Buttons, Select Menus, Modals, Slash Commands, SOC Stats)
    ├── security_events.py         # Heuristics Engine, Event Listeners, Anti-Nuke, Raid Fingerprint, Phishing
    └── web_verify.py              # Web Server (aiohttp), HMAC Verification, IP/Proxy/VPN Logging
```

---

## 🗄️ 3. สถาปัตยกรรมฐานข้อมูล (Database Schema)

ไฟล์ `cogs/database.py` จัดการ SQLite ทั้งหมด โดยมีตารางหลักดังนี้:

1. **`guild_config`**: ตั้งค่าความปลอดภัยของแต่ละกิลด์
   - `guild_id` (PRIMARY KEY), `log_channel_id`, `verify_channel_id`, `verify_role_id`, `quarantine_role_id`, `honeypot_channel_id`, `min_account_age_days`, `owner_pin`, `verify_domain`, `language` ('th'/'en')
   - **Toggles (0/1):** `malware_filter`, `ai_filter`, `phishing_api`, `anti_dox`, `anti_nuke`, `anti_mention`, `strike_system`, `voice_anti_raid`, `auto_purge`, `enforce_permissions`, `ip_ban_guard`, `anti_vpn`, `global_panic`, `ghost_ping_guard`, `anti_invite`, `webhook_guard`, `suspect_scan`, `anti_bot_add`, `anti_mass_action`, `anti_server_hijack`, `auto_panic_escalation`, `anti_zalgo`, `anti_unban_guard`, `anti_impersonation`, `raid_fingerprint`, `dm_owner_alert`
2. **`whitelist`**: สมาชิกหรือยศที่ได้รับการยกเว้นจากการตรวจสอบ (`guild_id`, `target_id`, `target_name`)
3. **`warnings`**: บันทึกประวัติการเตือน (`guild_id`, `user_id`, `reason`, `timestamp`)
4. **`quarantine`**: บันทึกยศเดิมของผู้ใช้ก่อนถูกส่งเข้ากักกัน (`guild_id`, `user_id`, `original_roles`)
5. **`backups`**: บันทึก JSON โครงสร้างเซิร์ฟเวอร์แบบ Manual (`id`, `guild_id`, `timestamp`, `data`)
6. **`server_snapshots`**: Snapshot โครงสร้างเซิร์ฟเวอร์แบบ Periodic อัตโนมัติ (`guild_id`, `timestamp`, `data`)
7. **`ip_logs`**: บันทึก IP และ User-Agent จากระบบยืนยันตัวตนบนเว็บ (`guild_id`, `user_id`, `ip_address`, `user_agent`, `timestamp`)
8. **`banned_ips`**: รายการ IP ที่ถูกขึ้นบัญชีดำ (`guild_id`, `ip_address`, `reason`, `timestamp`)
9. **`security_stats`**: สถิติการตรวจจับและระงับภัยคุกคามสะสมแบบ Real-Time (`guild_id`, `event_type`, `count`, `last_triggered`)

---

## 🛡️ 4. สรุประบบความปลอดภัยทั้งหมด (Security Capabilities)

### 4.1 ระบบป้องกันการทำลายล้าง (Anti-Nuke & Privilege Protection)
- **Anti-Nuke Rate Limiter:** ติดตามการลบห้อง/ยศ (> 3 ครั้งใน 10 วิ) → สั่งกักกัน + ริบยศ + ลบยศแอดมินของผู้ก่อเหตุ
- **Anti-Permission Escalation:** ตรวจจับใน `on_guild_role_update` หากยศใดได้ Dangerous Perms (Admin, Manage Roles, Manage Channels, Ban, Kick, Manage Webhooks, Manage Guild) โดยไม่ได้รับอนุญาต → ดึงสิทธิ์กลับทันที + ริบยศคนแก้ + Alert
- **Anti-Mass Role Tampering:** ดักจับการแก้ไข/สร้างยศรัว ๆ (> 3 ครั้งใน 10 วิ) → ริบยศทันที
- **Anti-Channel Tampering:** ดักจับการแอบแก้ไขชื่อห้อง/Overwrites ใน `on_guild_channel_update` → กักกัน + ริบยศ
- **Anti-Emoji & Sticker Nuke:** ดักจับการลบ Emoji/Sticker รัว ๆ (> 3 รายการใน 10 วิ) → ริบยศ
- **Anti-Unban Bypass:** ดักจับการแอบกด Unban ใน `on_member_unban` → ดึงกลับมาแบนซ้ำทันที + ริบยศผู้กด Unban

### 4.2 ระบบดักจับการบุกรุก & สแปม (Anti-Raid & Anti-Bot)
- **Raid Fingerprinting:** วิเคราะห์ multi-factor (ชื่อคล้ายกันด้วย Levenshtein distance, ไร้ Avatar, บัญชีเกิดใหม่, เข้ารัว ๆ) → เตะ/แบนทันที
- **Anti-Bot Add:** เตะบอทแปลกหน้าที่ไม่มี Whitelist ทันทีที่เข้ากิลด์ + ริบยศคนที่เชิญบอทเข้ามา
- **Anti-Mass Kick / Timeout:** ดักจับผู้ดูแลที่ Abuse เตะหรือ Timeout สมาชิกเกินลิมิตใน 10 วิ → ริบยศทันที
- **Anti-Server Hijack:** ดักจับการเปลี่ยนชื่อเซิร์ฟเวอร์หรือรูปโปรไฟล์กิลด์โดยไม่ได้รับอนุญาต → เปลี่ยนกลับอัตโนมัติ + ริบยศ
- **Nickname Impersonation Guard:** ป้องกันการตั้งชื่อเป็น Admin, Staff, Mod, Owner หรือชื่อเซิร์ฟเวอร์ → รีเซ็ตชื่อกลับอัตโนมัติ

### 4.3 ระบบความปลอดภัยด้านเนื้อหา & ข้อความ (Anti-Phishing & Anti-Spam)
- **Typosquatting & Homoglyphs:** ตรวจจับลิงก์ลวงโลกขั้นสูง เช่น `disc0rd`, อักษร Cyrillic `а`/`о` หน้าตาเหมือนภาษาอังกฤษ, และ TLD เสี่ยงสูง (`.xyz`, `.top`, `.ru` ปนคีย์เวิร์ดดิสคอร์ด)
- **Instant Webhook Killer:** ลบ Webhook ทันทีที่ถูกสร้างโดยผู้ที่ไม่ใช่ Whitelist/Owner + สั่งแบนผู้สร้าง
- **Webhook Spam Exploit Guard:** ดักจับข้อความสแปมยิงดิสจาก Webhook → ลบทันที + ทำลาย Webhook + แบนคนสร้าง
- **Anti-Invite & OAuth2 Bot Link:** ดักลบลิงก์ `discord.gg` และลิงก์ดูดสิทธิ์ `discord.com/oauth2/authorize`
- **Anti-Zalgo & Crash Text:** ตรวจจับข้อความที่มีตัวอักษร Combining Marks หนาแน่นผิดปกติที่ทำให้ดิสค้าง
- **Honeypot Invisible Trap:** ห้องดักบอทล่องหน (`🛑-security-trap`) หากมีใครส่งข้อความ = บอทสแปม → แบนทันที + DM แจ้งเตือน Owner
- **Ghost Ping Guard:** ตรวจจับและประจานคนแท็กแล้วลบข้อความทิ้ง

### 4.4 ระบบควบคุมฉุกเฉิน & ยืนยันตัวตน (Emergency & Verification)
- **Global Panic Lockdown:** สั่งล็อกดาวน์ทุกห้องในคลิกเดียว (ปิดสิทธิ์พิมพ์/ส่งเสียงของทุกยศ) ปลดล็อกด้วย Owner PIN (2FA)
- **DM Emergency Alert to Owner:** ส่งข้อความตรงหา Server Owner ทันทีเมื่อเกิดภัยคุกคามระดับวิกฤต
- **Web IP Verification & Anti-VPN:** ยืนยันตัวตนผ่านเว็บเพจ มีระบบตรวจจับ IP และ Proxy/VPN พร้อมซิงก์แบน IP อัตโนมัติ
- **Server Snapshot & Backup:** สำรองโครงสร้างยศและห้องลงฐานข้อมูล สามารถดูข้อมูลและ Restore ได้

---

## 💻 5. ระบบ Dashboard & UI Architecture

ไฟล์ `cogs/dashboard.py` ควบคุมการทำงานของหน้าควบคุมทั้งหมดผ่าน Discord UI Components:

- **คำสั่งเปิด:** `/security` หรือ `bang!security` หรือ `bang!panel` (ต้องการสิทธิ์ `manage_messages`)
- **Main Dashboard View (`MainDashboardView`):**
  - แสดงผล **SOC Real-Time Stats** (`get_security_stats(guild_id)`) นับจำนวนภัยคุกคามที่ถูกสกัดกั้น
  - ปุ่ม `🛡️ ความปลอดภัยขั้นสูง` -> เปิด `SecurityMenuView`
  - ปุ่ม `🔐 ระบบ Verify & IP Guard` -> เปิด `VerifyMenuView`
  - ปุ่ม `⚖️ จัดการสมาชิก & กักกัน` -> เปิด `ModerationMenuView`
  - ปุ่ม `⚙️ ตั้งค่า & Honeypot` -> เปิด `SettingsMenuView`
  - ปุ่ม `💾 ระบบ Backup & Restore` -> เปิด `BackupMenuView`
  - ปุ่ม `🔰 ป้องกันขั้นสูง (2026)` -> เปิด `AdvancedSecurityView` (ควบคุม 9 ระบบความปลอดภัยใหม่)

---

## ⚠️ 6. กฎสำคัญสำหรับ AI ที่จะมาเขียนโค้ดต่อ (Core Rules for Next AI)

1. **Hierarchy Check เสมอ:** ก่อนจะ Timeout, Kick, Ban หรือริบยศ ต้องเรียก `check_role_hierarchy` เสมอ และตรวจสอบว่าเป้าหมายไม่ใช่ Owner ของเซิร์ฟเวอร์
2. **Whitelist & Bot Exception:** ผู้ใช้ที่มี `guild.owner_id == member.id` หรือมียศใน `get_whitelist(guild_id)` จะได้รับการยกเว้นจากการถูกลงโทษ
3. **Discord UI Limits:**
   - 1 View มี Component ได้ไม่เกิน 25 ชิ้น
   - 1 แถว (Row) มี Button ได้ไม่เกิน 5 ปุ่ม หรือ Select Menu ได้ 1 อัน
4. **ความแม่นยำของ Heuristics:** ห้ามทำให้เกิด False Positive กับการสนทนาของคนปกติ (เช่น การตรวจ Typosquatting ต้องเช็คคู่กับคำว่า nitro, gift, steam หรือ TLD ผิดปกติเท่านั้น)
5. **Windows Encoding Note:** ในสภาพแวดล้อม Windows ให้รันคำสั่งไพธอนด้วย `python -X utf8` หากต้องแสดงผลภาษาไทยในคอนโซล
6. **Preserve Documentation:** รักษาคอมเมนต์เดิมและสไตล์การเขียนโค้ดเพื่อความต่อเนื่องของโปรเจกต์
