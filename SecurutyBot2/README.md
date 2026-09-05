# 🛡️ Discord Enterprise Security Bot (2026 Zero-Trust Edition)

ระบบบอทรักษาความปลอดภัย Discord ระดับองค์กร ออกแบบด้วยสถาปัตยกรรม **Zero-Trust & Anti-Nuke** ป้องกันการยิงดิส, บอทบุก (Raid), การขโมยสิทธิ์ (Privilege Escalation), ลิงก์ฟิชชิ่งลวงโลก และแอดมินทุจริตแบบ 100%

---

## ⚡ คุณสมบัติเด่น (Key Features)

- 🔒 **Anti-Permission Escalation**: ดักจับการแอบมอบสิทธิ์ Admin หรือสิทธิ์อันตราย → ดึงสิทธิ์กลับทันที + ริบยศ
- ⚡ **Anti-Nuke Engine**: สกัดกั้นการไล่ลบห้อง, ลบยศ, ลบอิโมจิ, แก้ไขสิทธิ์ Overwrite รัว ๆ
- 🕵️ **Raid Fingerprinting**: วิเคราะห์ลายนิ้วมือการบุกของบอทแบบกลุ่ม (ชื่อคล้าย, ไร้ Avatar, สมัครใหม่)
- 🌐 **Enhanced Phishing & Typosquatting**: ตรวจจับโดเมนปลอมแปลง, อักษร Cyrillic Homoglyphs (`disc0rd`, `disсord`), TLD เสี่ยงสูง
- ⚓ **Instant Webhook Killer**: ทำลาย Webhook สแปมทันทีที่สร้าง พร้อมแบนคนสร้าง
- 🚨 **Global Panic & 2FA PIN**: สั่งล็อกดาวน์ทุกห้องในคลิกเดียว ปลดล็อกด้วย PIN ลับของ Owner
- 📨 **DM Emergency Alert**: ส่งข้อความแจ้งเตือนระดับวิกฤตตรงเข้า DM ของ Server Owner
- 📊 **SOC Real-Time Dashboard**: แผงควบคุมผ่าน Discord UI 100% พร้อมรายงานสถิติภัยคุกคามสด

---

## 🚀 การติดตั้งและเริ่มใช้งาน (Getting Started)

### 1. ติดตั้ง Dependencies
```bash
pip install -r requirements.txt
```

### 2. ตั้งค่าไฟล์ `.env`
สร้างหรือแก้ไขไฟล์ `.env`:
```env
DISCORD_TOKEN=your_bot_token_here
OWNER_ID=your_discord_user_id
PORT=3000
```

### 3. รันบอท
- **Windows**: ดับเบิ้ลคลิกไฟล์ `start.bat` หรือรันคำสั่ง:
```bash
python main.py
```

---

## 🎮 คำสั่งหลัก (Commands)

| คำสั่ง | สิทธิ์ที่ต้องการ | คำอธิบาย |
|---|---|---|
| `/security` หรือ `bang!security` | `Manage Messages` | เปิดหน้าต่างควบคุมความปลอดภัย (SOC Dashboard) |
| `/purge` หรือ `bang!purge <จำนวน>` | `Manage Messages` | สั่งล้างข้อความในห้องอย่างรวดเร็ว |

---

## 🤖 สำหรับ AI หรือผู้พัฒนาต่อยอด (For AI & Developers)
กรุณาอ่านรายละเอียดสถาปัตยกรรม, กฎการเขียนโค้ด, และโครงสร้างฐานข้อมูลฉบับเต็มได้ที่ไฟล์ [`AI_INSTRUCTIONS.md`](AI_INSTRUCTIONS.md)
