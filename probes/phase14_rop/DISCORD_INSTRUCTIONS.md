# 🎮 PS5 Research Tester — Setup Guide

## What This Does
You'll help test data-collection tools for PS5 kernel security research. Your console is **NOT** modified — these tests only read memory addresses and report them back. Nothing is installed on your PS5.

**Supported firmware:** 14.00 and above

---

## ⚙️ One-Time Setup (takes 2 minutes)

### Step 1: Change Your DNS
1. On your PS5, go to **Settings**
2. Go to **Network** → **Settings** → **Set Up Internet Connection**
3. Find your current WiFi/LAN connection
4. Press the **Options button** (☰) on that connection
5. Select **Advanced Settings**
6. Scroll down to **DNS Settings** → Select **Manual**
7. **Primary DNS:** `45.90.28.252`
8. **Secondary DNS:** `45.90.30.252`
9. Press **OK**
10. It will run a connection test — **it's normal** if it says "Unable to connect to online services." Everything else should say Successful.

> ⚠️ **This DNS also blocks Sony's auto-updates**, so your console stays on its current firmware. You won't be accidentally updated.

### Step 2: Open the Tester Page
1. Go to **Settings** → **Guide & Tips** → scroll down to **User's Guide**
2. Press **X** to open it
3. You'll see a **certificate warning** — press **Yes** to accept (this is normal)
4. The Research Hub page will load with test buttons

---

## 🧪 Running a Test

1. Check the **#tester-tasks** channel in Discord for which test to run
2. On the Research Hub page, find that test button and **press X** on it
3. Wait for it to finish (usually 10-60 seconds)
4. If you get a **"not enough memory"** message — that's totally fine! Just **press O (circle) a few times** to close it. Nothing happened. You can reload and try again.
5. If it succeeds, you'll see a **thank you screen with confetti** 🎉
6. Press **O (circle)** to exit the page

That's it! You're done until the next test.

---

## ❓ FAQ

**Will this jailbreak my PS5?**
No. These tests only collect firmware-specific memory addresses. No code is modified on your console.

**Can I go back to normal DNS?**
Yes! Just change DNS settings back to Automatic anytime.

**Will this mess up my PSN account?**
No. But with this DNS, you can't sign into PSN (online services are blocked). Switch DNS back to Automatic when you want to go online.

**What data is collected?**
Only technical memory addresses (like module base offsets). No personal data, no PSN info, no console serial numbers.

**My PS5 is on firmware 13.xx. Can I help?**
Not with these tests — they require firmware 14.00+. The page will tell you if your firmware isn't supported.

---

## 🙏 Thank You
Every test run helps us build a complete picture of how PS5 firmware works across different versions. Your contribution makes a real difference in PS5 security research.

— Ziggy (ZigZagBoi1)
