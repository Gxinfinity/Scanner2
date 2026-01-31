import os
import time
import asyncio
import requests
import socket
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from fpdf import FPDF
from concurrent.futures import ThreadPoolExecutor

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes,
)

# ================= CONFIG =================
BOT_TOKEN = ""
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
MAX_PAGES = 30
PROGRESS_STEP = 5 
COMMON_PORTS = [21, 22, 80, 443, 3306, 8080]

def create_session():
    """Fix: Session per-scan for thread-safety"""
    s = requests.Session()
    s.headers.update(HEADERS)
    return s

async def resolve_dns_smart(domain, loop):
    """Fix: Robust DNS resolve with IPv4 preference for port scans"""
    try:
        addr_info = await loop.run_in_executor(None, socket.getaddrinfo, domain, None)
        # Prefer IPv4 (AF_INET) for better socket compatibility
        for fam, _, _, _, sockaddr in addr_info:
            if fam == socket.AF_INET:
                return sockaddr[0]
        return addr_info[0][4][0] 
    except:
        return None
# =========================================

# ============== UTILS & TOOLS ==============
def pdf_safe(text, max_len=80):
    if not isinstance(text, str): text = str(text)
    return text[:max_len].encode("latin-1", "ignore").decode("latin-1")

def find_subdomains(domain, session):
    subs = set()
    try:
        r = session.get(f"https://crt.sh/?q={domain}&output=json", timeout=15)
        if r.status_code == 200:
            try:
                data = r.json() # ValueError handle
                for entry in data:
                    name = entry['name_value']
                    for n in name.split("\n"):
                        n = n.strip()
                        # Filter wildcards
                        if "*" not in n and n.endswith(domain):
                            subs.add(n)
            except ValueError: return [] 
    except: pass
    return sorted(list(subs))

def scan_ports_fast(host_ip):
    # Cloudflare detection
    CF_RANGES = ("104.16.", "104.17.", "104.18.", "104.19.", "172.64.", "172.67.")
    if host_ip.startswith(CF_RANGES): return "CF_DETECTED"

    open_ports = []
    def check_port(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2) # Balanced timeout
                if s.connect_ex((host_ip, p)) == 0: return p
        except: return None

    with ThreadPoolExecutor(max_workers=5) as executor: 
        results = executor.map(check_port, COMMON_PORTS)
        open_ports = [p for p in results if p is not None]
    return open_ports

def indicator_scan(html):
    findings = []
    low_html = html.lower()
    if any(p in low_html for p in ["sql syntax", "mysql_fetch", "sqlite3"]):
        findings.append("Potential SQLi Error")
    # Low noise XSS detection
    if "onerror=" in low_html and "<img" in low_html:
        findings.append("Potential XSS Indicator")
    return findings

# ============== CORE LOGIC ==============
async def run_full_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get("scanning"): # Scan Lock
        await context.bot.send_message(chat_id=update.effective_chat.id, text="⏳ Scan already running!")
        return
    
    start_time = time.time()
    context.user_data["scanning"] = True
    target = context.user_data["target"]
    domain = urlparse(target).netloc
    msg = await context.bot.send_message(chat_id=update.effective_chat.id, text="🚀 Recon Starting...")
    
    session = create_session()
    loop = asyncio.get_running_loop() 

    try:
        # IP Resolution
        ip = await resolve_dns_smart(domain, loop)
        if not ip:
            await msg.edit_text("❌ DNS Resolve failed. Target might be offline.")
            return

        await msg.edit_text("🌐 Harvesting Subdomains...")
        subdomains = await loop.run_in_executor(None, find_subdomains, domain, session)

        await msg.edit_text("🔌 Scanning Ports...")
        ports_result = await loop.run_in_executor(None, scan_ports_fast, ip)
        
        # Proper Robots.txt check
        robots_url = urljoin(target, "/robots.txt")
        try:
            robots_res = await loop.run_in_executor(None, lambda: session.get(robots_url, timeout=5))
            has_robots = robots_res.status_code == 200
        except: has_robots = False

        await msg.edit_text("🔍 Analyzing Web Structure...")
        visited, results, queue = set(), [], [target]
        
        while queue and len(visited) < MAX_PAGES:
            # Absolute queue safety
            if len(queue) > 200: break 
            
            url = queue.pop(0)
            if url.count("/") > target.count("/") + 5: continue # Depth safety
            
            base_url = url.split("?")[0].rstrip("/") 
            if base_url in visited or urlparse(url).netloc != domain: continue
            visited.add(base_url)

            try:
                r = await loop.run_in_executor(None, lambda: session.get(url, timeout=8))
                vulns = indicator_scan(r.text)
                
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    clean_link = urljoin(url, a["href"]).split("#")[0]
                    if clean_link not in visited and clean_link not in queue:
                        if urlparse(clean_link).netloc == domain:
                            queue.append(clean_link)
                
                results.append({"url": url, "status": r.status_code, "vulns": vulns})
            except: continue

            # Flood protection
            if len(visited) % PROGRESS_STEP == 0:
                await msg.edit_text(f"🔍 Analyzed {len(visited)} pages...")

        duration = round(time.time() - start_time, 2)
        context.user_data["scan_data"] = {
            "results": results, "subdomains": subdomains, 
            "ports": ports_result, "time": duration, "robots": has_robots
        }
        context.user_data["ready"] = True
        
        port_msg = "Cloudflare (Skip)" if ports_result == "CF_DETECTED" else f"{len(ports_result)} Open"
        # Summary with robots.txt status
        summary = (f"✅ **Elite Scan Complete!**\nTime: {duration}s\n"
                   f"Subs: {len(subdomains)} | Robots.txt: {'✅' if has_robots else '❌'}\n"
                   f"Ports: {port_msg}")
        await msg.edit_text(summary)
    
    finally:
        context.user_data["scanning"] = False

# ============== PDF & EXPORT ==============
def make_elite_pdf(data, user_id):
    filename = f"report_{user_id}_{int(time.time())}.pdf" # Collision avoided
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16) # Linux portability
    pdf.cell(0, 10, "Elite Recon Audit Report", ln=True, align='C')
    pdf.ln(5)

    pdf.set_font("Helvetica", size=10)
    pdf.cell(0, 10, f"Duration: {data['time']}s | Robots.txt: {'Accessible' if data['robots'] else 'No'}", ln=True)
    pdf.ln(5)

    if not data['results']: # Empty UX handled
        pdf.multi_cell(0, 5, "No results found.")
    else:
        for r in data['results']:
            v_text = ", ".join(r['vulns']) if r['vulns'] else "Clean"
            pdf.multi_cell(0, 5, f"URL: {pdf_safe(r['url'])}\nStatus: {r['status']} | {v_text}\n" + "-"*40)
    
    pdf.output(filename)
    return filename

# ============== HANDLERS ==============
async def buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if q.data == "scan":
        if "target" not in context.user_data:
            await q.message.reply_text("❌ Use /target first!")
            return
        asyncio.create_task(run_full_scan(update, context))
    elif q.data == "pdf":
        if not context.user_data.get("ready"):
            await q.message.reply_text("❌ No scan data available.")
            return
        fname = await asyncio.get_running_loop().run_in_executor(None, make_elite_pdf, context.user_data["scan_data"], update.effective_user.id)
        with open(fname, "rb") as doc:
            await q.message.reply_document(doc, caption="🛡 Recon Finished.")
        os.remove(fname)

async def set_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /target example.com")
        return
    
    # Auto-HTTPS Fix
    raw_url = context.args[0].rstrip("/")
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    
    domain = urlparse(raw_url).netloc
    # Security: Block Private IPs
    if not domain or domain in ["localhost", "127.0.0.1"] or domain.startswith("192.168"):
        await update.message.reply_text("❌ Invalid or Private target.")
        return

    context.user_data.clear()
    context.user_data["target"] = raw_url
    await update.message.reply_text(f"🎯 Target Locked: {raw_url}")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    kb = [[InlineKeyboardButton("🚀 Start Scan", callback_data="scan")],
          [InlineKeyboardButton("📄 Get PDF", callback_data="pdf")]]
    await update.message.reply_text("🔥 **Elite Recon Bot v14**\nIPv6 preference, absolute safety, and bug-free logic.", reply_markup=InlineKeyboardMarkup(kb))

app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("target", set_target))
app.add_handler(CallbackQueryHandler(buttons))
app.run_polling()
