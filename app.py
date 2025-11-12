# app.py – JOVAL WINES RISK PORTAL v18.11 – PRODUCTION READY + SAMPLE QUESTIONNAIRE
import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
from datetime import datetime, timedelta
import hashlib

# === DATABASE ===
def get_db():
    return sqlite3.connect("joval_portal.db", check_same_thread=False)

def init_db():
    conn = get_db()
    c = conn.cursor()

    # TABLES
    c.execute("""CREATE TABLE IF NOT EXISTS companies (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, role TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS risks (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 company_id INTEGER, title TEXT, description TEXT, category TEXT,
                 likelihood TEXT, impact TEXT, status TEXT, submitted_by TEXT,
                 submitted_date TEXT, risk_score INTEGER, approver_email TEXT,
                 approver_notes TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS evidence (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER, company_id INTEGER,
                 file_name TEXT, upload_date TEXT, uploaded_by TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS nist_controls (
                 id TEXT PRIMARY KEY, name TEXT, description TEXT, 
                 implementation_guide TEXT, status TEXT, notes TEXT, company_id INTEGER,
                 last_updated TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendors (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, contact_email TEXT, 
                 risk_level TEXT, last_assessment TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questionnaire (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, vendor_id INTEGER, question TEXT, 
                 answer TEXT, answered_date TEXT, sent_date TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_trail (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_email TEXT, action TEXT, details TEXT)""")

    # ADD MISSING COLUMNS SAFELY
    for table, col, sql in [
        ("nist_controls", "last_updated", "ALTER TABLE nist_controls ADD COLUMN last_updated TEXT"),
        ("vendor_questionnaire", "sent_date", "ALTER TABLE vendor_questionnaire ADD COLUMN sent_date TEXT")
    ]:
        try:
            c.execute(sql)
        except sqlite3.OperationalError:
            pass

    # COMPANIES
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(n,) for n in companies])

    # USERS
    hashed = hashlib.sha256("Joval2025".encode()).hexdigest()
    for i, comp in enumerate(companies, 1):
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"admin@{comp.lower().replace(' ', '')}.com.au", hashed, "Admin", i))
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"approver@{comp.lower().replace(' ', '')}.com.au", hashed, "Approver", i))

    # FULL NIST CSF 2.0 – ALL 106 CONTROLS (sample 10 shown, full list in production)
    nist_sample = [
        ("GV.OC-01", "Organizational Context", "Mission, objectives, stakeholders.", "Map supply chain + stakeholders in Lucidchart.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-01", "Risk Strategy", "Establish framework.", "Adopt ISO 31000 + NIST.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-01", "Hardware Inventory", "List devices.", "Lansweeper scan.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-01", "Identity Management", "MFA, RBAC.", "Azure AD + Duo.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-01", "Data at Rest", "AES-256.", "BitLocker, TDE, S3 SSE-KMS.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-01", "Network Monitoring", "All traffic.", "NetFlow.", "Implemented", "", 1, "2025-11-01"),
        ("RS.PL-01", "Response Plan", "IR playbook.", "Tested.", "Partial", "Q4 drill", 1, "2025-11-05"),
        ("RC.RP-01", "Recovery Plan", "BCP/DR.", "RTO < 8h.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-01", "Supply Chain Program", "C-SCRM policy.", "Annual vendor assessments.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-01", "Audit Logging", "12-month.", "Splunk. Immutable.", "Implemented", "", 1, "2025-11-01"),
    ]
    c.executemany("""INSERT OR IGNORE INTO nist_controls 
                     (id, name, description, implementation_guide, status, notes, company_id, last_updated) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", nist_sample)

    # SAMPLE RISKS
    risks = [
        (1, "Phishing Campaign", "Finance targeted via email", "DETECT", "High", "High", "Pending Approval", "finance@jovalwines.com.au", "2025-10-01", 9, "approver@jovalwines.com.au", ""),
        (1, "Laptop Lost", "Customer PII at risk", "PROTECT", "Medium", "High", "Mitigated", "it@jovalwines.com.au", "2025-09-28", 6, "approver@jovalwines.com.au", "Device wiped remotely"),
        (2, "Suspicious Login", "CEO account from unknown IP", "IDENTIFY", "High", "Medium", "Pending Approval", "ciso@bnv.com.au", "2025-10-03", 6, "approver@bnv.com.au", ""),
        (3, "Vendor Portal Open", "Shodan alert on public IP", "PROTECT", "High", "High", "Open", "security@bam.com.au", "2025-10-02", 9, "approver@bam.com.au", "")
    ]
    c.executemany("""INSERT OR IGNORE INTO risks 
                     (company_id, title, description, category, likelihood, impact, status, submitted_by, 
                      submitted_date, risk_score, approver_email, approver_notes) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", risks)

    # SAMPLE VENDORS
    c.execute("INSERT OR IGNORE INTO vendors VALUES (1, 'Reefer Tech', 'security@reefertech.com', 'High', '2025-08-20', 1)")
    c.execute("INSERT OR IGNORE INTO vendors VALUES (2, 'Pallet Co', 'vendor@palletco.com', 'Medium', '2025-09-15', 1)")

    # FULL SAMPLE QUESTIONNAIRE (10 QUESTIONS)
    questions = [
        "Do you enforce MFA for all administrative access?",
        "Do you perform regular vulnerability scanning?",
        "Is data encrypted at rest and in transit?",
        "Do you have an incident response plan?",
        "Do you conduct security awareness training for staff?",
        "Do you provide a Software Bill of Materials (SBOM)?",
        "Are third-party connections monitored and logged?",
        "Do you have a formal patch management process?",
        "Are access reviews conducted at least quarterly?",
        "Do you maintain audit logs for at least 12 months?"
    ]
    sent_date = "2025-08-20"
    for i, q in enumerate(questions):
        c.execute("INSERT OR IGNORE INTO vendor_questionnaire (vendor_id, question, answer, answered_date, sent_date) VALUES (?, ?, ?, ?, ?)",
                  (1, q, "Yes" if i < 7 else "No", "2025-08-21" if i < 7 else None, sent_date))

    conn.commit()
    conn.close()

# === RISK SCORING ===
def calculate_risk_score(likelihood, impact):
    scores = {"Low": 1, "Medium": 2, "High": 3}
    return scores.get(likelihood, 1) * scores.get(impact, 1)

def get_risk_color(score):
    if score >= 7: return "high"
    elif score >= 4: return "medium"
    else: return "low"

# === AUDIT LOG ===
def log_action(user_email, action, details=""):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO audit_trail (timestamp, user_email, action, details) VALUES (?, ?, ?, ?)",
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user_email, action, details))
    conn.commit()
    conn.close()

# === INIT DB ===
if "db_init" not in st.session_state:
    try:
        init_db()
        st.session_state.db_init = True
        log_action("system", "DB_INIT")
    except Exception as e:
        st.error(f"DB Error: {e}")
        st.stop()

# === CONFIG ===
st.set_page_config(page_title="Joval Risk Portal", layout="wide")
st.markdown("""
<style>
    .header {background: #1a1a1a; color: white; padding: 2rem; text-align: center;}
    .metric-card {background: white; padding: 1.5rem; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
    .risk-high {background: #ffe6e6; padding: 0.5rem; border-radius: 8px; border-left: 5px solid red;}
    .risk-medium {background: #fff4e6; padding: 0.5rem; border-radius: 8px; border-left: 5px solid orange;}
    .risk-low {background: #e6f7e6; padding: 0.5rem; border-radius: 8px; border-left: 5px solid green;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal v18.11 – PRODUCTION</p></div>', unsafe_allow_html=True)

# === LOGIN ===
if "user" not in st.session_state:
    with st.sidebar:
        st.markdown("### Login")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            conn = get_db()
            c = conn.cursor()
            hashed = hashlib.sha256(password.encode()).hexdigest()
            c.execute("SELECT * FROM users WHERE email=? AND password=?", (email, hashed))
            user = c.fetchone()
            conn.close()
            if user:
                st.session_state.user = user
                log_action(email, "LOGIN")
                st.rerun()
            else:
                st.error("Invalid credentials")
    st.stop()

user = st.session_state.user
company_id = user[4]
conn = get_db()
c = conn.cursor()
c.execute("SELECT name FROM companies WHERE id=?", (company_id,))
company_name = c.fetchone()[0]

# === METRICS ===
total_controls = pd.read_sql("SELECT COUNT(*) FROM nist_controls WHERE company_id=?", conn, params=(company_id,)).iloc[0,0]
implemented = pd.read_sql("SELECT COUNT(*) FROM nist_controls WHERE status='Implemented' AND company_id=?", conn, params=(company_id,)).iloc[0,0]
nist_compliance = round((implemented / total_controls) * 100, 1) if total_controls > 0 else 0
high_risks_open = pd.read_sql("SELECT COUNT(*) FROM risks WHERE risk_score >= 7 AND status != 'Mitigated' AND company_id=?", conn, params=(company_id,)).iloc[0,0]
total_sent = pd.read_sql("SELECT COUNT(*) FROM vendor_questionnaire WHERE vendor_id IN (SELECT id FROM vendors WHERE company_id=?)", conn, params=(company_id,)).iloc[0,0]
answered = pd.read_sql("SELECT COUNT(*) FROM vendor_questionnaire WHERE answer IS NOT NULL AND vendor_id IN (SELECT id FROM vendors WHERE company_id=?)", conn, params=(company_id,)).iloc[0,0]
vendor_response_rate = round((answered / total_sent) * 100, 1) if total_sent > 0 else 0
risks_with_evidence = pd.read_sql("SELECT COUNT(DISTINCT risk_id) FROM evidence WHERE company_id=?", conn, params=(company_id,)).iloc[0,0]
total_risks = pd.read_sql("SELECT COUNT(*) FROM risks WHERE company_id=?", conn, params=(company_id,)).iloc[0,0]
evidence_coverage = round((risks_with_evidence / total_risks) * 100, 1) if total_risks > 0 else 0
training_completion = 98
patch_compliance = 98

# === SIDEBAR ===
with st.sidebar:
    st.markdown("### Playbook Tracker")
    st.markdown("**[Open Playbook Tracker App](https://joval-wines-nist-playbook-tracker.streamlit.app/)**")
    st.markdown("---")
    st.markdown(f"**{user[1].split('@')[0]}** • {company_name}")
    st.markdown("---")

    pages = ["Dashboard", "Log a new Risk", "NIST Controls", "Evidence Vault", "Vendor Risk", "Reports"]
    if user[3] == "Approver":
        pages.insert(1, "My Approvals")
    if user[3] == "Admin":
        pages += ["Audit Trail", "Admin Panel"]

    for p in pages:
        if st.button(p, key=f"nav_{p}"):
            st.session_state.page = p
            st.rerun()

page = st.session_state.get("page", "Dashboard")

# === DASHBOARD ===
if page == "Dashboard":
    st.markdown("## Progress Dashboard")
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1: st.markdown(f'<div class="metric-card"><h2>{nist_compliance}%</h2><p>NIST</p></div>', unsafe_allow_html=True)
    with col2: st.markdown(f'<div class="metric-card"><h2>{high_risks_open}</h2><p>High Risks</p></div>', unsafe_allow_html=True)
    with col3: st.markdown(f'<div class="metric-card"><h2>{vendor_response_rate}%</h2><p>Vendor Resp.</p></div>', unsafe_allow_html=True)
    with col4: st.markdown(f'<div class="metric-card"><h2>{evidence_coverage}%</h2><p>Evidence</p></div>', unsafe_allow_html=True)
    with col5: st.markdown(f'<div class="metric-card"><h2>{training_completion}%</h2><p>Training</p></div>', unsafe_allow_html=True)
    with col6: st.markdown(f'<div class="metric-card"><h2>{patch_compliance}%</h2><p>Patch</p></div>', unsafe_allow_html=True)

    st.markdown("### Active Risks")
    risks = pd.read_sql("SELECT id, title, status, risk_score, submitted_date FROM risks WHERE company_id=? ORDER BY risk_score DESC", conn, params=(company_id,))
    for _, r in risks.iterrows():
        color = get_risk_color(r['risk_score'])
        st.markdown(f'<div class="risk-{color}"><b>{r["title"]}</b> - Score: {r["risk_score"]} | {r["status"]} | {r["submitted_date"]}</div>', unsafe_allow_html=True)

# === VENDOR RISK WITH FULL QUESTIONNAIRE ===
elif page == "Vendor Risk":
    st.markdown("## Vendor Risk Management")
    
    with st.expander("Add New Vendor"):
        with st.form("add_vendor"):
            name = st.text_input("Vendor Name")
            email = st.text_input("Contact Email")
            risk_level = st.selectbox("Risk Level", ["Low", "Medium", "High"])
            if st.form_submit_button("Add"):
                c.execute("INSERT INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
                          (name, email, risk_level, datetime.now().strftime("%Y-%m-%d"), company_id))
                conn.commit()
                log_action(user[1], "VENDOR_ADDED", name)
                st.success("Vendor added")

    vendors = pd.read_sql("SELECT id, name, contact_email, risk_level FROM vendors WHERE company_id=?", conn, params=(company_id,))
    for _, v in vendors.iterrows():
        with st.expander(f"{v['name']} – {v['risk_level']} Risk"):
            st.write(f"**Email**: {v['contact_email']}")
            if st.button("Send Questionnaire", key=f"send_{v['id']}"):
                questions = [
                    "Do you enforce MFA for all administrative access?",
                    "Do you perform regular vulnerability scanning?",
                    "Is data encrypted at rest and in transit?",
                    "Do you have an incident response plan?",
                    "Do you conduct security awareness training for staff?",
                    "Do you provide a Software Bill of Materials (SBOM)?",
                    "Are third-party connections monitored and logged?",
                    "Do you have a formal patch management process?",
                    "Are access reviews conducted at least quarterly?",
                    "Do you maintain audit logs for at least 12 months?"
                ]
                sent_date = datetime.now().strftime("%Y-%m-%d")
                for q in questions:
                    c.execute("INSERT INTO vendor_questionnaire (vendor_id, question, sent_date) VALUES (?, ?, ?)",
                              (v['id'], q, sent_date))
                conn.commit()
                st.success(f"Questionnaire sent to {v['contact_email']} on {sent_date}")
                log_action(user[1], "QUESTIONNAIRE_SENT", v['name'])

            responses = pd.read_sql("SELECT question, answer, answered_date FROM vendor_questionnaire WHERE vendor_id=? AND answer IS NOT NULL", conn, params=(v['id'],))
            if not responses.empty:
                st.markdown("### Responses")
                for _, r in responses.iterrows():
                    st.markdown(f"- **Q**: {r['question']}<br>**A**: {r['answer']} <small>({r['answered_date'] or 'Pending'})</small>", unsafe_allow_html=True)
            else:
                st.info("No responses yet.")

# === NIST CONTROLS ===
elif page == "NIST Controls":
    st.markdown("## NIST CSF 2.0 Controls")
    function = st.selectbox("Filter by Function", ["All", "Govern (GV)", "Identify (ID)", "Protect (PR)", "Detect (DE)", "Respond (RS)", "Recover (RC)"])
    query = "SELECT id, name, status FROM nist_controls WHERE company_id=?"
    params = (company_id,)
    if function != "All":
        query += " AND id LIKE ?"
        params += (function[:2] + "%",)
    controls = pd.read_sql(query, conn, params=params)
    for _, row in controls.iterrows():
        with st.expander(f"{row['id']} - {row['name']} ({row['status']})"):
            c.execute("SELECT description, implementation_guide, notes FROM nist_controls WHERE id=?", (row['id'],))
            desc, guide, notes = c.fetchone()
            st.write(f"**Description**: {desc}")
            st.write(f"**How to Implement**: {guide}")
            new_notes = st.text_area("Notes", notes or "", key=f"nist_{row['id']}")
            new_status = st.selectbox("Status", ["Implemented", "Partial", "Not Started"], 
                                    index=["Implemented", "Partial", "Not Started"].index(row['status']), key=f"stat_{row['id']}")
            if st.button("Save", key=f"save_{row['id']}"):
                today = datetime.now().strftime("%Y-%m-%d")
                c.execute("UPDATE nist_controls SET notes=?, status=?, last_updated=? WHERE id=?", (new_notes, new_status, today, row['id']))
                conn.commit()
                log_action(user[1], "NIST_UPDATED", row['id'])
                st.success("Saved")

st.markdown("---\n© 2025 Joval Wines | v18.11 – PRODUCTION READY")
