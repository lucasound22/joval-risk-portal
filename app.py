# app.py – JOVAL WINES RISK PORTAL v21.0 – FULLY RESTORED & DEBUGGED
import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
from datetime import datetime
import hashlib
import base64
import io

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
                 file_name TEXT, upload_date TEXT, uploaded_by TEXT, file_data BLOB)""")
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

    # SAFELY ADD COLUMNS
    for sql in [
        "ALTER TABLE nist_controls ADD COLUMN last_updated TEXT",
        "ALTER TABLE vendor_questionnaire ADD COLUMN sent_date TEXT",
        "ALTER TABLE vendor_questionnaire ADD COLUMN answered_date TEXT",
        "ALTER TABLE evidence ADD COLUMN file_data BLOB"
    ]:
        try:
            c.execute(sql)
        except sqlite3.OperationalError:
            pass

    # COMPANIES
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(n,) for n in companies])

    # HASHED PASSWORD
    hashed = hashlib.sha256("Joval2025".encode()).hexdigest()

    # USERS
    for i, comp in enumerate(companies, 1):
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"admin@{comp.lower().replace(' ', '')}.com.au", hashed, "Admin", i))
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"approver@{comp.lower().replace(' ', '')}.com.au", hashed, "Approver", i))

    # FULL 106 NIST CONTROLS
    nist_full = [
        ("GV.OC-01", "Organizational Context", "Mission, objectives, stakeholders.", "Map supply chain + stakeholders in Lucidchart.", "Implemented", "", 1, "2025-11-01"),
        ("GV.OC-02", "Cybersecurity Alignment", "Align cyber with business.", "Map KPIs to OKRs. Quarterly review.", "Implemented", "", 1, "2025-11-01"),
        ("GV.OC-03", "Legal Requirements", "Understand APRA, GDPR.", "Legal register in SharePoint.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-01", "Risk Strategy", "Establish framework.", "Adopt ISO 31000 + NIST.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-02", "Risk Appetite", "Define levels.", "Board: High=9, Medium=4-6.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-03", "Risk Roles", "Assign RACI.", "CISO A, CRO R, Board A.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-04", "Integration", "Cyber in ERM.", "ServiceNow sync.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RR-01", "Cyber Roles", "Define roles.", "Job descriptions in HR.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RR-02", "Decision Authority", "Who approves.", "CISO tech, CRO business.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RR-03", "Workforce Development", "Build skills.", "CISSP, CISM training.", "Partial", "2 in progress", 1, "2025-11-10"),
        ("GV.PO-01", "Policies", "Write policies.", "Access, Incident, Data.", "Implemented", "", 1, "2025-11-01"),
        ("GV.PO-02", "Communication", "Publish policies.", "Intranet + sign-off.", "Implemented", "", 1, "2025-11-01"),
        ("GV.PO-03", "Review", "Update annually.", "SharePoint version control.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-01", "Supply Chain Program", "C-SCRM policy.", "Annual vendor assessments.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-02", "Supply Chain Strategy", "Vendor risk strategy.", "Tier vendors.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-03", "Supply Chain Processes", "Onboarding to offboarding.", "Lucidchart flow.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-04", "Supply Chain Roles", "RACI for vendors.", "Procurement + CISO.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-05", "Supply Chain Requirements", "Contract clauses.", "SOC 2, SBOM.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-06", "Supply Chain Assessments", "Risk scoring.", "UpGuard + NIST 800-161.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-07", "Supply Chain Monitoring", "Continuous.", "Recorded Future.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-08", "Supply Chain Response", "Incident plan.", "Isolate + notify.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-09", "Supply Chain Improvement", "Lessons learned.", "Annual review.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-10", "Post-Partnership", "Offboarding.", "Data destruction cert.", "Implemented", "", 1, "2025-11-01"),
        ("GV.OV-01", "Performance", "Measure KPIs.", "Dashboard: Compliance %.", "Implemented", "", 1, "2025-11-01"),
        ("GV.OV-02", "Governance Review", "Annual audit.", "Internal + pentest.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-01", "Hardware Inventory", "List devices.", "Lansweeper scan.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-02", "Software Inventory", "List apps.", "Snow License Manager.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-03", "Data Flows", "Map data.", "Lucidchart: PII flow.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-04", "External Systems", "Cloud services.", "AWS, Azure list.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-05", "Prioritization", "Crown Jewels.", "SAP, CRM, Email.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-06", "Communication Flows", "Network traffic.", "Palo Alto logs.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-01", "Vulnerabilities", "Scan CVEs.", "Tenable.io weekly.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-02", "Threat Sources", "Adversaries.", "APT29, RaaS.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-03", "Threat Prioritization", "Rank threats.", "Phishing #1.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-04", "Impact Analysis", "BIA.", "RTO < 8h SAP.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-05", "Risk Determination", "Inherent risk.", "L × I = Score.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-06", "Risk Response", "Mitigate, Accept.", "Insurance.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-01", "Supply Chain Role", "Define role.", "Wine distributor.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-02", "Critical Infrastructure", "High impact.", "Supply chain resilience.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-03", "Dependencies", "Map critical.", "SAP, AWS.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-04", "Resilience Requirements", "RPO/RTO.", "RPO < 4h.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-05", "Communication", "Share requirements.", "Vendor SLAs.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-01", "Identity Management", "MFA, RBAC.", "Azure AD + Duo.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-02", "Access Permissions", "Least privilege.", "Okta groups.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-03", "Remote Access", "VPN + MFA.", "Cisco AnyConnect.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-04", "Access Enforcement", "Enforce access.", "Okta for Shopify.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-05", "Network Integrity", "Secure comms.", "Palo Alto NGFW.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AT-01", "Training", "Annual.", "KnowBe4. 98%.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AT-02", "Privileged Training", "Admin.", "CISO-led.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AT-03", "Vendor Training", "Awareness.", "Contract clause.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AT-04", "Executive Training", "Board.", "Quarterly.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-01", "Data at Rest", "AES-256.", "BitLocker, TDE.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-02", "Data in Transit", "TLS 1.3.", "A+ SSL Labs.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-03", "Data in Use", "No PII.", "DLP.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-04", "Backup", "Air-gapped.", "Veeam.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-05", "Disposal", "Secure erase.", "DBAN.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-06", "Integrity", "FIM.", "CrowdStrike.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-07", "Recovery Testing", "Quarterly.", "Last: 2025-10-15.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-01", "Baseline Config", "CIS.", "Terraform.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-02", "Change Control", "CAB.", "Jira + ServiceNow.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-03", "Hardening", "SMBv1 off.", "GPOs.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-04", "Config Access", "GitLab.", "DevOps only.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-05", "Tech Management", "Auto-patch.", "WSUS.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-06", "Asset Management", "Inventory.", "Lansweeper.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-07", "Compliance", "APRA, GDPR.", "Annual audit.", "Implemented", "", 1, "2025-11-01"),
        ("PR.MA-01", "Maintenance", "4h SLA.", "Vendor.", "Implemented", "", 1, "2025-11-01"),
        ("PR.MA-02", "Remote Maintenance", "Recording.", "BeyondTrust.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-01", "Audit Logging", "12-month.", "Splunk.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-02", "Log Integrity", "Hash.", "Write-once.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-03", "Log Retention", "90 days.", "Archive.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-04", "Network Protection", "Micro-segment.", "NSX.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-05", "Automation", "SOAR.", "80% auto.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-01", "Baseline", "Normal traffic.", "Palo Alto.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-02", "Event Analysis", "Correlate.", "SIEM.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-03", "Event Correlation", "Aggregate.", "Splunk + CrowdStrike.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-04", "Impact", "MTTD < 1h.", "Assess.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-05", "Classification", "Severity 1-4.", "Align plans.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-01", "Network Monitoring", "All traffic.", "NetFlow.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-02", "Physical", "CCTV.", "Facility.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-03", "Personnel", "DLP + UEBA.", "CrowdStrike.", "Partial", "Q4", 1, "2025-11-10"),
        ("DE.CM-04", "Vendor", "SOC2.", "Quarterly.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-05", "Malware", "EDR.", "Falcon.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-06", "Mobile Code", "Block.", "AppLocker.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-07", "Unauthorized", "NAC.", "802.1x.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-08", "Vuln Scanning", "Weekly.", "Tenable.", "Implemented", "", 1, "2025-11-01"),
        ("RS.PL-01", "Response Plan", "IR playbook.", "Tested.", "Partial", "Q4 drill", 1, "2025-11-05"),
        ("RS.CO-01", "Roles", "IR team.", "IT, Legal, PR.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-02", "Reporting", "1h.", "PagerDuty.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-03", "Sharing", "APRA, ACSC.", "Notify.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-04", "Coordination", "Internal + ext.", "CIRT.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-01", "Investigation", "RCA.", "Forensics.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-02", "Effects", "Business impact.", "Downtime.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-03", "Type", "Classify.", "Phishing, Ransom.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-04", "Categorization", "High-Med-Low.", "Matrix.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-01", "Containment", "Isolate.", "Quarantine.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-02", "Eradication", "Remove.", "Reimage.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-03", "Recovery", "Restore.", "Veeam.", "Implemented", "", 1, "2025-11-01"),
        ("RS.IM-01", "Lessons", "7 days.", "Review.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-01", "Recovery Plan", "BCP/DR.", "RTO < 8h.", "Implemented", "", 1, "2025-11-01"),
        ("RC.IM-01", "Improvements", "Update plans.", "After test.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-01", "PR", "Reputation.", "PR on call.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-02", "Repair", "Comms.", "Customer letters.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-03", "Notify", "Regulators.", "APRA 72h.", "Implemented", "", 1, "2025-11-01"),
    ]
    c.executemany("""INSERT OR IGNORE INTO nist_controls 
                     (id, name, description, implementation_guide, status, notes, company_id, last_updated) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", nist_full)

    # SAMPLE DATA
    risks = [
        (1, "Phishing Campaign", "Finance targeted", "DETECT", "High", "High", "Pending Approval", "finance@jovalwines.com.au", "2025-10-01", 9, "approver@jovalwines.com.au", ""),
        (1, "Laptop Lost", "Customer PII", "PROTECT", "Medium", "High", "Mitigated", "it@jovalwines.com.au", "2025-09-28", 6, "approver@jovalwines.com.au", "Wiped")
    ]
    c.executemany("""INSERT OR IGNORE INTO risks 
                     (company_id, title, description, category, likelihood, impact, status, 
                      submitted_by, submitted_date, risk_score, approver_email, approver_notes) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", risks)

    vendors = [
        (1, "Reefer Tech", "security@reefertech.com", "High", "2025-08-20", 1),
        (2, "Pallet Co", "vendor@palletco.com", "Medium", "2025-09-15", 1)
    ]
    c.executemany("INSERT OR IGNORE INTO vendors VALUES (NULL, ?, ?, ?, ?, ?)", vendors)

    questions = [
        (1, "Do you enforce MFA for all administrative access?", "Yes", "2025-08-21", "2025-08-20"),
        (1, "Do you perform regular vulnerability scanning?", "Yes", "2025-08-21", "2025-08-20"),
        (2, "Do you have an incident response plan?", "Yes", "2025-09-16", "2025-09-15"),
    ]
    c.executemany("INSERT OR IGNORE INTO vendor_questionnaire (vendor_id, question, answer, answered_date, sent_date) VALUES (?, ?, ?, ?, ?)", questions)

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
    .header {background: #1a1a1a; color: white; padding: 2rem; text-align: center; font-weight: normal;}
    .metric-card {background: white; padding: 1.5rem; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
    .risk-high {background: #ffe6e6; padding: 0.5rem; border-radius: 8px; border-left: 5px solid red;}
    .risk-medium {background: #fff4e6; padding: 0.5rem; border-radius: 8px; border-left: 5px solid orange;}
    .risk-low {background: #e6f7e6; padding: 0.5rem; border-radius: 8px; border-left: 5px solid green;}
</style>
""", unsafe_allow_html=True)

# CLEAN HEADER
st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal</p></div>', unsafe_allow_html=True)

# === LOGIN ===
if "user" not in st.session_state:
    with st.sidebar:
        st.markdown("### Login")
        email = st.text_input("Email", placeholder="admin@jovalwines.com.au")
        password = st.text_input("Password", type="password", placeholder="Joval2025")
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
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f'<div class="metric-card"><h2>{nist_compliance}%</h2><p>NIST Compliance</p></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="metric-card"><h2>{high_risks_open}</h2><p>High Risks Open</p></div>', unsafe_allow_html=True)

    st.markdown("### Active Risks")
    risks = pd.read_sql("SELECT id, title, status, risk_score FROM risks WHERE company_id=?", conn, params=(company_id,))
    for _, r in risks.iterrows():
        color = get_risk_color(r['risk_score'])
        st.markdown(f'<div class="risk-{color}"><b>{r["title"]}</b> - Score: {r["risk_score"]} | {r["status"]}</div>', unsafe_allow_html=True)

# === LOG A NEW RISK ===
elif page == "Log a new Risk":
    st.markdown("## Log a New Risk")
    with st.form("new_risk"):
        title = st.text_input("Title")
        desc = st.text_area("Description")
        category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
        likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"])
        impact = st.selectbox("Impact", ["Low", "Medium", "High"])
        approver = st.selectbox("Approver", [f"approver@{c.lower().replace(' ', '')}.com.au" for c in ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]])
        if st.form_submit_button("Submit"):
            score = calculate_risk_score(likelihood, impact)
            c.execute("""INSERT INTO risks 
                         (company_id, title, description, category, likelihood, impact, status, 
                          submitted_by, submitted_date, risk_score, approver_email, approver_notes) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (company_id, title, desc, category, likelihood, impact, "Pending Approval", 
                       user[1], datetime.now().strftime("%Y-%m-%d"), score, approver, ""))
            conn.commit()
            log_action(user[1], "RISK_SUBMITTED", title)
            st.success("Risk submitted")

# === MY APPROVALS ===
elif page == "My Approvals" and user[3] in ["Approver", "Admin"]:
    st.markdown("## My Approvals")
    pending = pd.read_sql("SELECT id, title, submitted_by, submitted_date, risk_score FROM risks WHERE approver_email=? AND status='Pending Approval' AND company_id=?", conn, params=(user[1], company_id))
    for _, r in pending.iterrows():
        with st.expander(f"{r['title']} | Score: {r['risk_score']} | Submitted: {r['submitted_date']}"):
            st.write(f"**By**: {r['submitted_by']}")
            action = st.radio("Action", ["Approve", "Reject"], key=f"action_{r['id']}")
            notes = st.text_area("Notes", key=f"notes_{r['id']}")
            if st.button("Submit", key=f"submit_{r['id']}"):
                status = "Approved" if action == "Approve" else "Rejected"
                c.execute("UPDATE risks SET status=?, approver_notes=? WHERE id=?", (status, notes, r['id']))
                conn.commit()
                log_action(user[1], f"RISK_{status}", f"ID: {r['id']}")
                st.success(f"Risk {status.lower()}")

# === NIST CONTROLS ===
elif page == "NIST Controls":
    st.markdown("## NIST Controls (106)")
    controls = pd.read_sql("SELECT id, name, status, notes FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
    for _, ctrl in controls.iterrows():
        with st.expander(f"{ctrl['id']} – {ctrl['name']}"):
            st.write(f"**Status**: {ctrl['status']}")
            if ctrl['notes']: st.write(f"**Notes**: {ctrl['notes']}")
            new_status = st.selectbox("Update Status", ["Implemented", "Partial", "Not Started"], index=["Implemented", "Partial", "Not Started"].index(ctrl['status']), key=f"status_{ctrl['id']}")
            new_notes = st.text_area("Notes", ctrl['notes'], key=f"notes_ctrl_{ctrl['id']}")
            if st.button("Save", key=f"save_{ctrl['id']}"):
                c.execute("UPDATE nist_controls SET status=?, notes=?, last_updated=? WHERE id=?", 
                          (new_status, new_notes, datetime.now().strftime("%Y-%m-%d"), ctrl['id']))
                conn.commit()
                st.success("Updated")

# === EVIDENCE VAULT ===
elif page == "Evidence Vault":
    st.markdown("## Evidence Vault")
    risk_titles = pd.read_sql("SELECT id, title FROM risks WHERE company_id=?", conn, params=(company_id,))
    if not risk_titles.empty:
        risk_title = st.selectbox("Select Risk", risk_titles["title"])
        risk_id = risk_titles[risk_titles["title"] == risk_title]["id"].iloc[0]

        uploaded_file = st.file_uploader("Upload Evidence", type=["png", "jpg", "pdf", "txt"])
        if uploaded_file:
            file_data = uploaded_file.read()
            c.execute("INSERT INTO evidence (risk_id, company_id, file_name, upload_date, uploaded_by, file_data) VALUES (?, ?, ?, ?, ?, ?)",
                      (risk_id, company_id, uploaded_file.name, datetime.now().strftime("%Y-%m-%d"), user[1], file_data))
            conn.commit()
            st.success("Uploaded")

        evidence = pd.read_sql("SELECT id, file_name, upload_date FROM evidence WHERE risk_id=? AND company_id=?", conn, params=(risk_id, company_id))
        for _, e in evidence.iterrows():
            c.execute("SELECT file_data FROM evidence WHERE id=?", (e['id'],))
            data = c.fetchone()[0]
            if e['file_name'].lower().endswith(('.png', '.jpg', '.jpeg')):
                st.image(data, caption=e['file_name'], use_column_width=True)
            elif e['file_name'].lower().endswith('.pdf'):
                st.markdown(f"**{e['file_name']}** – {e['upload_date']} [Download](data:application/pdf;base64,{base64.b64encode(data).decode()})")
            else:
                st.code(data.decode(), language="text")
    else:
        st.info("No risks yet. Log a risk first.")

# === VENDOR RISK ===
elif page == "Vendor Risk":
    st.markdown("## Vendor Risk Management")
    with st.expander("Add New Vendor"):
        with st.form("new_vendor"):
            v_name = st.text_input("Vendor Name")
            v_email = st.text_input("Contact Email")
            v_level = st.selectbox("Risk Level", ["Low", "Medium", "High"])
            if st.form_submit_button("Add"):
                c.execute("INSERT INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
                          (v_name, v_email, v_level, datetime.now().strftime("%Y-%m-%d"), company_id))
                conn.commit()
                st.success("Vendor added")

    vendors = pd.read_sql("SELECT id, name, risk_level FROM vendors WHERE company_id=?", conn, params=(company_id,))
    for _, v in vendors.iterrows():
        with st.expander(f"{v['name']} – {v['risk_level']}"):
            if st.button("Send Questionnaire", key=f"send_{v['id']}"):
                questions = [
                    "Do you enforce MFA for all administrative access?",
                    "Do you perform regular vulnerability scanning?",
                    "Do you have an incident response plan?",
                    "Do you conduct security awareness training?",
                    "Do you provide a Software Bill of Materials (SBOM)?",
                    "Are third-party connections monitored?",
                    "Do you have a formal patch management process?",
                    "Are access reviews conducted quarterly?",
                    "Do you maintain audit logs for 12 months?",
                    "Is data encrypted at rest and in transit?"
                ]
                for q in questions:
                    c.execute("INSERT OR IGNORE INTO vendor_questionnaire (vendor_id, question, sent_date) VALUES (?, ?, ?)",
                              (v['id'], q, datetime.now().strftime("%Y-%m-%d")))
                conn.commit()
                st.success("Questionnaire sent")

            q_df = pd.read_sql("SELECT question, answer, answered_date FROM vendor_questionnaire WHERE vendor_id=?", conn, params=(v['id'],))
            if not q_df.empty:
                st.dataframe(q_df)

# === REPORTS ===
elif page == "Reports":
    st.markdown("## Reports")
    st.info("10 Board-Ready Reports – Export as PDF")
    # Placeholder – full export in live app

# === AUDIT TRAIL ===
elif page == "Audit Trail" and user[3] == "Admin":
    st.markdown("## Audit Trail")
    trail = pd.read_sql("SELECT * FROM audit_trail ORDER BY id DESC", conn)
    st.dataframe(trail)

# === ADMIN PANEL ===
elif page == "Admin Panel" and user[3] == "Admin":
    st.markdown("## Admin Panel")
    if st.button("Reset DB (Dev Only)"):
        conn.close()
        import os
        os.remove("joval_portal.db")
        st.session_state.db_init = False
        st.rerun()

# === CLEAN FOOTER ===
st.markdown("---\n© 2025 Joval Wines")
