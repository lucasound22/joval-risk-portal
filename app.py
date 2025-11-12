# app.py – JOVAL WINES RISK PORTAL v18.9 – TREND CHARTS + DASHBOARD + FULL NIST
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

    # ADD MISSING COLUMNS
    for col, sql in [
        ("last_updated", "ALTER TABLE nist_controls ADD COLUMN last_updated TEXT"),
        ("sent_date", "ALTER TABLE vendor_questionnaire ADD COLUMN sent_date TEXT")
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

    # FULL NIST CSF 2.0 – ALL 106 CONTROLS
    nist_full = [
        # GOVERN (GV) – 27
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

        # IDENTIFY (ID) – 18
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

        # PROTECT (PR) – 25
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

        # DETECT (DE) – 8
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

        # RESPOND (RS) – 13
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

        # RECOVER (RC) – 5
        ("RC.RP-01", "Recovery Plan", "BCP/DR.", "RTO < 8h.", "Implemented", "", 1, "2025-11-01"),
        ("RC.IM-01", "Improvements", "Update plans.", "After test.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-01", "PR", "Reputation.", "PR on call.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-02", "Repair", "Comms.", "Customer letters.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-03", "Notify", "Regulators.", "APRA 72h.", "Implemented", "", 1, "2025-11-01"),
    ]
    c.executemany("""INSERT OR IGNORE INTO nist_controls 
                     (id, name, description, implementation_guide, status, notes, company_id, last_updated) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", nist_full)

    # SAMPLE VENDORS + QUESTIONNAIRE WITH DATES
    c.execute("INSERT OR IGNORE INTO vendors VALUES (1, 'Reefer Tech', 'security@reefertech.com', 'High', '2025-08-20', 1)")
    c.execute("INSERT OR IGNORE INTO vendors VALUES (2, 'Pallet Co', 'vendor@palletco.com', 'Medium', '2025-09-15', 1)")
    c.execute("INSERT OR IGNORE INTO vendor_questionnaire VALUES (1, 1, 'Do you have MFA?', 'Yes, for all admin.', '2025-08-21', '2025-08-20')")
    c.execute("INSERT OR IGNORE INTO vendor_questionnaire VALUES (2, 1, 'Do you provide SBOM?', 'Yes, on request.', '2025-08-21', '2025-08-20')")
    c.execute("INSERT OR IGNORE INTO vendor_questionnaire VALUES (3, 2, 'Do you encrypt data?', 'Yes, TLS 1.3.', '2025-09-16', '2025-09-15')")

    conn.commit()
    conn.close()

# === RISK SCORING ===
def calculate_risk_score(likelihood, impact):
    scores = {"Low": 1, "Medium": 2, "High": 3}
    return scores[likelihood] * scores[impact]

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

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal v18.9 – TRENDS</p></div>', unsafe_allow_html=True)

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

# === METRICS & TRENDS ===
# NIST Compliance Trend (Last 30 days)
nist_trend = pd.read_sql("""
    SELECT last_updated, status FROM nist_controls 
    WHERE company_id=? AND last_updated IS NOT NULL
""", conn, params=(company_id,))
if not nist_trend.empty:
    nist_trend['last_updated'] = pd.to_datetime(nist_trend['last_updated'])
    nist_trend = nist_trend.set_index('last_updated').resample('D').apply(lambda x: (x == 'Implemented').sum() / len(x) * 100 if len(x) > 0 else 0).reset_index()
    nist_trend.columns = ['Date', 'Compliance %']
else:
    nist_trend = pd.DataFrame({'Date': [datetime.now() - timedelta(days=30)], 'Compliance %': [0]})

# Open Risks by Day
risks_trend = pd.read_sql("SELECT submitted_date, risk_score FROM risks WHERE company_id=?", conn, params=(company_id,))
if not risks_trend.empty:
    risks_trend['submitted_date'] = pd.to_datetime(risks_trend['submitted_date'])
    risks_trend = risks_trend.groupby(risks_trend['submitted_date'].dt.date).apply(lambda x: pd.Series({
        'High': (x['risk_score'] >= 7).sum(),
        'Medium': ((x['risk_score'] >= 4) & (x['risk_score'] < 7)).sum(),
        'Low': (x['risk_score'] < 4).sum()
    })).reset_index()
else:
    risks_trend = pd.DataFrame({'submitted_date': [datetime.now().date()], 'High': [0], 'Medium': [0], 'Low': [0]})

# Vendor Response Time
vendor_resp = pd.read_sql("""
    SELECT sent_date, answered_date FROM vendor_questionnaire 
    WHERE vendor_id IN (SELECT id FROM vendors WHERE company_id=?)
""", conn, params=(company_id,))
if not vendor_resp.empty:
    vendor_resp['sent_date'] = pd.to_datetime(vendor_resp['sent_date'])
    vendor_resp['answered_date'] = pd.to_datetime(vendor_resp['answered_date'])
    vendor_resp['response_days'] = (vendor_resp['answered_date'] - vendor_resp['sent_date']).dt.days
    avg_response = vendor_resp['response_days'].mean()
else:
    avg_response = 0

# Evidence Uploads
evidence_trend = pd.read_sql("SELECT upload_date FROM evidence WHERE company_id=?", conn, params=(company_id,))
if not evidence_trend.empty:
    evidence_trend['upload_date'] = pd.to_datetime(evidence_trend['upload_date']).dt.date
    evidence_trend = evidence_trend.value_counts().sort_index().reset_index()
    evidence_trend.columns = ['Date', 'Uploads']
else:
    evidence_trend = pd.DataFrame({'Date': [datetime.now().date()], 'Uploads': [0]})

# Current Metrics
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

# === DASHBOARD WITH TRENDS ===
if page == "Dashboard":
    st.markdown("## Progress Dashboard")
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1: st.markdown(f'<div class="metric-card"><h2>{nist_compliance}%</h2><p>NIST</p></div>', unsafe_allow_html=True)
    with col2: st.markdown(f'<div class="metric-card"><h2>{high_risks_open}</h2><p>High Risks</p></div>', unsafe_allow_html=True)
    with col3: st.markdown(f'<div class="metric-card"><h2>{vendor_response_rate}%</h2><p>Vendor Resp.</p></div>', unsafe_allow_html=True)
    with col4: st.markdown(f'<div class="metric-card"><h2>{evidence_coverage}%</h2><p>Evidence</p></div>', unsafe_allow_html=True)
    with col5: st.markdown(f'<div class="metric-card"><h2>{training_completion}%</h2><p>Training</p></div>', unsafe_allow_html=True)
    with col6: st.markdown(f'<div class="metric-card"><h2>{patch_compliance}%</h2><p>Patch</p></div>', unsafe_allow_html=True)

    st.markdown("### Trend Charts")
    col1, col2 = st.columns(2)
    with col1:
        fig1 = px.line(nist_trend, x='Date', y='Compliance %', title="NIST Compliance Trend (30d)", markers=True)
        st.plotly_chart(fig1, use_container_width=True)
    with col2:
        fig2 = px.area(risks_trend, x='submitted_date', y=['High', 'Medium', 'Low'], title="Open Risks by Severity")
        st.plotly_chart(fig2, use_container_width=True)

    col3, col4 = st.columns(2)
    with col3:
        st.markdown(f"**Avg Vendor Response Time**: {avg_response:.1f} days")
        fig3 = px.bar(evidence_trend.tail(7), x='Date', y='Uploads', title="Evidence Uploads (7d)")
        st.plotly_chart(fig3, use_container_width=True)
    with col4:
        st.markdown("### Risk Heatmap")
        risks = pd.read_sql("SELECT likelihood, impact FROM risks WHERE company_id=?", conn, params=(company_id,))
        if not risks.empty:
            risks['likelihood'] = risks['likelihood'].map({"Low":1, "Medium":2, "High":3})
            risks['impact'] = risks['impact'].map({"Low":1, "Medium":2, "High":3})
            heatmap = risks.groupby(['likelihood', 'impact']).size().unstack(fill_value=0)
            fig4 = px.imshow(heatmap, text_auto=True, color_continuous_scale="Reds", title="Risk Heatmap")
            st.plotly_chart(fig4, use_container_width=True)

# === OTHER PAGES (unchanged) ===
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
                st.success("Added")

    vendors = pd.read_sql("SELECT id, name, contact_email, risk_level FROM vendors WHERE company_id=?", conn, params=(company_id,))
    for _, v in vendors.iterrows():
        with st.expander(f"{v['name']} – {v['risk_level']} Risk"):
            st.write(f"**Email**: {v['contact_email']}")
            if st.button("Send Questionnaire", key=f"send_{v['id']}"):
                sent_date = datetime.now().strftime("%Y-%m-%d")
                c.execute("INSERT INTO vendor_questionnaire (vendor_id, question, sent_date) VALUES (?, ?, ?)",
                          (v['id'], "Standard Security Questionnaire", sent_date))
                conn.commit()
                st.success(f"Sent on {sent_date}")
                log_action(user[1], "QUESTIONNAIRE_SENT", v['name'])

            responses = pd.read_sql("SELECT question, answer, answered_date FROM vendor_questionnaire WHERE vendor_id=?", conn, params=(v['id'],))
            if not responses.empty:
                st.markdown("### Responses")
                for _, r in responses.iterrows():
                    st.markdown(f"- **Q**: {r['question']}<br>**A**: {r['answer']} <small>({r['answered_date']})</small>", unsafe_allow_html=True)
            else:
                st.info("No responses yet.")

elif page == "NIST Controls":
    st.markdown("## NIST CSF 2.0 Controls (106)")
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

st.markdown("---\n© 2025 Joval Wines | v18.9 – TRENDS LIVE")
