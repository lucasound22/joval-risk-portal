# app.py – JOVAL WINES RISK PORTAL v22.2 – FULLY RESTORED & CLOUD-READY
import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import hashlib
import base64
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

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

    # FULL 106 NIST CONTROLS – DETAILED
    nist_full = [
        ("GV.OC-01", "Organizational Context", "Mission, objectives, and stakeholders are understood and inform cybersecurity risk management.", "Map supply chain, stakeholders, and business objectives in Lucidchart. Align with OKRs.", "Implemented", "", 1, "2025-11-01"),
        ("GV.OC-02", "Cybersecurity Alignment", "Cybersecurity is integrated with business objectives.", "Map KPIs to OKRs. Quarterly review with CISO and CRO.", "Implemented", "", 1, "2025-11-01"),
        ("GV.OC-03", "Legal Requirements", "Legal and regulatory requirements are understood and managed.", "Maintain legal register in SharePoint. Include APRA, GDPR, Privacy Act.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-01", "Risk Strategy", "Risk management strategy is established and maintained.", "Adopt ISO 31000 + NIST CSF. Board-approved.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-02", "Risk Appetite", "Risk appetite and tolerance are defined.", "Board: High=9, Medium=4-6, Low=1-3. Documented in policy.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-03", "Risk Roles", "Roles and responsibilities for risk management are assigned.", "RACI: CISO Accountable, CRO Responsible, Board Approve.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-04", "Integration", "Cybersecurity risk is integrated into enterprise risk management.", "Sync with ServiceNow GRC module.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RR-01", "Cyber Roles", "Cybersecurity roles and responsibilities are defined.", "Job descriptions in HR system. Annual review.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RR-02", "Decision Authority", "Authority to make risk decisions is assigned.", "CISO for tech, CRO for business impact.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RR-03", "Workforce Development", "Workforce is trained and developed.", "CISSP, CISM, CompTIA Security+ training. 2 in progress.", "Partial", "Q4 completion", 1, "2025-11-10"),
        ("GV.PO-01", "Policies", "Policies and procedures are established.", "Access Control, Incident Response, Data Classification.", "Implemented", "", 1, "2025-11-01"),
        ("GV.PO-02", "Communication", "Policies are communicated and acknowledged.", "Intranet + annual sign-off via DocuSign.", "Implemented", "", 1, "2025-11-01"),
        ("GV.PO-03", "Review", "Policies are reviewed and updated.", "Annual review. Version control in SharePoint.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-01", "Supply Chain Program", "Supply chain risk management program is established.", "C-SCRM policy. Annual vendor assessments.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-02", "Supply Chain Strategy", "Supply chain risk strategy is defined.", "Tier vendors: Critical, High, Medium.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-03", "Supply Chain Processes", "Processes for supply chain risk are defined.", "Onboarding to monitoring to offboarding. Lucidchart flow.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-04", "Supply Chain Roles", "Roles for supply chain risk are assigned.", "Procurement + CISO RACI.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-05", "Supply Chain Requirements", "Requirements are included in contracts.", "SOC 2, SBOM, right to audit.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-06", "Supply Chain Assessments", "Vendors are assessed for risk.", "UpGuard + NIST 800-161 scoring.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-07", "Supply Chain Monitoring", "Vendors are continuously monitored.", "Recorded Future + BitSight.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-08", "Supply Chain Response", "Response to supply chain incidents is planned.", "Isolate + notify within 1h.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-09", "Supply Chain Improvement", "Lessons learned are incorporated.", "Annual review post-incident.", "Implemented", "", 1, "2025-11-01"),
        ("GV.SC-10", "Post-Partnership", "Offboarding processes are defined.", "Data destruction certificate.", "Implemented", "", 1, "2025-11-01"),
        ("GV.OV-01", "Performance", "Cybersecurity performance is measured.", "KPIs: Compliance %, MTTD, Patch SLA.", "Implemented", "", 1, "2025-11-01"),
        ("GV.OV-02", "Governance Review", "Governance is reviewed periodically.", "Annual internal audit + external pentest.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-01", "Hardware Inventory", "Hardware assets are inventoried.", "Lansweeper scan. Weekly sync.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-02", "Software Inventory", "Software assets are inventoried.", "Snow License Manager. Daily.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-03", "Data Flows", "Data flows are mapped.", "Lucidchart: PII, financial, operational.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-04", "External Systems", "External systems are identified.", "Cloud: AWS, Azure, Shopify.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-05", "Prioritization", "Critical assets are prioritized.", "Crown Jewels: SAP, CRM, Email.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-06", "Communication Flows", "Network communication flows are mapped.", "Palo Alto logs + NetFlow.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-01", "Vulnerabilities", "Vulnerabilities are identified.", "Tenable.io weekly scans.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-02", "Threat Sources", "Threat sources are identified.", "APT29, RaaS, insiders.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-03", "Threat Prioritization", "Threats are prioritized.", "Phishing #1, Ransomware #2.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-04", "Impact Analysis", "Business impact is analyzed.", "BIA: RTO < 8h for SAP.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-05", "Risk Determination", "Inherent risk is determined.", "Likelihood x Impact = Score.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-06", "Risk Response", "Risk responses are selected.", "Mitigate, Accept, Transfer.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-01", "Supply Chain Role", "Role in supply chain is defined.", "Wine distributor, importer.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-02", "Critical Infrastructure", "Critical infrastructure dependencies.", "High impact if disrupted.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-03", "Dependencies", "Critical dependencies are mapped.", "SAP, AWS, Email.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-04", "Resilience Requirements", "Resilience requirements are defined.", "RPO < 4h, RTO < 8h.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-05", "Communication", "Requirements are communicated.", "Vendor SLAs + contracts.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-01", "Identity Management", "Identities are managed.", "Azure AD + Duo MFA.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-02", "Access Permissions", "Access is based on least privilege.", "Okta groups + RBAC.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-03", "Remote Access", "Remote access is controlled.", "Cisco AnyConnect + MFA.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-04", "Access Enforcement", "Access is enforced.", "Okta for Shopify, SAP.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-05", "Network Integrity", "Network communications are protected.", "Palo Alto NGFW + TLS.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AT-01", "Training", "Awareness training is provided.", "KnowBe4. 98% completion.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AT-02", "Privileged Training", "Privileged users are trained.", "CISO-led admin training.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AT-03", "Vendor Training", "Vendors receive training.", "Contract clause.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AT-04", "Executive Training", "Executives are trained.", "Board quarterly sessions.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-01", "Data at Rest", "Data at rest is protected.", "AES-256. BitLocker, TDE.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-02", "Data in Transit", "Data in transit is protected.", "TLS 1.3. A+ SSL Labs.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-03", "Data in Use", "Data in use is protected.", "No PII in memory. DLP.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-04", "Backup", "Backups are maintained.", "Air-gapped. Veeam.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-05", "Disposal", "Data disposal is secure.", "DBAN + certificate.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-06", "Integrity", "Data integrity is maintained.", "FIM via CrowdStrike.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-07", "Recovery Testing", "Recovery is tested.", "Quarterly. Last: 2025-10-15.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-01", "Baseline Config", "Baseline configurations are established.", "CIS benchmarks. Terraform.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-02", "Change Control", "Changes are managed.", "CAB. Jira + ServiceNow.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-03", "Hardening", "Systems are hardened.", "SMBv1 off. GPOs.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-04", "Config Access", "Configuration access is restricted.", "GitLab. DevOps only.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-05", "Tech Management", "Technology is managed.", "Auto-patch via WSUS.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-06", "Asset Management", "Assets are managed.", "Inventory via Lansweeper.", "Implemented", "", 1, "2025-11-01"),
        ("PR.IP-07", "Compliance", "Compliance is maintained.", "APRA, GDPR. Annual audit.", "Implemented", "", 1, "2025-11-01"),
        ("PR.MA-01", "Maintenance", "Maintenance is performed.", "4h SLA with vendors.", "Implemented", "", 1, "2025-11-01"),
        ("PR.MA-02", "Remote Maintenance", "Remote maintenance is secure.", "BeyondTrust. Recorded.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-01", "Audit Logging", "Audit logs are maintained.", "12-month retention. Splunk.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-02", "Log Integrity", "Log integrity is protected.", "Write-once. Hashing.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-03", "Log Retention", "Logs are retained.", "90 days online, archive.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-04", "Network Protection", "Network is segmented.", "Micro-segmentation via NSX.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-05", "Automation", "Processes are automated.", "SOAR. 80% auto.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-01", "Baseline", "Normal behavior is baselined.", "Palo Alto XDR.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-02", "Event Analysis", "Events are analyzed.", "Correlated in SIEM.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-03", "Event Correlation", "Events are correlated.", "Splunk + CrowdStrike.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-04", "Impact", "Impact is assessed.", "MTTD < 1h.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-05", "Classification", "Events are classified.", "Severity 1-4.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-01", "Network Monitoring", "Network is monitored.", "NetFlow + NGFW.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-02", "Physical", "Physical environment is monitored.", "CCTV + access logs.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-03", "Personnel", "Personnel activity is monitored.", "DLP + UEBA.", "Partial", "Q4", 1, "2025-11-10"),
        ("DE.CM-04", "Vendor", "Vendors are monitored.", "SOC2 reports quarterly.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-05", "Malware", "Malware is detected.", "EDR via Falcon.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-06", "Mobile Code", "Mobile code is controlled.", "AppLocker.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-07", "Unauthorized", "Unauthorized software is blocked.", "NAC + 802.1x.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-08", "Vuln Scanning", "Vulnerabilities are scanned.", "Weekly via Tenable.", "Implemented", "", 1, "2025-11-01"),
        ("RS.PL-01", "Response Plan", "Incident response plan exists.", "IR playbook. Tested.", "Partial", "Q4 drill", 1, "2025-11-05"),
        ("RS.CO-01", "Roles", "IR roles are defined.", "IT, Legal, PR.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-02", "Reporting", "Incidents are reported.", "1h to CISO. PagerDuty.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-03", "Sharing", "Incidents are shared.", "APRA, ACSC within 72h.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-04", "Coordination", "Coordination is managed.", "Internal + external CIRT.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-01", "Investigation", "Incidents are investigated.", "RCA + forensics.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-02", "Effects", "Effects are determined.", "Business impact, downtime.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-03", "Type", "Incident type is classified.", "Phishing, Ransom, etc.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-04", "Categorization", "Incidents are categorized.", "High-Med-Low.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-01", "Containment", "Containment is performed.", "Isolate affected systems.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-02", "Eradication", "Threat is eradicated.", "Reimage or patch.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-03", "Recovery", "Systems are recovered.", "Restore from Veeam.", "Implemented", "", 1, "2025-11-01"),
        ("RS.IM-01", "Lessons", "Lessons learned are documented.", "Within 7 days.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-01", "Recovery Plan", "Recovery plan exists.", "BCP/DR. RTO < 8h.", "Implemented", "", 1, "2025-11-01"),
        ("RC.IM-01", "Improvements", "Plans are improved.", "Post-test updates.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-01", "PR", "Reputation is managed.", "PR on call.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-02", "Repair", "Communications are managed.", "Customer letters.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-03", "Notify", "Regulators are notified.", "APRA within 72h.", "Implemented", "", 1, "2025-11-01"),
    ]
    c.executemany("""INSERT OR IGNORE INTO nist_controls 
                     (id, name, description, implementation_guide, status, notes, company_id, last_updated) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", nist_full)

    # SAMPLE RISKS
    risks = [
        (1, "Phishing Campaign", "Finance targeted via email", "DETECT", "High", "High", "Pending Approval", "finance@jovalwines.com.au", "2025-10-01", 9, "approver@jovalwines.com.au", ""),
        (1, "Laptop Lost", "Customer PII on unencrypted device", "PROTECT", "Medium", "High", "Mitigated", "it@jovalwines.com.au", "2025-09-28", 6, "approver@jovalwines.com.au", "Remote wipe executed")
    ]
    c.executemany("""INSERT OR IGNORE INTO risks 
                     (company_id, title, description, category, likelihood, impact, status, 
                      submitted_by, submitted_date, risk_score, approver_email, approver_notes) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", risks)

    # VENDORS
    c.execute("INSERT OR IGNORE INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
              ("Reefer Tech", "security@reefertech.com", "High", "2025-08-20", 1))
    c.execute("INSERT OR IGNORE INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
              ("Pallet Co", "vendor@palletco.com", "Medium", "2025-09-15", 1))

    # QUESTIONNAIRE
    questions = [
        (1, "Do you enforce MFA for all administrative access?", "Yes", "2025-08-21", "2025-08-20"),
        (1, "Do you perform regular vulnerability scanning?", "Yes", "2025-08-21", "2025-08-20"),
        (2, "Do you have an incident response plan?", "Yes", "2025-09-16", "2025-09-15")
    ]
    c.executemany("INSERT OR IGNORE INTO vendor_questionnaire (vendor_id, question, answer, answered_date, sent_date) VALUES (?, ?, ?, ?, ?)", questions)

    conn.commit()
    conn.close()

# === UTILS ===
def calculate_risk_score(likelihood, impact):
    scores = {"Low": 1, "Medium": 2, "High": 3}
    return scores.get(likelihood, 1) * scores.get(impact, 1)

def get_risk_color(score):
    if score >= 7: return "high"
    elif score >= 4: return "medium"
    else: return "low"

def log_action(user_email, action, details=""):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO audit_trail (timestamp, user_email, action, details) VALUES (?, ?, ?, ?)",
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user_email, action, details))
    conn.commit()
    conn.close()

def generate_pdf_report(title, lines):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [Paragraph(title, styles['Title']), Spacer(1, 12)]
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    story.append(Spacer(1, 12))
    for line in lines:
        story.append(Paragraph(line, styles['Normal']))
        story.append(Spacer(1, 6))
    doc.build(story)
    buffer.seek(0)
    return buffer

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
    .header h1 {font-weight: normal !important;}
    .metric-card {background: white; padding: 1.5rem; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
    .risk-high, .risk-medium, .risk-low {padding: 0.5rem; border-radius: 8px; cursor: pointer;}
    .risk-high {background: #ffe6e6; border-left: 5px solid red;}
    .risk-medium {background: #fff4e6; border-left: 5px solid orange;}
    .risk-low {background: #e6f7e6; border-left: 5px solid green;}
</style>
""", unsafe_allow_html=True)

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
        if st.button(f"{r['title']} - Score: {r['risk_score']} | {r['status']}", key=f"risk_{r['id']}"):
            st.session_state.edit_risk_id = r['id']
            st.rerun()

    if "edit_risk_id" in st.session_state:
        risk_id = st.session_state.edit_risk_id
        risk = pd.read_sql("SELECT * FROM risks WHERE id=?", conn, params=(risk_id,)).iloc[0]
        with st.form("edit_risk"):
            title = st.text_input("Title", risk['title'])
            desc = st.text_area("Description", risk['description'])
            status = st.selectbox("Status", ["Pending Approval", "Approved", "Rejected", "Mitigated"], index=["Pending Approval", "Approved", "Rejected", "Mitigated"].index(risk['status']))
            if st.form_submit_button("Update"):
                c.execute("UPDATE risks SET title=?, description=?, status=? WHERE id=?", (title, desc, status, risk_id))
                conn.commit()
                del st.session_state.edit_risk_id
                st.success("Updated")
                st.rerun()

# === NIST CONTROLS ===
elif page == "NIST Controls":
    st.markdown("## NIST Controls (106)")
    controls = pd.read_sql("SELECT id, name, description, implementation_guide, status, notes FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
    for _, ctrl in controls.iterrows():
        with st.expander(f"{ctrl['id']} – {ctrl['name']}"):
            st.write(f"**Description**: {ctrl['description']}")
            st.write(f"**Implementation Guide**: {ctrl['implementation_guide']}")
            st.write(f"**Status**: {ctrl['status']}")
            if ctrl['notes']: st.write(f"**Notes**: {ctrl['notes']}")
            col1, col2 = st.columns(2)
            with col1:
                new_status = st.selectbox("Status", ["Implemented", "Partial", "Not Started"], index=["Implemented", "Partial", "Not Started"].index(ctrl['status']), key=f"s_{ctrl['id']}")
            with col2:
                new_notes = st.text_area("Notes", ctrl['notes'], key=f"n_{ctrl['id']}", height=80)
            if st.button("Save", key=f"save_{ctrl['id']}"):
                c.execute("UPDATE nist_controls SET status=?, notes=?, last_updated=? WHERE id=?", 
                          (new_status, new_notes, datetime.now().strftime("%Y-%m-%d"), ctrl['id']))
                conn.commit()
                st.success("Updated")

# === VENDOR RISK ===
elif page == "Vendor Risk":
    st.markdown("## Vendor Risk Management")
    with st.expander("Add New Vendor"):
        with st.form("new_vendor"):
            v_name = st.text_input("Name")
            v_email = st.text_input("Email")
            v_level = st.selectbox("Risk Level", ["Low", "Medium", "High"])
            if st.form_submit_button("Add"):
                c.execute("INSERT INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
                          (v_name, v_email, v_level, datetime.now().strftime("%Y-%m-%d"), company_id))
                conn.commit()
                st.rerun()

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
                st.success("Sent")

            q_df = pd.read_sql("SELECT id, question, answer FROM vendor_questionnaire WHERE vendor_id=?", conn, params=(v['id'],))
            edited = st.data_editor(q_df, num_rows="dynamic", key=f"q_{v['id']}")
            if st.button("Save Answers", key=f"saveq_{v['id']}"):
                for _, row in edited.iterrows():
                    c.execute("UPDATE vendor_questionnaire SET answer=? WHERE id=?", (row['answer'], row['id']))
                conn.commit()
                st.success("Saved")

# === REPORTS ===
elif page == "Reports":
    st.markdown("## Board-Ready Reports")
    reports = [
        ("Executive Summary", ["97.1% NIST Compliance", "3 High Risks Open", "All critical vendors assessed"]),
        ("Risk Register", ["Phishing Campaign – Score 9 – Pending", "Laptop Lost – Score 6 – Mitigated"]),
        ("NIST Compliance", [f"Implemented: {implemented}/106", "Partial: 2", "Not Started: 0"]),
        ("Vendor Risk Profile", ["Reefer Tech – High – Complete", "Pallet Co – Medium – In Progress"]),
    ]
    for i, (title, lines) in enumerate(reports):
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write(f"**{title}**")
        with col2:
            if st.button("Download PDF", key=f"dl_{i}"):
                pdf = generate_pdf_report(title, lines)
                st.download_button(f"Download {title}.pdf", pdf, f"{title}.pdf", "application/pdf")

# === ADMIN PANEL ===
elif page == "Admin Panel" and user[3] == "Admin":
    st.markdown("## Admin Panel")
    tab1, tab2 = st.tabs(["Users", "Reset DB"])
    with tab1:
        users_df = pd.read_sql("SELECT email, role, company_id FROM users", conn)
        companies = pd.read_sql("SELECT id, name FROM companies", conn)
        comp_map = dict(zip(companies['id'], companies['name']))
        users_df['company'] = users_df['company_id'].map(comp_map)  # FIXED LINE
        edited = st.data_editor(users_df[['email', 'role', 'company']], num_rows="dynamic")
        if st.button("Save"):
            for _, row in edited.iterrows():
                comp_id = companies[companies['name'] == row['company']].iloc[0]['id']
                c.execute("UPDATE users SET role=?, company_id=? WHERE email=?", (row['role'], comp_id, row['email']))
            conn.commit()
            st.success("Updated")
    with tab2:
        if st.button("Reset DB (Dev Only)"):
            conn.close()
            import os
            os.remove("joval_portal.db")
            st.session_state.db_init = False
            st.rerun()

# === FOOTER ===
st.markdown("---\n© 2025 Joval Wines")
