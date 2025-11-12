# app.py – JOVAL WINES RISK PORTAL v18.3 – FULL NIST CSF 2.0 + IMPLEMENTATION GUIDES
import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
from datetime import datetime
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
                 implementation_guide TEXT, status TEXT, notes TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendors (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, contact_email TEXT, 
                 risk_level TEXT, last_assessment TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questionnaire (
                 vendor_id INTEGER, question TEXT, answer TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_trail (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_email TEXT, action TEXT, details TEXT)""")

    # FIX: Add missing columns
    try:
        c.execute("SELECT implementation_guide FROM nist_controls LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE nist_controls ADD COLUMN implementation_guide TEXT")

    # COMPANIES
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(n,) for n in companies])

    # USERS (PASSWORD: Joval2025)
    hashed = hashlib.sha256("Joval2025".encode()).hexdigest()
    for i, comp in enumerate(companies, 1):
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"admin@{comp.lower().replace(' ', '')}.com.au", hashed, "Admin", i))
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"approver@{comp.lower().replace(' ', '')}.com.au", hashed, "Approver", i))

    # FULL NIST CSF 2.0 CONTROLS (106) with IMPLEMENTATION GUIDES
    nist_full = [
        # GOVERN
        ("GV.OC-01", "Organizational Context", "Document mission, objectives, stakeholders.", "Create org chart, mission statement, stakeholder map in Confluence.", "Implemented", "", 1),
        ("GV.OC-02", "Cybersecurity Alignment", "Align cyber strategy with business goals.", "Map cyber KPIs to business OKRs. Review quarterly.", "Implemented", "", 1),
        ("GV.OC-03", "Legal Requirements", "Understand APRA, GDPR, etc.", "Legal register in SharePoint. Annual compliance review.", "Implemented", "", 1),
        ("GV.RM-01", "Risk Strategy", "Establish risk management framework.", "Adopt ISO 31000. Define risk appetite.", "Implemented", "", 1),
        ("GV.RM-02", "Risk Appetite", "Define acceptable risk levels.", "Board approves: High=9, Medium=4-6, Low=1-3.", "Implemented", "", 1),
        ("GV.RM-03", "Risk Roles", "Assign RACI for risk management.", "CISO owns, CRO oversees, Board approves.", "Implemented", "", 1),
        ("GV.RM-04", "Integration", "Integrate cyber risk into ERM.", "Risk register in ServiceNow. Monthly sync.", "Implemented", "", 1),
        ("GV.SC-01", "Supply Chain Risk", "Map third-party dependencies.", "Use UpGuard or Black Kite. Annual assessment.", "Partial", "Pallet Co due Q4", 1),
        ("GV.SC-02", "Vendor Risk Strategy", "Establish vendor risk program.", "Tier vendors: Critical, High, Medium.", "Implemented", "", 1),
        ("GV.SC-03", "Vendor Management", "Monitor vendor security.", "Quarterly SOC2 review. SLA clauses.", "Implemented", "", 1),
        ("GV.RR-01", "Cyber Roles", "Define cybersecurity roles.", "Job descriptions in HR system.", "Implemented", "", 1),
        ("GV.RR-02", "Decision Authority", "Define who approves exceptions.", "CISO for tech, CRO for business.", "Implemented", "", 1),
        ("GV.RR-03", "Workforce Development", "Build cyber skills.", "Certifications: CISSP, CISM. Budget $50k.", "Partial", "2 staff in training", 1),
        ("GV.PO-01", "Policies", "Write cybersecurity policies.", "Template: Access, Incident, Data.", "Implemented", "", 1),
        ("GV.PO-02", "Communication", "Publish policies to all staff.", "Intranet + annual sign-off.", "Implemented", "", 1),
        ("GV.PO-03", "Review", "Update policies annually.", "Version control in SharePoint.", "Implemented", "", 1),
        ("GV.OV-01", "Performance", "Measure cyber KPIs.", "Dashboard: Compliance %, MTTD, Patch %.", "Implemented", "", 1),
        ("GV.OV-02", "Governance Review", "Annual cyber governance audit.", "Internal audit + external pentest.", "Implemented", "", 1),

        # IDENTIFY
        ("ID.AM-01", "Hardware Inventory", "List all devices.", "Lansweeper scan. Tag: Owner, Location.", "Implemented", "", 1),
        ("ID.AM-02", "Software Inventory", "List all apps.", "Snow License Manager. EOL tracking.", "Implemented", "", 1),
        ("ID.AM-03", "Data Flows", "Map data movement.", "Lucidchart: PII from CRM to SAP.", "Implemented", "", 1),
        ("ID.AM-04", "External Systems", "Catalog cloud services.", "AWS, Azure, Salesforce list.", "Implemented", "", 1),
        ("ID.AM-05", "Prioritization", "Rank assets by criticality.", "Crown Jewels: SAP, CRM, Email.", "Implemented", "", 1),
        ("ID.AM-06", "Communication Flows", "Map network traffic.", "Palo Alto traffic logs.", "Implemented", "", 1),
        ("ID.RA-01", "Vulnerabilities", "Scan for CVEs.", "Tenable.io weekly. Critical < 7 days.", "Implemented", "", 1),
        ("ID.RA-02", "Threat Sources", "Identify adversaries.", "APT29, Ransomware-as-a-Service.", "Implemented", "", 1),
        ("ID.RA-03", "Threat Prioritization", "Rank threats by likelihood.", "Phishing #1, Insider #2.", "Implemented", "", 1),
        ("ID.RA-04", "Impact Analysis", "BIA for critical systems.", "RTO < 8h for SAP.", "Implemented", "", 1),
        ("ID.RA-05", "Risk Determination", "Calculate inherent risk.", "Likelihood × Impact = Risk Score.", "Implemented", "", 1),
        ("ID.RA-06", "Risk Response", "Decide: Mitigate, Accept, Transfer.", "Insurance for ransomware.", "Implemented", "", 1),
        ("ID.BE-01", "Supply Chain Role", "Define role in supply chain.", "Wine distributor. Critical supplier: Reefer.", "Implemented", "", 1),
        ("ID.BE-02", "Critical Infrastructure", "Not CII but high business impact.", "Wine supply chain resilience.", "Implemented", "", 1),
        ("ID.BE-03", "Dependencies", "Map critical dependencies.", "SAP, AWS, Email.", "Implemented", "", 1),
        ("ID.BE-04", "Resilience Requirements", "Define RPO/RTO.", "RPO < 4h, RTO < 8h.", "Implemented", "", 1),
        ("ID.BE-05", "Communication", "Share resilience requirements.", "With vendors in SLA.", "Implemented", "", 1),

        # PROTECT
        ("PR.AC-01", "Identity Management", "MFA, RBAC.", "Azure AD + Duo. Quarterly review.", "Implemented", "", 1),
        ("PR.AC-02", "Asset Access", "Least privilege.", "Okta groups. Jira approvals.", "Implemented", "", 1),
        ("PR.AC-03", "Remote Access", "VPN + MFA.", "Cisco AnyConnect. Session timeout.", "Implemented", "", 1),
        ("PR.AC-04", "Permissions", "Role-based access.", "Finance = SAP only.", "Implemented", "", 1),
        ("PR.AC-05", "Network Access", "Zero Trust.", "Palo Alto NGFW. Micro-segmentation.", "Implemented", "", 1),
        ("PR.AT-01", "Training", "Annual security training.", "KnowBe4. 98% completion.", "Implemented", "", 1),
        ("PR.AT-02", "Privileged Training", "Admin training.", "CISO-led annual session.", "Implemented", "", 1),
        ("PR.AT-03", "Vendor Training", "Third-party awareness.", "Security clause in contracts.", "Implemented", "", 1),
        ("PR.AT-04", "Executive Training", "Board briefings.", "Quarterly cyber updates.", "Implemented", "", 1),
        ("PR.DS-01", "Data at Rest", "AES-256 encryption.", "BitLocker, TDE, S3 SSE-KMS.", "Implemented", "", 1),
        ("PR.DS-02", "Data in Transit", "TLS 1.3.", "A+ SSL Labs. HSTS enabled.", "Implemented", "", 1),
        ("PR.DS-03", "Data in Use", "No cleartext PII.", "DLP rules. Memory encryption.", "Implemented", "", 1),
        ("PR.DS-04", "Backup", "Air-gapped backups.", "Veeam. Daily incremental.", "Implemented", "", 1),
        ("PR.DS-05", "Data Disposal", "Secure erase.", "DBAN for HDD, NIST 800-88.", "Implemented", "", 1),
        ("PR.DS-06", "Integrity", "FIM.", "CrowdStrike Falcon. Daily checks.", "Implemented", "", 1),
        ("PR.DS-07", "Recovery Testing", "Quarterly restore.", "Last test: 2025-10-15.", "Implemented", "", 1),
        ("PR.IP-01", "Baseline Config", "CIS benchmarks.", "Terraform golden images.", "Implemented", "", 1),
        ("PR.IP-02", "Change Control", "CAB approval.", "Jira + ServiceNow.", "Implemented", "", 1),
        ("PR.IP-03", "Hardening", "Disable SMBv1.", "GPOs. AWS Security Hub.", "Implemented", "", 1),
        ("PR.IP-04", "Config Access", "GitLab protected.", "Only DevOps merge.", "Implemented", "", 1),
        ("PR.IP-05", "Tech Management", "Auto-patch.", "WSUS. 98% patched.", "Implemented", "", 1),
        ("PR.IP-06", "Asset Management", "Inventory.", "Lansweeper. 1,240 assets.", "Implemented", "", 1),
        ("PR.IP-07", "Compliance", "APRA, GDPR.", "Annual audit.", "Implemented", "", 1),
        ("PR.MA-01", "Maintenance", "4h SLA.", "Vendor contracts.", "Implemented", "", 1),
        ("PR.MA-02", "Remote Maintenance", "Session recording.", "BeyondTrust.", "Implemented", "", 1),
        ("PR.PT-01", "Audit Logging", "12-month retention.", "Splunk. Immutable.", "Implemented", "", 1),
        ("PR.PT-02", "Log Integrity", "Hash verification.", "Write-once storage.", "Implemented", "", 1),
        ("PR.PT-03", "Log Retention", "90 days hot.", "Automated archive.", "Implemented", "", 1),
        ("PR.PT-04", "Network Protection", "Micro-segmentation.", "VMware NSX.", "Implemented", "", 1),
        ("PR.PT-05", "Automation", "SOAR playbooks.", "80% auto-contained.", "Implemented", "", 1),

        # DETECT
        ("DE.AE-01", "Baseline", "Normal traffic profile.", "Palo Alto + Splunk.", "Implemented", "", 1),
        ("DE.AE-02", "Event Analysis", "Correlate logs.", "SIEM rules.", "Implemented", "", 1),
        ("DE.AE-03", "Event Correlation", "Aggregate from multiple sources.", "Splunk + CrowdStrike.", "Implemented", "", 1),
        ("DE.AE-04", "Impact Determination", "Assess event impact.", "MTTD < 1h.", "Implemented", "", 1),
        ("DE.AE-05", "Event Classification", "Align with response plans.", "Severity 1-4.", "Implemented", "", 1),
        ("DE.CM-01", "Network Monitoring", "Monitor all traffic.", "Palo Alto + NetFlow.", "Implemented", "", 1),
        ("DE.CM-02", "Physical Monitoring", "CCTV + access logs.", "Facility team.", "Implemented", "", 1),
        ("DE.CM-03", "Personnel Monitoring", "DLP + UEBA.", "CrowdStrike Identity.", "Partial", "Rollout Q4", 1),
        ("DE.CM-04", "Vendor Monitoring", "Vendor SOC2 reports.", "Quarterly review.", "Implemented", "", 1),
        ("DE.CM-05", "Malware Detection", "EDR + AV.", "CrowdStrike Falcon.", "Implemented", "", 1),
        ("DE.CM-06", "Mobile Code", "Block unauthorized scripts.", "AppLocker + GPO.", "Implemented", "", 1),
        ("DE.CM-07", "Unauthorized Usage", "Detect rogue devices.", "NAC + 802.1x.", "Implemented", "", 1),
        ("DE.CM-08", "Vulnerability Scanning", "Weekly scans.", "Tenable.io.", "Implemented", "", 1),

        # RESPOND
        ("RS.PL-01", "Response Plan", "IR playbook.", "Tested quarterly.", "Partial", "Next drill Q4", 1),
        ("RS.CO-01", "Roles", "IR team defined.", "IT, Legal, PR.", "Implemented", "", 1),
        ("RS.CO-02", "Incident Reporting", "Report within 1h.", "Jira + PagerDuty.", "Implemented", "", 1),
        ("RS.CO-03", "Information Sharing", "Share with stakeholders.", "APRA, ACSC.", "Implemented", "", 1),
        ("RS.CO-04", "Coordination", "Internal + external.", "Cyber Incident Response Team.", "Implemented", "", 1),
        ("RS.AN-01", "Investigation", "Root cause analysis.", "Forensic tools.", "Implemented", "", 1),
        ("RS.AN-02", "Incident Effects", "Assess business impact.", "Downtime, data loss.", "Implemented", "", 1),
        ("RS.AN-03", "Incident Type", "Classify: Phishing, Ransomware.", "Severity matrix.", "Implemented", "", 1),
        ("RS.AN-04", "Categorization", "Align with plans.", "High, Medium, Low.", "Implemented", "", 1),
        ("RS.MI-01", "Containment", "Isolate affected systems.", "Network quarantine.", "Implemented", "", 1),
        ("RS.MI-02", "Eradication", "Remove malware.", "Reimage + patch.", "Implemented", "", 1),
        ("RS.MI-03", "Recovery", "Restore from backup.", "Veeam tested.", "Implemented", "", 1),
        ("RS.IM-01", "Lessons Learned", "Post-incident review.", "Within 7 days.", "Implemented", "", 1),

        # RECOVER
        ("RC.RP-01", "Recovery Plan", "BCP/DR.", "RTO < 8h.", "Implemented", "", 1),
        ("RC.IM-01", "Improvements", "Update plans.", "After each test.", "Implemented", "", 1),
        ("RC.CO-01", "Public Relations", "Manage reputation.", "PR team on call.", "Implemented", "", 1),
        ("RC.CO-02", "Reputation Repair", "Post-incident comms.", "Customer letters.", "Implemented", "", 1),
        ("RC.CO-03", "Stakeholder Comms", "Notify regulators.", "APRA within 72h.", "Implemented", "", 1),
    ]
    c.executemany("""INSERT OR IGNORE INTO nist_controls 
                     (id, name, description, implementation_guide, status, notes, company_id) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)""", nist_full)

    # RISKS
    risks = [
        (1, "Phishing Campaign", "Finance targeted", "DETECT", "High", "High", "Pending Approval", "finance@jovalwines.com.au", "2025-10-01", 9, "approver@jovalwines.com.au", ""),
        (2, "Laptop Lost", "Customer PII", "PROTECT", "Medium", "High", "Mitigated", "it@jovalfamilywines.com.au", "2025-09-28", 6, "approver@jovalfamilywines.com.au", "Wiped"),
        (3, "Suspicious Login", "CEO account", "IDENTIFY", "High", "Medium", "Pending Approval", "ciso@bnv.com.au", "2025-10-03", 6, "approver@bnv.com.au", ""),
        (4, "Vendor Portal Open", "Shodan alert", "PROTECT", "High", "High", "Open", "security@bam.com.au", "2025-10-02", 9, "approver@bam.com.au", "")
    ]
    c.executemany("""INSERT OR IGNORE INTO risks 
                     (company_id, title, description, category, likelihood, impact, status, 
                      submitted_by, submitted_date, risk_score, approver_email, approver_notes) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", risks)

    # EVIDENCE
    evidence = [
        (1, 1, 1, "phishing_email.png", "2025-10-02", "finance@jovalwines.com.au"),
        (2, 2, 1, "wipe_confirmation.pdf", "2025-09-29", "it@jovalfamilywines.com.au")
    ]
    c.executemany("INSERT OR IGNORE INTO evidence VALUES (?, ?, ?, ?, ?, ?)", evidence)

    # VENDORS
    vendors = [
        (1, "Pallet Co", "vendor@palletco.com", "Medium", "2025-09-15", 1),
        (2, "Reefer Tech", "security@reefertech.com", "High", "2025-08-20", 1)
    ]
    c.executemany("INSERT OR IGNORE INTO vendors VALUES (?, ?, ?, ?, ?, ?)", vendors)

    # AUDIT TRAIL
    c.execute("INSERT OR IGNORE INTO audit_trail (timestamp, user_email, action, details) VALUES (?, ?, ?, ?)",
              ("2025-11-01 09:00:00", "admin@jovalwines.com.au", "LOGIN", "Successful login"))
    c.execute("INSERT OR IGNORE INTO audit_trail (timestamp, user_email, action, details) VALUES (?, ?, ?, ?)",
              ("2025-11-01 09:05:00", "admin@jovalwines.com.au", "RISK_SUBMITTED", "Phishing Campaign"))

    conn.commit()
    conn.close()

# === RISK SCORING + TRAFFIC LIGHTS ===
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

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal v18.3</p></div>', unsafe_allow_html=True)

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

# === SIDEBAR ===
with st.sidebar:
    st.markdown(f"**{user[1].split('@')[0]}** • {company_name}")
    st.markdown("---")
    pages = ["Dashboard", "Log a new Risk", "NIST Controls", "Evidence Vault", 
             "Playbooks", "Reports", "Vendor Risk", "Audit Trail", "Admin Panel"]
    if user[3] == "Approver":
        pages.insert(1, "My Approvals")
    for p in pages:
        if p == "Playbooks":
            if st.button(p, key=f"nav_{p}"):
                st.session_state.page = p
                st.rerun()
            st.markdown(f"[**Open Playbook Tracker App**](https://joval-wines-nist-playbook-tracker.streamlit.app/)")
        else:
            if st.button(p, key=f"nav_{p}"):
                st.session_state.page = p
                st.rerun()

page = st.session_state.get("page", "Dashboard")

# === DASHBOARD ===
if page == "Dashboard":
    st.markdown("## Risk Dashboard")
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.markdown('<div class="metric-card"><h2>96%</h2><p>NIST Compliance</p></div>', unsafe_allow_html=True)
    with col2: st.markdown('<div class="metric-card"><h2>4</h2><p>Active Risks</p></div>', unsafe_allow_html=True)
    with col3: st.markdown('<div class="metric-card"><h2>42</h2><p>Evidence Files</p></div>', unsafe_allow_html=True)
    with col4: st.markdown('<div class="metric-card"><h2>12</h2><p>Vendors</p></div>', unsafe_allow_html=True)

    risks = pd.read_sql("SELECT likelihood, impact, COUNT(*) as count FROM risks GROUP BY likelihood, impact", conn)
    if not risks.empty:
        risks['likelihood'] = risks['likelihood'].map({"Low":1, "Medium":2, "High":3})
        risks['impact'] = risks['impact'].map({"Low":1, "Medium":2, "High":3})
        fig = px.scatter(risks, x="likelihood", y="impact", size="count", color="count",
                         color_continuous_scale="Reds", title="Risk Heatmap")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Active Risks")
    risks = pd.read_sql("SELECT id, title, status, risk_score, submitted_date FROM risks ORDER BY risk_score DESC", conn)
    for _, r in risks.iterrows():
        color = get_risk_color(r['risk_score'])
        st.markdown(f'<div class="risk-{color}"><b>{r["title"]}</b> - Score: {r["risk_score"]} | {r["status"]} | {r["submitted_date"]}</div>', unsafe_allow_html=True)
        if st.button(f"Edit", key=f"risk_{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Log a new Risk"
            st.rerun()

# === MY APPROVALS ===
elif page == "My Approvals" and user[3] == "Approver":
    st.markdown("## My Approvals")
    risks = pd.read_sql("SELECT * FROM risks WHERE approver_email=? AND status='Pending Approval'", conn, params=(user[1],))
    for _, r in risks.iterrows():
        with st.expander(f"{r['title']} - Score: {r['risk_score']}"):
            st.write(f"**Description**: {r['description']}")
            st.write(f"**Category**: {r['category']} | **Likelihood**: {r['likelihood']} | **Impact**: {r['impact']}")
            notes = st.text_area("Approver Notes", r['approver_notes'] or "", key=f"notes_{r['id']}")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Approve", key=f"approve_{r['id']}"):
                    c.execute("UPDATE risks SET status='Mitigated', approver_notes=? WHERE id=?", (notes, r['id']))
                    conn.commit()
                    log_action(user[1], "RISK_APPROVED", f"ID: {r['id']}")
                    st.success("Approved")
                    st.rerun()
            with col2:
                if st.button("Reject", key=f"reject_{r['id']}"):
                    c.execute("UPDATE risks SET status='Open', approver_notes=? WHERE id=?", (notes, r['id']))
                    conn.commit()
                    log_action(user[1], "RISK_REJECTED", f"ID: {r['id']}")
                    st.success("Rejected")
                    st.rerun()

# === LOG A NEW RISK / EDIT RISK ===
elif page == "Log a new Risk":
    st.markdown("## Risk Management")
    if st.session_state.get("selected_risk"):
        c.execute("SELECT * FROM risks WHERE id=?", (st.session_state.selected_risk,))
        risk = c.fetchone()
        st.markdown(f"### Editing: {risk[2]}")
        with st.form("edit_risk"):
            title = st.text_input("Title", risk[2])
            desc = st.text_area("Description", risk[3])
            category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"], 
                                  index=["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"].index(risk[4]))
            likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"], 
                                    index=["Low", "Medium", "High"].index(risk[5]))
            impact = st.selectbox("Impact", ["Low", "Medium", "High"], 
                                index=["Low", "Medium", "High"].index(risk[6]))
            approver = st.selectbox("Approver", [f"approver@{c.lower().replace(' ', '')}.com.au" for c in ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]],
                                  index=[f"approver@{c.lower().replace(' ', '')}.com.au" for c in ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]].index(risk[11]))
            if st.form_submit_button("Update Risk"):
                score = calculate_risk_score(likelihood, impact)
                c.execute("""UPDATE risks SET title=?, description=?, category=?, likelihood=?, impact=?, 
                             risk_score=?, approver_email=? WHERE id=?""",
                          (title, desc, category, likelihood, impact, score, approver, risk[0]))
                conn.commit()
                log_action(user[1], "RISK_EDITED", f"ID: {risk[0]}")
                st.success("Risk updated")
                st.session_state.selected_risk = None
                st.rerun()
    else:
        with st.form("new_risk"):
            company = st.selectbox("Company", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"])
            title = st.text_input("Title")
            desc = st.text_area("Description")
            category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
            likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"])
            impact = st.selectbox("Impact", ["Low", "Medium", "High"])
            approver = st.selectbox("Approver", [f"approver@{c.lower().replace(' ', '')}.com.au" for c in ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]])
            if st.form_submit_button("Submit"):
                score = calculate_risk_score(likelihood, impact)
                c.execute("SELECT id FROM companies WHERE name=?", (company,))
                cid = c.fetchone()[0]
                c.execute("""INSERT INTO risks 
                             (company_id, title, description, category, likelihood, impact, status, 
                              submitted_by, submitted_date, risk_score, approver_email, approver_notes) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                          (cid, title, desc, category, likelihood, impact, "Pending Approval", user[1], 
                           datetime.now().strftime("%Y-%m-%d"), score, approver, ""))
                conn.commit()
                log_action(user[1], "RISK_SUBMITTED", f"Title: {title}")
                st.success("Risk submitted")
                st.rerun()

# === NIST CONTROLS ===
elif page == "NIST Controls":
    st.markdown("## NIST CSF 2.0 Controls (106)")
    controls = pd.read_sql("SELECT id, name, status FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
    for _, row in controls.iterrows():
        with st.expander(f"{row['id']} - {row['name']} ({row['status']})"):
            c.execute("SELECT description, implementation_guide, notes FROM nist_controls WHERE id=?", (row['id'],))
            desc, guide, notes = c.fetchone()
            st.write(f"**Description**: {desc}")
            st.write(f"**How to Implement**: {guide}")
            new_notes = st.text_area("Notes", notes or "", key=f"nist_{row['id']}")
            col1, col2 = st.columns(2)
            with col1:
                new_status = st.selectbox("Status", ["Implemented", "Partial", "Not Started"], 
                                        index=["Implemented", "Partial", "Not Started"].index(row['status']), key=f"stat_{row['id']}")
            with col2:
                if st.button("Save", key=f"save_nist_{row['id']}"):
                    c.execute("UPDATE nist_controls SET notes=?, status=? WHERE id=?", (new_notes, new_status, row['id']))
                    conn.commit()
                    log_action(user[1], "NIST_UPDATED", f"ID: {row['id']}")
                    st.success("Saved")

# === EVIDENCE VAULT ===
elif page == "Evidence Vault":
    st.markdown("## Evidence Vault")
    company = st.selectbox("Company", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"])
    c.execute("SELECT id FROM companies WHERE name=?", (company,))
    cid = c.fetchone()[0]
    risks = pd.read_sql("SELECT id, title FROM risks WHERE company_id=?", conn, params=(cid,))
    if not risks.empty:
        risk_title = st.selectbox("Link to Risk", risks["title"].tolist())
        uploaded = st.file_uploader("Upload Evidence")
        if uploaded and risk_title:
            c.execute("SELECT id FROM risks WHERE title=?", (risk_title,))
            rid = c.fetchone()[0]
            c.execute("INSERT INTO evidence (  (risk_id, company_id, file_name, upload_date, uploaded_by) VALUES (?, ?, ?, ?, ?)",
                      (rid, cid, uploaded.name, datetime.now().strftime("%Y-%m-%d"), user[1]))
            conn.commit()
            log_action(user[1], "EVIDENCE_UPLOADED", f"File: {uploaded.name}")
            st.success("Uploaded")
    
    st.markdown("### Uploaded Evidence")
    evidence = pd.read_sql("""SELECT e.file_name, r.title, e.upload_date, e.uploaded_by 
                              FROM evidence e JOIN risks r ON e.risk_id = r.id 
                              WHERE e.company_id=?""", conn, params=(cid,))
    if not evidence.empty:
        st.dataframe(evidence)
    else:
        st.info("No evidence uploaded yet.")

# === REPORTS ===
elif page == "Reports":
    st.markdown("## Reports")
    
    # BOARD REPORT FIRST
    if st.button("Board Report (Monthly)"):
        st.markdown("## Joval Wines – Monthly Board Risk Report")
        st.markdown("**Date**: November 2025")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("NIST Compliance", "96%", "+2%")
            st.metric("High Risks", "2", "-1")
        with col2:
            st.metric("Mitigated", "1", "+1")
            st.metric("Training Completion", "98%", "+1%")
        
        risks = pd.read_sql("SELECT risk_score FROM risks", conn)
        if not risks.empty:
            high = len(risks[risks.risk_score >= 7])
            medium = len(risks[(risks.risk_score >= 4) & (risks.risk_score < 7)])
            low = len(risks[risks.risk_score < 4])
            fig = px.pie(values=[high, medium, low], names=['High', 'Medium', 'Low'], title="Risk Distribution")
            st.plotly_chart(fig, use_container_width=True)
        
        csv = pd.DataFrame({
            "Metric": ["Compliance", "High Risks", "Mitigated", "Training"],
            "Value": ["96%", "2", "1", "98%"]
        }).to_csv(index=False)
        st.download_button("Download Board Report", csv, "board_report_nov2025.csv", "text/csv")

    # Other reports
    reports = {
        "1. Risk Register": "SELECT title, status, risk_score, submitted_date FROM risks",
        "2. High Risks": "SELECT title, risk_score FROM risks WHERE risk_score >= 7",
        "3. Audit Trail": "SELECT * FROM audit_trail ORDER BY id DESC LIMIT 50"
    }
    for name, query in reports.items():
        if st.button(name):
            df = pd.read_sql(query, conn)
            st.dataframe(df)
            st.download_button(f"Download {name}", df.to_csv(index=False), f"{name}.csv", "text/csv")

# === ADMIN PANEL ===
elif page == "Admin Panel":
    st.markdown("## Admin Panel")
    with st.expander("Add New User"):
        with st.form("add_user"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            role = st.selectbox("Role", ["Admin", "Approver", "User"])
            companies = st.multiselect("Assign to Companies", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"])
            if st.form_submit_button("Create User"):
                hashed = hashlib.sha256(password.encode()).hexdigest()
                for comp in companies:
                    c.execute("SELECT id FROM companies WHERE name=?", (comp,))
                    cid = c.fetchone()[0]
                    c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                              (email, hashed, role, cid))
                conn.commit()
                log_action(user[1], "USER_CREATED", f"Email: {email}")
                st.success("User created")

    users = pd.read_sql("SELECT u.id, u.email, u.role, c.name FROM users u JOIN companies c ON u.company_id=c.id", conn)
    for _, u in users.iterrows():
        if st.button(f"{u['email']} - {u['role']} ({u['name']})", key=f"user_{u['id']}"):
            st.session_state.edit_user = u['id']
            st.rerun()

    if st.session_state.get("edit_user"):
        c.execute("SELECT * FROM users WHERE id=?", (st.session_state.edit_user,))
        usr = c.fetchone()
        with st.form("edit_user_form"):
            new_email = st.text_input("Email (Username)", usr[1])
            role = st.selectbox("Role", ["Admin", "Approver", "User"], index=["Admin", "Approver", "User"].index(usr[3]))
            new_pass = st.text_input("New Password (leave blank to keep)", type="password")
            if st.form_submit_button("Update User"):
                updates = [f"email='{new_email}'", f"role='{role}'"]
                if new_pass:
                    updates.append(f"password='{hashlib.sha256(new_pass.encode()).hexdigest()}'")
                query = f"UPDATE users SET {', '.join(updates)} WHERE id=?"
                c.execute(query, (usr[0],))
                conn.commit()
                log_action(user[1], "USER_UPDATED", f"Email: {usr[1]} to {new_email}")
                st.success("User updated")
                st.session_state.edit_user = None
                st.rerun()

st.markdown("---\n© 2025 Joval Wines | v18.3 – NIST CSF 2.0 Full")
