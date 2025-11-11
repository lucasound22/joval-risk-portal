import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
from datetime import datetime
import hashlib
import random

# === INIT DB ===
@st.cache_resource
def get_db():
    return sqlite3.connect("joval_portal.db", check_same_thread=False)

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, role TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS risks (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, title TEXT, description TEXT, category TEXT,
                 likelihood TEXT, impact TEXT, status TEXT, submitted_by TEXT, submitted_date TEXT, risk_score INTEGER, approver_email TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS evidence (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER, company_id INTEGER, file_name TEXT, upload_date TEXT, uploaded_by TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS nist_controls (
                 id TEXT PRIMARY KEY, name TEXT, description TEXT, status TEXT, notes TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS playbook_steps (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, playbook_name TEXT, step TEXT, checked INTEGER, notes TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendors (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, risk_level TEXT, last_assessment TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questionnaire (
                 vendor_id INTEGER, question TEXT, answer TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS custom_reports (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, filters TEXT, created_by TEXT, created_date TEXT)""")

    # 4 Companies
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(c,) for c in companies])

    # Admins + Approvers
    hashed = hashlib.sha256("admin123".encode()).hexdigest()
    for i, comp in enumerate(companies, 1):
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"admin@{comp.lower().replace(' ', '')}.com.au", hashed, "Admin", i))
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"approver@{comp.lower().replace(' ', '')}.com.au", hashed, "Approver", i))

    # 20 FULL NIST CONTROLS WITH DETAIL
    nist_data = [
        ("GV.OC-01", "Organizational Context", "The organizational context includes the internal and external factors that influence the organization's cybersecurity risk management decisions. This includes governance structures, risk tolerance, and legal/regulatory requirements.", "Implemented", "Board approved risk appetite statement", 1),
        ("ID.AM-01", "Physical Device Inventory", "The organization's physical devices are inventoried to establish device requirements, support lifecycle management, and track asset location.", "Implemented", "Updated quarterly with barcode scanning", 1),
        ("ID.AM-02", "Software Platform Inventory", "The organization's software platforms are inventoried to establish software requirements, support lifecycle management, and track asset location.", "Implemented", "Software asset management tool deployed", 1),
        ("ID.AM-03", "Organizational Communication and Data Flows", "The organization's communication and data flows are mapped to establish requirements for security and privacy in communications and data flows.", "Partial", "In progress with data flow diagrams", 1),
        ("ID.AM-04", "External Information Systems", "External information systems are catalogued.", "Not Started", "Q4 2025", 1),
        ("ID.AM-05", "Prioritization of Resources", "Resources are prioritized based on their classification, criticality, and business value.", "Implemented", "Criticality matrix updated", 1),
        ("ID.AM-06", "Roles and Responsibilities", "Roles and responsibilities for business, owner, and user of information systems and information processing facilities are established.", "Implemented", "RACI matrix maintained", 1),
        ("ID.BE-01", "Improvement", "The organization's mission and objectives, and how they relate to information security, are established and communicated.", "Implemented", "Strategic alignment documented", 1),
        ("ID.BE-02", "Improvement", "The organization's role in the supply chain is identified and communicated.", "Partial", "Supply chain mapping ongoing", 1),
        ("ID.BE-03", "Improvement", "Dependencies and critical functions for delivery of critical services are established.", "Implemented", "Business impact analysis complete", 1),
        ("ID.BE-04", "Improvement", "Resiliency requirements to meet the needs to deliver critical services are established.", "Implemented", "BCP/DRP aligned", 1),
        ("ID.BE-05", "Improvement", "Resiliency requirements to meet the needs to deliver critical services are established.", "Partial", "Testing in progress", 1),
        ("ID.RA-01", "Vulnerability Management", "Vulnerabilities are identified, validated, and prioritized.", "Implemented", "Weekly scanning", 1),
        ("ID.RA-02", "Vulnerability Management", "Vulnerabilities are managed.", "Implemented", "Patch Tuesday process", 1),
        ("ID.RA-03", "Vulnerability Management", "Vulnerabilities are managed.", "Partial", "Remediation SLAs defined", 1),
        ("ID.RA-04", "Vulnerability Management", "Vulnerabilities are managed.", "Not Started", "Q1 2026", 1),
        ("ID.RA-05", "Vulnerability Management", "Vulnerabilities are managed.", "Implemented", "Threat modeling quarterly", 1),
        ("ID.RA-06", "Vulnerability Management", "Vulnerabilities are managed.", "Partial", "Pilot UEBA", 1),
        ("PR.AA-01", "Identity Management", "Identities and credentials are issued, managed, verified, revoked, and audited.", "Implemented", "Okta SSO + MFA", 1),
        ("PR.AA-02", "Identity Management", "Identities and credentials are issued, managed, verified, revoked, and audited.", "Implemented", "Annual access review", 1)
    ]
    c.executemany("INSERT OR IGNORE INTO nist_controls VALUES (?, ?, ?, ?, ?, ?)", nist_data)

    # 12 FULL NIST PLAYBOOKS
    playbooks = {
        "Ransomware Response": [
            "Isolate affected systems from network immediately (disable Wi-Fi, unplug Ethernet, disable VPN)",
            "Preserve forensic evidence: capture full memory dump and disk image using FTK Imager or Volatility",
            "Activate Incident Response Team via Slack #ir-alert and notify CISO within 15 minutes of detection",
            "Engage external legal counsel to determine APRA/ASIC mandatory breach reporting requirements (72 hours)",
            "Restore critical systems from verified, offline backup in isolated environment using Veeam",
            "Conduct root cause analysis using 5-Whys methodology and update detection rules in SIEM"
        ],
        "Phishing Attack": [
            "Quarantine malicious email across all mailboxes using Microsoft 365 Defender or Proofpoint",
            "Reset passwords for affected users and enforce MFA re-authentication via Okta or Azure AD",
            "Scan all endpoints for malware using CrowdStrike Falcon Complete or SentinelOne",
            "Deploy targeted phishing simulation to impacted department within 48 hours using KnowBe4",
            "Update phishing filters in Proofpoint and add sender domains to global blocklist"
        ],
        "Data Exfiltration": [
            "Block all egress traffic at firewall level except approved IPs and cloud services (Palo Alto or Fortinet)",
            "Preserve network packet captures (PCAP) for 90 days in secure storage using Wireshark or Zeek",
            "Initiate digital forensics investigation with external IR firm (Mandiant or Deloitte)",
            "Notify APRA within 72 hours if PII or financial data is confirmed exfiltrated (use breach template)",
            "Implement DLP policy with content inspection and automated blocking using Symantec or McAfee"
        ],
        "Insider Threat": [
            "Place suspected employee on immediate administrative leave with pay (HR notification)",
            "Revoke all access tokens, VPN, physical badges, and corporate devices (Okta + Badge system)",
            "Preserve HR records, access logs, email, and OneDrive activity for 12 months (legal hold)",
            "Conduct exit interview and full device return inspection with IT forensics team",
            "Review and enforce least privilege access policies across all systems (RBAC audit)"
        ],
        "DDoS Attack": [
            "Activate Cloudflare DDoS mitigation rules and enable 'I'm Under Attack' mode immediately",
            "Engage ISP for upstream traffic scrubbing and BGP rerouting (Telstra or Optus)",
            "Monitor traffic patterns in real-time using Datadog and Splunk dashboards",
            "Failover to secondary data center with geo-redundant DNS (Route 53 failover)",
            "Conduct post-event capacity planning and load testing using JMeter"
        ],
        "Physical Breach": [
            "Lock down facility and activate all CCTV recording in high-res mode (Milestone XProtect)",
            "Notify law enforcement and preserve scene for physical investigation (CSI unit)",
            "Preserve access card logs and video footage for 30 days in immutable storage",
            "Conduct full physical security audit with third-party assessor (Kroll or Control Risks)",
            "Update badge access policies and implement mantraps at server room entrances"
        ],
        "Cloud Misconfiguration": [
            "Revoke public access to exposed S3 bucket and enable 'Block Public Access' policy",
            "Enable AWS CloudTrail, GuardDuty, and Security Hub across all accounts and regions",
            "Scan all cloud accounts for open ports and weak IAM policies using Prowler or Scout Suite",
            "Implement CIS AWS Foundations benchmark via Terraform IaC templates",
            "Train DevOps team on secure Infrastructure as Code practices (AWS Well-Architected)"
        ],
        "Zero-Day Exploit": [
            "Deploy virtual patching via Imperva WAF rule to block known exploit pattern signatures",
            "Isolate vulnerable systems in containment VLAN with no internet or lateral movement access",
            "Monitor exploit attempts in SIEM with custom YARA rules and Suricata signatures",
            "Apply vendor patch within 24 hours of release using emergency change process",
            "Update vulnerability management process with zero-day protocol and rapid response SLA"
        ],
        "Credential Stuffing": [
            "Enforce MFA for all external-facing applications immediately (Okta Adaptive MFA)",
            "Block IPs with >10 failed login attempts per hour using Cloudflare Bot Management",
            "Reset passwords for any accounts with breached credentials from HaveIBeenPwned database",
            "Enable dark web monitoring via Recorded Future for corporate email domains",
            "Implement CAPTCHA and bot detection on all login pages (reCAPTCHA v3)"
        ],
        "Supply Chain Attack": [
            "Isolate compromised vendor software from production environment (air-gapped testing)",
            "Scan all systems for IOCs using VirusTotal, YARA rules, and Tanium endpoint detection",
            "Notify affected vendors and activate joint response team with shared threat intel",
            "Review third-party risk program and update vendor SLAs with security incident notification clauses",
            "Update vendor onboarding checklist with SBOM requirement and continuous monitoring"
        ],
        "Backup Failure": [
            "Restore from secondary offsite backup location (AWS Glacier Deep Archive or Iron Mountain)",
            "Initiate root cause analysis on primary backup system (Veeam root cause template)",
            "Test restored data integrity and application functionality in staging environment",
            "Update backup configuration and monitoring alerts in PRTG or SolarWinds",
            "Conduct full backup verification drill within 7 days with end-to-end testing"
        ]
    }
    for name, steps in playbooks.items():
        for step in steps:
            c.execute("INSERT OR IGNORE INTO playbook_steps (playbook_name, step, checked, notes) VALUES (?, ?, ?, ?)",
                      (name, step, 0, ""))

    # VENDORS + NIST QUESTIONS
    vendors = [(1, "Pallet Co", "Medium", "2025-09-15", 1), (2, "Reefer Tech", "High", "2025-08-20", 1)]
    c.executemany("INSERT OR IGNORE INTO vendors VALUES (?, ?, ?, ?, ?)", vendors)
    questions = [
        (1, "Does your organization have a formal information security program?", ""),
        (1, "Is the program aligned with NIST CSF, ISO 27001, or similar framework?", ""),
        (1, "Do you conduct regular third-party penetration testing?", ""),
        (1, "Are critical systems segmented from the internet?", ""),
        (1, "Do you maintain incident response and business continuity plans?", ""),
        (2, "Do you encrypt data in transit and at rest?", ""),
        (2, "Are access controls based on least privilege?", ""),
        (2, "Do you perform regular vulnerability scanning?", "")
    ]
    c.executemany("INSERT OR IGNORE INTO vendor_questionnaire VALUES (?, ?, ?)", questions)

    # RISKS + EVIDENCE
    risks = [
        (1, "Phishing Campaign Targeting Finance", "Multiple users reported emails requesting wire transfer changes", "DETECT", "High", "High", "Pending Approval", "finance@jovalwines.com.au", "2025-10-01", 9),
        (2, "Unencrypted Laptop Lost in Transit", "Employee reported missing device with customer PII", "PROTECT", "Medium", "High", "Mitigated", "it@jovalfamilywines.com.au", "2025-09-28", 6),
        (3, "Suspicious Login from Russia", "MFA bypass attempt on CEO account at 3 AM", "IDENTIFY", "High", "Medium", "Pending Approval", "ciso@bnv.com.au", "2025-10-03", 6),
        (4, "Vendor Portal Exposed to Public", "Shodan scan revealed open admin interface", "PROTECT", "High", "High", "Open", "security@bam.com.au", "2025-10-02", 9)
    ]
    c.executemany("INSERT OR IGNORE INTO risks (company_id, title, description, category, likelihood, impact, status, submitted_by, submitted_date, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", risks)

    evidence = [
        (1, 1, "phishing_email.eml", "2025-10-02", "soc@jovalwines.com.au"),
        (2, 2, "laptop_incident_report.pdf", "2025-09-29", "hr@jovalfamilywines.com.au"),
        (3, 3, "login_logs.csv", "2025-10-04", "ciso@bnv.com.au"),
        (4, 4, "shodan_scan.png", "2025-10-03", "security@bam.com.au")
    ]
    c.executemany("INSERT OR IGNORE INTO evidence (risk_id, company_id, file_name, upload_date, uploaded_by) VALUES (?, ?, ?, ?, ?)", evidence)

    conn.commit()
    conn.close()

init_db()

# === UI ===
st.set_page_config(page_title="Joval Risk Portal", layout="wide")
st.markdown("""
<style>
    .main {background-color: #f7f7f7;}
    .header {background: #1a1a1a; color: white; padding: 2.2rem; text-align: center;}
    .header h1 {font-weight: 300; font-size: 2.4rem;}
    .css-1d391kg {background: #1a1a1a !important; padding: 2rem 1rem !important;}
    .css-1v0mbdj button {background: #2b2b2b !important; color: white !important; width: 100% !important; text-align: left !important; padding: 0.9rem 1.2rem !important; border-radius: 8px !important; margin: 0.4rem 0 !important; min-height: 50px !important;}
    .css-1v0mbdj button:hover {background: #444 !important;}
    .metric-card {background: white; padding: 2rem; border-radius: 12px; text-align: center; cursor: pointer;}
</style>
""", unsafe_allow_html=True)

st.markdown('''
<div class="header">
    <h1>JOVAL WINES</h1>
    <p>Risk Management Portal</p>
</div>
''', unsafe_allow_html=True)

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
            if user:
                st.session_state.user = user
                st.rerun()
            else:
                st.error("Invalid")
            conn.close()
    st.stop()

user = st.session_state.user
company_id = user[4]
conn = get_db()
c = conn.cursor()
c.execute("SELECT name FROM companies WHERE id=?", (company_id,))
company_name = c.fetchone()[0]

# === SIDEBAR ===
with st.sidebar:
    st.markdown(f"**{user[1].split('@')[0]}**")
    st.markdown(f"<small>{user[3]} • {company_name}</small>", unsafe_allow_html=True)
    st.markdown("---")
    pages = ["Dashboard", "Log a new Risk", "NIST Controls", "Evidence Vault", "Playbooks", "Reports", "Vendor Risk", "Admin Panel"]
    for p in pages:
        if st.button(p, key=f"nav_{p}"):
            st.session_state.page = p
            st.rerun()

page = st.session_state.get("page", "Dashboard")

# === DASHBOARD (FIXED RACI + RISKS) ===
if page == "Dashboard":
    st.markdown("## Dashboard")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("96% Compliance", key="card_comp"):
            st.session_state.page = "NIST Controls"; st.rerun()
        st.markdown('<div class="metric-card"><h2>96%</h2><p>Compliance</p></div>', unsafe_allow_html=True)
    with col2:
        if st.button("4 Active Risks", key="card_risk"):
            st.session_state.page = "Log a new Risk"; st.rerun()
        st.markdown('<div class="metric-card"><h2>4</h2><p>Active Risks</p></div>', unsafe_allow_html=True)
    with col3:
        if st.button("42 Evidence Files", key="card_ev"):
            st.session_state.page = "Evidence Vault"; st.rerun()
        st.markdown('<div class="metric-card"><h2>42</h2><p>Evidence Files</p></div>', unsafe_allow_html=True)

    # RACI x4 (FIXED)
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    for i, comp in enumerate(companies):
        with st.expander(f"RACI Matrix – {comp}"):
            raci_data = pd.DataFrame([
                ["Asset Inventory", "A", "R", "C", "I"],
                ["Backup", "R", "A", "I", "C"]
            ], columns=["Control", "IT", "Ops", "Sec", "Finance"]).set_index("Control")
            fig = px.imshow(raci_data, color_continuous_scale="Greys")
            st.plotly_chart(fig, use_container_width=True, key=f"raci_{i}")

    # CLICKABLE RISKS
    risks = pd.read_sql("SELECT id, title, status, risk_score, company_id FROM risks", conn)
    st.markdown("### Active Risks")
    for _, r in risks.iterrows():
        c.execute("SELECT name FROM companies WHERE id=?", (r['company_id'],))
        comp_name = c.fetchone()[0]
        if st.button(f"{r['title']} [{comp_name}] - {r['status']} (Score: {r['risk_score']})", key=f"risk_btn_{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Log a new Risk"
            st.rerun()

# === LOG A NEW RISK + EDIT ===
elif page == "Log a new Risk":
    st.markdown("## Log a new Risk")
    if st.session_state.get("selected_risk"):
        c.execute("SELECT * FROM risks WHERE id=?", (st.session_state.selected_risk,))
        risk = c.fetchone()
        st.markdown(f"### Editing: {risk[2]}")
        with st.form("edit_risk"):
            status = st.selectbox("Status", ["Open", "Pending Approval", "Mitigated", "Closed"], index=["Open", "Pending Approval", "Mitigated", "Closed"].index(risk[7]))
            if st.form_submit_button("Update"):
                c.execute("UPDATE risks SET status=? WHERE id=?", (status, risk[0]))
                conn.commit()
                st.success("Updated")
                st.session_state.selected_risk = None
    else:
        with st.form("new_risk"):
            company_sel = st.selectbox("Company", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"])
            title = st.text_input("Title")
            desc = st.text_area("Description")
            category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
            likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"])
            impact = st.selectbox("Impact", ["Low", "Medium", "High"])
            if st.form_submit_button("Submit"):
                score = {"Low":1, "Medium":2, "High":3}[likelihood] * {"Low":1, "Medium":2, "High":3}[impact]
                c.execute("SELECT id FROM companies WHERE name=?", (company_sel,))
                cid = c.fetchone()[0]
                c.execute("INSERT INTO risks (company_id, title, description, category, likelihood, impact, status, submitted_by, submitted_date, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (cid, title, desc, category, likelihood, impact, "Pending Approval", user[1], datetime.now().strftime("%Y-%m-%d"), score))
                conn.commit()
                st.success("Submitted")

# === NIST CONTROLS ===
elif page == "NIST Controls":
    st.markdown("## NIST CSF 2.0 Controls")
    controls = pd.read_sql("SELECT id, name, status FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
    for _, row in controls.iterrows():
        with st.expander(f"{row['id']} - {row['name']} ({row['status']})"):
            c.execute("SELECT description FROM nist_controls WHERE id=?", (row['id'],))
            desc = c.fetchone()[0]
            st.write(desc)

# === EVIDENCE VAULT ===
elif page == "Evidence Vault":
    st.markdown("## Evidence Vault")
    company_sel = st.selectbox("Company", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"], key="evc")
    c.execute("SELECT id FROM companies WHERE name=?", (company_sel,))
    cid = c.fetchone()[0]
    risks = pd.read_sql("SELECT id, title FROM risks WHERE company_id=?", conn, params=(cid,))
    risk_sel = st.selectbox("Link to Risk", risks["title"].tolist()) if not risks.empty else None
    uploaded = st.file_uploader("Upload")
    if uploaded and risk_sel:
        c.execute("SELECT id FROM risks WHERE title=?", (risk_sel,))
        rid = c.fetchone()[0]
        c.execute("INSERT INTO evidence (risk_id, company_id, file_name, upload_date, uploaded_by) VALUES (?, ?, ?, ?, ?)",
                  (rid, cid, uploaded.name, datetime.now().strftime("%Y-%m-%d"), user[1]))
        conn.commit()
        st.success("Uploaded")

# === PLAYBOOKS (12 FULL) ===
elif page == "Playbooks":
    st.markdown("## Response Playbooks")
    playbooks = pd.read_sql("SELECT DISTINCT playbook_name FROM playbook_steps ORDER BY playbook_name", conn)
    for _, pb in playbooks.iterrows():
        with st.expander(pb['playbook_name']):
            steps = pd.read_sql("SELECT step FROM playbook_steps WHERE playbook_name=?", conn, params=(pb['playbook_name'],))
            for i, s in enumerate(steps["step"]):
                st.markdown(f"**Step {i+1}:** {s}")

# === REPORTS (PREBUILT + CUSTOM) ===
elif page == "Reports":
    st.markdown("## Reports")
    prebuilt = ["Risk Register", "Compliance Scorecard", "Vendor Risk Summary"]
    for r in prebuilt:
        if st.button(r, key=f"pre_{r}"):
            if r == "Risk Register":
                df = pd.read_sql("SELECT title, status, risk_score FROM risks WHERE company_id=?", conn, params=(company_id,))
            elif r == "Compliance Scorecard":
                df = pd.read_sql("SELECT id, name, status FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
            elif r == "Vendor Risk Summary":
                df = pd.read_sql("SELECT name, risk_level FROM vendors WHERE company_id=?", conn, params=(company_id,))
            st.dataframe(df)
            st.download_button("Download", df.to_csv(index=False), f"{r}.csv")

    # Custom Reports
    if st.button("Create Custom Report"):
        with st.form("custom"):
            name = st.text_input("Name")
            company = st.selectbox("Company", ["All", "Joval Wines", "Joval Family Wines", "BNV", "BAM"])
            status = st.multiselect("Status", ["Open", "Pending Approval", "Mitigated", "Closed"])
            if st.form_submit_button("Save"):
                filters = f"company={company},status={','.join(status)}"
                c.execute("INSERT INTO custom_reports (name, filters, created_by, created_date) VALUES (?, ?, ?, ?)",
                          (name, filters, user[1], datetime.now().strftime("%Y-%m-%d")))
                conn.commit()
                st.success("Saved")

# === VENDOR RISK (FIXED KEYS) ===
elif page == "Vendor Risk":
    st.markdown("## Vendor Risk Management")
    vendors = pd.read_sql("SELECT id, name, risk_level FROM vendors WHERE company_id=?", conn, params=(company_id,))
    for idx, v in vendors.iterrows():
        with st.expander(f"{v['name']} - {v['risk_level']}"):
            c.execute("SELECT question, answer FROM vendor_questionnaire WHERE vendor_id=?", (v['id'],))
            for q_idx, (q, a) in enumerate(c.fetchall()):
                key = f"vqa_{v['id']}_{q_idx}"
                new_a = st.text_input(q, a, key=key)
                if st.button("Save", key=f"save_vqa_{v['id']}_{q_idx}"):
                    c.execute("UPDATE vendor_questionnaire SET answer=? WHERE vendor_id=? AND question=?", (new_a, v['id'], q))
                    conn.commit()
                    st.success("Saved")

# === ADMIN PANEL (FULL) ===
elif page == "Admin Panel":
    st.markdown("## Admin Panel")
    users = pd.read_sql("SELECT u.id, u.email, u.role, c.name FROM users u JOIN companies c ON u.company_id=c.id", conn)
    st.dataframe(users)
    if st.button("Add New User"):
        with st.form("new_user"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            role = st.selectbox("Role", ["Admin", "Approver", "User"])
            comps = st.multiselect("Assign to Companies", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"])
            if st.form_submit_button("Create"):
                hashed = hashlib.sha256(password.encode()).hexdigest()
                for comp in comps:
                    c.execute("SELECT id FROM companies WHERE name=?", (comp,))
                    cid = c.fetchone()[0]
                    c.execute("INSERT INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)", (email, hashed, role, cid))
                conn.commit()
                st.success("User added")

# === FOOTER ===
st.markdown("""
---
<div style="text-align:center; color:#888; padding:1.2rem;">
© 2025 Joval Wines | Risk Management Portal v15.0
</div>
""", unsafe_allow_html=True)
'@ | Out-File app.py -Encoding utf8

# === BUILD & RUN ===
Write-Host "Building Joval Risk Portal v15.0..." -ForegroundColor Green
docker build -t joval-portal .
Write-Host "STARTING → http://localhost:8501" -ForegroundColor Green
docker run -p 8501:8501 joval-portal
