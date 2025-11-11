import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
from datetime import datetime
import hashlib
import os

# === CONFIG ===
st.set_page_config(page_title="Joval Risk Portal", layout="wide")

# === CLOUD-SAFE DB PATH ===
DB_PATH = "/tmp/joval_portal.db"

@st.cache_resource
def get_db():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

# === INIT DB ONLY ONCE ===
def init_db():
    if os.path.exists(DB_PATH):
        return
    conn = get_db()
    c = conn.cursor()

    # Tables
    c.execute("CREATE TABLE IF NOT EXISTS companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)")
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, role TEXT, company_id INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS risks (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, title TEXT, description TEXT, category TEXT, likelihood TEXT, impact TEXT, status TEXT, submitted_by TEXT, submitted_date TEXT, risk_score INTEGER, approver_email TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER, company_id INTEGER, file_name TEXT, upload_date TEXT, uploaded_by TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS nist_controls (id TEXT PRIMARY KEY, name TEXT, description TEXT, status TEXT, notes TEXT, company_id INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS playbook_steps (id INTEGER PRIMARY KEY AUTOINCREMENT, playbook_name TEXT, step TEXT, checked INTEGER, notes TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS vendors (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, risk_level TEXT, last_assessment TEXT, company_id INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS vendor_questionnaire (vendor_id INTEGER, question TEXT, answer TEXT)")

    # Companies
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(n,) for n in companies])

    # Users
    hashed = hashlib.sha256("admin123".encode()).hexdigest()
    for i, comp in enumerate(companies, 1):
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"admin@{comp.lower().replace(' ', '')}.com.au", hashed, "Admin", i))
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"approver@{comp.lower().replace(' ', '')}.com.au", hashed, "Approver", i))

    # NIST Controls (20 Full)
    nist_data = [
        ("ID.SC-02", "Supply Chain Risk", "Establish and maintain a supply chain risk management program that identifies, assesses, and mitigates risks associated with third-party suppliers and vendors. Conduct regular risk assessments, require security attestations (e.g., SOC 2), and maintain vendor contracts with security clauses.", "Partial", "Annual review in progress", 1),
        ("PR.AC-01", "Identity Management", "Implement identity and access management controls including unique user IDs, multi-factor authentication (MFA), and role-based access control (RBAC). Regularly review user access and disable inactive accounts within 24 hours.", "Implemented", "Okta SSO + MFA enforced", 1),
        ("PR.DS-05", "Data Encryption", "Encrypt sensitive data at rest using AES-256 and in transit using TLS 1.3. Implement key management with rotation every 90 days and hardware security modules (HSM) where applicable.", "Implemented", "Azure Key Vault", 1),
        ("DE.CM-01", "Continuous Monitoring", "Deploy SIEM with 24/7 monitoring, log retention for 12 months, and automated alerting. Correlate logs from endpoints, network, and cloud.", "Implemented", "Splunk + CrowdStrike", 1),
        ("RS.MI-01", "Incident Response Plan", "Maintain a documented, tested incident response plan with defined roles, communication protocols, and escalation paths. Conduct tabletop exercises quarterly and full drills annually.", "Partial", "Last test: Q3 2025", 1),
        ("RC.RP-01", "Recovery Planning", "Define RPO < 4 hours and RTO < 8 hours. Maintain offsite backups with air-gapped storage and test restores quarterly.", "Implemented", "Veeam + AWS S3", 1),
        ("PR.MA-01", "Maintenance", "Implement patch management with critical patches applied within 7 days. Use vulnerability scanning and CIS benchmarks.", "Implemented", "Tenable + Ansible", 1),
        ("PR.AT-01", "Awareness Training", "Conduct mandatory security awareness training annually and phishing simulations quarterly. Track completion rates > 95%.", "Implemented", "KnowBe4", 1),
        ("ID.RA-05", "Threat Identification", "Subscribe to threat intelligence feeds and integrate with SIEM. Conduct threat modeling for new systems.", "Partial", "Pilot phase", 1),
        ("PR.IP-01", "Baseline Configuration", "Maintain hardened system images using CIS benchmarks. Use configuration management tools.", "Implemented", "Ansible Tower", 1),
        ("DE.AE-01", "Anomalous Activity", "Deploy UEBA to detect insider threats and lateral movement. Set behavioral baselines.", "Partial", "Pilot with 100 users", 1),
        ("RS.CO-02", "Coordination", "Establish cross-functional incident response team with clear RACI. Conduct joint drills with IT, Legal, PR.", "Implemented", "Quarterly", 1),
        ("GV.OC-01", "Organizational Context", "Define governance structures, risk tolerance, and regulatory requirements. Align with business objectives.", "Implemented", "Board approved", 1),
        ("ID.AM-01", "Asset Inventory", "Maintain inventory of hardware and software. Update quarterly with barcode scanning.", "Implemented", "Lansweeper", 1),
        ("ID.AM-06", "Roles & Responsibilities", "Define and document RACI for all controls. Annual review.", "Implemented", "Updated", 1),
        ("PR.AA-02", "Credential Management", "Issue, manage, verify, revoke, and audit credentials. Annual access review.", "Implemented", "Okta", 1),
        ("PR.DS-02", "Data-in-Use Protection", "Protect data in memory. Prevent screen capture on sensitive applications.", "Partial", "Pilot phase", 1),
        ("DE.CM-07", "Physical Monitoring", "Monitor temperature, power, and physical access. Integrate with SIEM.", "Implemented", "DCIM system", 1),
        ("RS.AN-01", "Root Cause Analysis", "Conduct 5-Whys post-incident. Update controls based on findings.", "Implemented", "Standard template", 1),
        ("RC.IM-01", "Improvement", "Incorporate lessons learned into IR plan. Update annually.", "Partial", "Q4 2025", 1)
    ]
    c.executemany("INSERT OR IGNORE INTO nist_controls VALUES (?, ?, ?, ?, ?, ?)", nist_data)

    # Playbooks (12 Full)
    playbooks = {
        "Ransomware Response": [
            "Isolate affected systems immediately (disable network, Wi-Fi, VPN)",
            "Preserve forensic evidence: capture memory dump and disk image",
            "Activate IR team via Slack #ir-alert and notify CISO",
            "Engage legal counsel for APRA/ASIC reporting",
            "Restore from verified offline backup",
            "Conduct root cause analysis and update detection rules"
        ],
        "Phishing Attack": [
            "Quarantine malicious email in Microsoft 365",
            "Reset passwords and enforce MFA re-authentication",
            "Scan endpoints with EDR (CrowdStrike)",
            "Run targeted phishing simulation in 48h",
            "Update filters and block sender domains"
        ],
        "Data Exfiltration": [
            "Block all egress traffic at firewall",
            "Preserve PCAP for 90 days",
            "Engage external IR firm (Mandiant)",
            "Notify APRA within 72 hours if PII involved",
            "Implement DLP with content inspection"
        ],
        "Insider Threat": [
            "Place employee on administrative leave",
            "Revoke all access (VPN, badges, devices)",
            "Preserve logs for 12 months (legal hold)",
            "Conduct exit interview and device inspection",
            "Enforce least privilege policies"
        ],
        "DDoS Attack": [
            "Activate Cloudflare 'I'm Under Attack' mode",
            "Engage ISP for traffic scrubbing",
            "Monitor in Datadog and Splunk",
            "Failover to secondary data center",
            "Conduct post-event capacity planning"
        ],
        "Physical Breach": [
            "Lock down facility and activate CCTV",
            "Notify law enforcement",
            "Preserve access logs and footage",
            "Conduct third-party physical audit",
            "Update badge policies and mantraps"
        ],
        "Cloud Misconfiguration": [
            "Revoke public access to S3 bucket",
            "Enable GuardDuty and Security Hub",
            "Scan with Prowler or Scout Suite",
            "Apply CIS benchmarks via Terraform",
            "Train DevOps on secure IaC"
        ],
        "Zero-Day Exploit": [
            "Deploy virtual patch in WAF",
            "Isolate vulnerable systems in VLAN",
            "Monitor with YARA and Suricata",
            "Apply patch within 24 hours",
            "Update vuln management process"
        ],
        "Credential Stuffing": [
            "Enforce MFA for all apps",
            "Block IPs with >10 failed logins",
            "Reset breached accounts (HaveIBeenPwned)",
            "Enable dark web monitoring",
            "Implement CAPTCHA on login"
        ],
        "Supply Chain Attack": [
            "Isolate compromised vendor software",
            "Scan with YARA and VirusTotal",
            "Activate joint response with vendor",
            "Update SLAs with security clauses",
            "Require SBOM in onboarding"
        ],
        "Backup Failure": [
            "Restore from secondary offsite backup",
            "Initiate RCA on primary system",
            "Test restored data in staging",
            "Update monitoring alerts",
            "Conduct full drill in 7 days"
        ],
        "API Abuse": [
            "Implement rate limiting",
            "Rotate API keys every 30 days",
            "Audit API logs in Splunk",
            "Enable WAF and Apigee",
            "Document API usage policy"
        ]
    }
    for name, steps in playbooks.items():
        for step in steps:
            c.execute("INSERT OR IGNORE INTO playbook_steps (playbook_name, step, checked, notes) VALUES (?, ?, ?, ?)",
                      (name, step, 0, ""))

    # Risks
    risks = [
        (1, "Phishing Campaign Targeting Finance", "Multiple users reported wire transfer scam", "DETECT", "High", "High", "Pending Approval", "finance@jovalwines.com.au", "2025-10-01", 9, "approver@jovalwines.com.au"),
        (2, "Unencrypted Laptop Lost", "Employee device missing with customer PII", "PROTECT", "Medium", "High", "Mitigated", "it@jovalfamilywines.com.au", "2025-09-28", 6, "approver@jovalfamilywines.com.au"),
        (3, "Suspicious Login from Russia", "MFA bypass attempt on CEO account", "IDENTIFY", "High", "Medium", "Pending Approval", "ciso@bnv.com.au", "2025-10-03", 6, "approver@bnv.com.au"),
        (4, "Vendor Portal Exposed", "Shodan scan found open admin interface", "PROTECT", "High", "High", "Open", "security@bam.com.au", "2025-10-02", 9, "approver@bam.com.au")
    ]
    c.executemany("INSERT OR IGNORE INTO risks (company_id, title, description, category, likelihood, impact, status, submitted_by, submitted_date, risk_score, approver_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", risks)

    # Vendors + Questions
    c.execute("INSERT OR IGNORE INTO vendors VALUES (1, 'Pallet Co', 'Medium', '2025-09-15', 1)")
    c.execute("INSERT OR IGNORE INTO vendors VALUES (2, 'Reefer Tech', 'High', '2025-08-20', 1)")
    questions = [
        (1, "Does your organization have a formal information security program?", ""),
        (1, "Is the program aligned with NIST CSF, ISO 27001, or similar?", ""),
        (1, "Do you conduct regular third-party penetration testing?", ""),
        (2, "Do you encrypt data in transit and at rest?", ""),
        (2, "Are access controls based on least privilege?", "")
    ]
    c.executemany("INSERT OR IGNORE INTO vendor_questionnaire VALUES (?, ?, ?)", questions)

    conn.commit()
    conn.close()

init_db()

# === STYLES ===
st.markdown("""
<style>
    .main {background: #f7f7f7;}
    .header {background: #1a1a1a; color: white; padding: 2rem; text-align: center;}
    .header h1 {font-weight: 300; font-size: 2.4rem;}
    .metric-card {background: white; padding: 2rem; border-radius: 12px; text-align: center; cursor: pointer;}
    .css-1d391kg {background: #1a1a1a !important;}
    .css-1v0mbdj button {background: #2b2b2b !important; color: white !important; width: 100% !important; text-align: left !important; padding: 1rem !important; border-radius: 8px !important; margin: 0.4rem 0 !important;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal</p></div>', unsafe_allow_html=True)

# === LOGIN ===
if "user" not in st.session_state:
    with st.sidebar.form("login_form"):
        st.markdown("### Login")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            conn = get_db()
            c = conn.cursor()
            hashed = hashlib.sha256(password.encode()).hexdigest()
            c.execute("SELECT * FROM users WHERE email=? AND password=?", (email, hashed))
            user = c.fetchone()
            conn.close()
            if user:
                st.session_state.user = user
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
    st.markdown(f"**{user[1].split('@')[0]}**")
    st.markdown(f"<small>{user[3]} • {company_name}</small>", unsafe_allow_html=True)
    st.markdown("---")
    pages = ["Dashboard", "Log a new Risk", "NIST Controls", "Evidence Vault", "Playbooks", "Reports", "Vendor Risk", "Admin Panel"]
    for p in pages:
        if st.button(p, key=f"nav_{p}"):
            st.session_state.page = p
            st.rerun()

page = st.session_state.get("page", "Dashboard")

# === DASHBOARD ===
if page == "Dashboard":
    st.markdown("## Dashboard")
    col1, col2, col3 = st.columns(3)
    with col1: st.markdown('<div class="metric-card"><h2>96%</h2><p>Compliance</p></div>', unsafe_allow_html=True)
    with col2: st.markdown('<div class="metric-card"><h2>4</h2><p>Active Risks</p></div>', unsafe_allow_html=True)
    with col3: st.markdown('<div class="metric-card"><h2>42</h2><p>Evidence Files</p></div>', unsafe_allow_html=True)

    for i, comp in enumerate(["Joval Wines", "Joval Family Wines", "BNV", "BAM"]):
        with st.expander(f"RACI Matrix – {comp}"):
            df = pd.DataFrame([
                ["Asset Inventory", "A", "R", "C", "I"],
                ["Backup", "R", "A", "I", "C"]
            ], columns=["Control", "IT", "Ops", "Sec", "Finance"]).set_index("Control")
            fig = px.imshow(df, color_continuous_scale="Greys")
            st.plotly_chart(fig, use_container_width=True, key=f"raci_{i}")

    st.markdown("### Active Risks")
    risks = pd.read_sql("SELECT id, title, status, risk_score FROM risks", conn)
    for _, r in risks.iterrows():
        if st.button(f"{r['title']} - {r['status']} (Score: {r['risk_score']})", key=f"risk_{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Log a new Risk"
            st.rerun()

# === LOG A NEW RISK + EDIT ===
elif page == "Log a new Risk":
    st.markdown("## Risk Management")
    if st.session_state.get("selected_risk"):
        c.execute("SELECT title, status FROM risks WHERE id=?", (st.session_state.selected_risk,))
        title, status = c.fetchone()
        st.markdown(f"### Editing: {title}")
        with st.form("edit_risk"):
            new_status = st.selectbox("Status", ["Open", "Pending Approval", "Mitigated", "Closed"], index=["Open", "Pending Approval", "Mitigated", "Closed"].index(status))
            if st.form_submit_button("Update"):
                c.execute("UPDATE risks SET status=? WHERE id=?", (new_status, st.session_state.selected_risk))
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
                st.success("Risk logged")

# === NIST CONTROLS ===
elif page == "NIST Controls":
    st.markdown("## NIST CSF 2.0 Controls")
    controls = pd.read_sql("SELECT id, name, status FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
    for _, row in controls.iterrows():
        with st.expander(f"{row['id']} - {row['name']} ({row['status']})"):
            c.execute("SELECT description FROM nist_controls WHERE id=?", (row['id'],))
            st.write(c.fetchone()[0])

# === EVIDENCE VAULT ===
elif page == "Evidence Vault":
    st.markdown("## Evidence Vault")
    company_sel = st.selectbox("Company", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"], key="ev_company")
    c.execute("SELECT id FROM companies WHERE name=?", (company_sel,))
    cid = c.fetchone()[0]
    risks = pd.read_sql("SELECT id, title FROM risks WHERE company_id=?", conn, params=(cid,))
    risk_sel = st.selectbox("Link to Risk", risks["title"].tolist()) if not risks.empty else None
    uploaded = st.file_uploader("Upload Evidence")
    if uploaded and risk_sel:
        c.execute("SELECT id FROM risks WHERE title=?", (risk_sel,))
        rid = c.fetchone()[0]
        c.execute("INSERT INTO evidence (risk_id, company_id, file_name, upload_date, uploaded_by) VALUES (?, ?, ?, ?, ?)",
                  (rid, cid, uploaded.name, datetime.now().strftime("%Y-%m-%d"), user[1]))
        conn.commit()
        st.success("Evidence uploaded")

# === PLAYBOOKS ===
elif page == "Playbooks":
    st.markdown("## Response Playbooks")
    playbooks = pd.read_sql("SELECT DISTINCT playbook_name FROM playbook_steps ORDER BY playbook_name", conn)
    for _, pb in playbooks.iterrows():
        with st.expander(pb['playbook_name']):
            steps = pd.read_sql("SELECT step FROM playbook_steps WHERE playbook_name=?", conn, params=(pb['playbook_name'],))
            for i, s in enumerate(steps["step"]):
                st.markdown(f"**Step {i+1}:** {s}")

# === REPORTS ===
elif page == "Reports":
    st.markdown("## Reports")
    if st.button("Risk Register"):
        df = pd.read_sql("SELECT title, status, risk_score FROM risks", conn)
        st.dataframe(df)
        st.download_button("Download CSV", df.to_csv(index=False), "risk_register.csv")
    if st.button("Compliance Scorecard"):
        df = pd.read_sql("SELECT id, name, status FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
        st.dataframe(df)

# === VENDOR RISK ===
elif page == "Vendor Risk":
    st.markdown("## Vendor Risk Management")
    vendors = pd.read_sql("SELECT id, name, risk_level FROM vendors WHERE company_id=?", conn, params=(company_id,))
    for idx, v in enumerate(vendors.itertuples()):
        with st.expander(f"{v.name} - {v.risk_level}"):
            c.execute("SELECT question, answer FROM vendor_questionnaire WHERE vendor_id=?", (v.id,))
            for q_idx, (q, a) in enumerate(c.fetchall()):
                key = f"vq_{v.id}_{q_idx}"
                new_a = st.text_input(q, a, key=key)
                if st.button("Save", key=f"save_{key}"):
                    c.execute("UPDATE vendor_questionnaire SET answer=? WHERE vendor_id=? AND question=?", (new_a, v.id, q))
                    conn.commit()

# === ADMIN PANEL ===
elif page == "Admin Panel":
    st.markdown("## Admin Panel")
    users = pd.read_sql("SELECT u.email, u.role, c.name FROM users u JOIN companies c ON u.company_id=c.id", conn)
    st.dataframe(users)
    with st.form("add_user"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["Admin", "Approver", "User"])
        comps = st.multiselect("Companies", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"])
        if st.form_submit_button("Add User"):
            hashed = hashlib.sha256(password.encode()).hexdigest()
            for comp in comps:
                c.execute("SELECT id FROM companies WHERE name=?", (comp,))
                cid = c.fetchone()[0]
                c.execute("INSERT INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)", (email, hashed, role, cid))
            conn.commit()
            st.success("User added")

st.markdown("---")
st.markdown("<p style='text-align:center; color:#888;'>© 2025 Joval Wines | Risk Portal v15.1</p>", unsafe_allow_html=True)
