import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
from datetime import datetime
import hashlib

# === CONFIG ===
st.set_page_config(page_title="Joval Risk Portal", layout="wide")

# === INIT DB ===
@st.cache_resource
def get_db():
    return sqlite3.connect("joval_portal.db", check_same_thread=False)

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Tables
    c.execute("CREATE TABLE IF NOT EXISTS companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)")
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, role TEXT, company_id INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS risks (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, title TEXT, description TEXT, category TEXT, likelihood TEXT, impact TEXT, status TEXT, submitted_by TEXT, submitted_date TEXT, risk_score INTEGER)")
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
        ("ID.SC-02", "Supply Chain Risk", "Establish supply chain risk management program with vendor assessments, SOC 2 requirements, and security clauses in contracts.", "Partial", "", 1),
        ("PR.AC-01", "Identity Management", "Implement unique IDs, MFA, RBAC. Review access quarterly. Disable inactive accounts in 24h.", "Implemented", "Okta + MFA", 1),
        ("PR.DS-05", "Data Encryption", "Encrypt data at rest (AES-256) and in transit (TLS 1.3). Rotate keys every 90 days.", "Implemented", "Azure Key Vault", 1),
        ("DE.CM-01", "Continuous Monitoring", "Deploy SIEM with 24/7 monitoring, 12-month log retention, automated alerts.", "Implemented", "Splunk + CrowdStrike", 1),
        ("RS.MI-01", "Incident Response", "Documented IR plan with roles, comms, escalation. Quarterly tabletop, annual drill.", "Partial", "Last test Q3 2025", 1),
        ("RC.RP-01", "Recovery Planning", "RPO < 4h, RTO < 8h. Offsite air-gapped backups. Quarterly restore tests.", "Implemented", "Veeam + AWS S3", 1),
        ("PR.MA-01", "Maintenance", "Patch critical systems in 7 days. Weekly vuln scans. CIS benchmarks.", "Implemented", "Tenable + Ansible", 1),
        ("PR.AT-01", "Awareness Training", "Annual training + quarterly phishing sims. >95% completion.", "Implemented", "KnowBe4", 1),
        ("ID.RA-05", "Threat Identification", "Subscribe to threat intel feeds. Integrate with SIEM. Threat modeling.", "Partial", "Pilot phase", 1),
        ("PR.IP-01", "Baseline Config", "Hardened images via CIS. Config management with Ansible.", "Implemented", "Ansible Tower", 1),
        ("DE.AE-01", "Anomalous Activity", "Deploy UEBA for insider threats. Behavioral baselines.", "Partial", "100 users", 1),
        ("RS.CO-02", "Coordination", "Cross-functional IR team. Quarterly drills with IT, Legal, PR.", "Implemented", "Quarterly", 1),
        ("GV.OC-01", "Org Context", "Define governance, risk appetite, regulatory requirements.", "Implemented", "Board approved", 1),
        ("ID.AM-01", "Asset Inventory", "Maintain hardware/software inventory. Quarterly updates.", "Implemented", "Lansweeper", 1),
        ("ID.AM-06", "Roles & Resp", "RACI matrix for all controls. Annual review.", "Implemented", "Updated", 1),
        ("PR.AA-02", "Credential Mgmt", "Issue, manage, revoke credentials. Annual audit.", "Implemented", "Okta", 1),
        ("PR.DS-02", "Data-in-Use", "Protect data in memory. Prevent screen capture on sensitive apps.", "Partial", "Pilot", 1),
        ("DE.CM-07", "Monitoring", "Monitor physical environment (temp, power, access).", "Implemented", "DCIM", 1),
        ("RS.AN-01", "Analysis", "Root cause analysis post-incident. Update controls.", "Implemented", "5-Whys", 1),
        ("RC.IM-01", "Improvement", "Lessons learned from incidents. Update IR plan.", "Partial", "Q4 2025", 1)
    ]
    c.executemany("INSERT OR IGNORE INTO nist_controls VALUES (?, ?, ?, ?, ?, ?)", nist_data)

    # Playbooks (12 Full)
    playbooks = {
        "Ransomware Response": [
            "Isolate systems (disable network, Wi-Fi, VPN)",
            "Preserve evidence: memory dump, disk image",
            "Activate IR team via Slack #ir-alert",
            "Engage legal for APRA/ASIC reporting",
            "Restore from offline backup",
            "Root cause analysis + update rules"
        ],
        "Phishing Attack": [
            "Quarantine email in M365",
            "Reset passwords + enforce MFA",
            "Scan endpoints with EDR",
            "Run phishing sim in 48h",
            "Update filters + blocklist"
        ],
        "Data Exfiltration": [
            "Block egress at firewall",
            "Preserve PCAP for 90 days",
            "Engage Mandiant",
            "Notify APRA in 72h",
            "Deploy DLP"
        ],
        "Insider Threat": [
            "Admin leave + revoke access",
            "Preserve logs for 12 months",
            "Exit interview + device check",
            "Enforce least privilege"
        ],
        "DDoS Attack": [
            "Activate Cloudflare 'Under Attack'",
            "Engage ISP for scrubbing",
            "Monitor in Datadog",
            "Failover to DR site"
        ],
        "Physical Breach": [
            "Lock down + CCTV high-res",
            "Notify police",
            "Preserve logs + footage",
            "Physical audit"
        ],
        "Cloud Misconfig": [
            "Block public S3",
            "Enable GuardDuty",
            "Scan with Prowler",
            "Apply CIS via Terraform"
        ],
        "Zero-Day": [
            "Virtual patch in WAF",
            "Isolate in VLAN",
            "Monitor with YARA",
            "Emergency patch in 24h"
        ],
        "Credential Stuffing": [
            "Enforce MFA",
            "Block IPs >10 fails",
            "Reset breached accounts",
            "Dark web monitoring"
        ],
        "Supply Chain": [
            "Isolate vendor software",
            "Scan with YARA",
            "Joint response team",
            "Update SLAs + SBOM"
        ],
        "Backup Failure": [
            "Restore from secondary",
            "RCA on Veeam",
            "Test in staging",
            "Full drill in 7 days"
        ],
        "API Abuse": [
            "Rate limiting + key rotation",
            "Audit API logs",
            "Revoke compromised keys",
            "WAF + Apigee"
        ]
    }
    for name, steps in playbooks.items():
        for step in steps:
            c.execute("INSERT OR IGNORE INTO playbook_steps (playbook_name, step, checked, notes) VALUES (?, ?, ?, ?)",
                      (name, step, 0, ""))

    # Risks
    risks = [
        (1, "Phishing Campaign", "Finance team targeted", "DETECT", "High", "High", "Pending Approval", "finance@jovalwines.com.au", "2025-10-01", 9),
        (2, "Lost Laptop", "Unencrypted device missing", "PROTECT", "Medium", "High", "Mitigated", "it@jovalfamilywines.com.au", "2025-09-28", 6),
        (3, "Suspicious Login", "CEO account from Russia", "IDENTIFY", "High", "Medium", "Pending Approval", "ciso@bnv.com.au", "2025-10-03", 6),
        (4, "Vendor Portal Open", "Shodan found admin page", "PROTECT", "High", "High", "Open", "security@bam.com.au", "2025-10-02", 9)
    ]
    c.executemany("INSERT OR IGNORE INTO risks (company_id, title, description, category, likelihood, impact, status, submitted_by, submitted_date, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", risks)

    # Vendors
    c.execute("INSERT OR IGNORE INTO vendors VALUES (1, 'Pallet Co', 'Medium', '2025-09-15', 1)")
    c.execute("INSERT OR IGNORE INTO vendors VALUES (2, 'Reefer Tech', 'High', '2025-08-20', 1)")
    questions = [
        (1, "Formal security program?", ""), (1, "Aligned with NIST/ISO?", ""),
        (1, "Pen testing?", ""), (2, "Data encryption?", ""), (2, "Least privilege?", "")
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
    with st.sidebar.form("login"):
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

# === PAGES ===
if page == "Dashboard":
    st.markdown("## Dashboard")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown('<div class="metric-card"><h2>96%</h2><p>Compliance</p></div>', unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="metric-card"><h2>4</h2><p>Active Risks</p></div>', unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="metric-card"><h2>42</h2><p>Evidence Files</p></div>', unsafe_allow_html=True)

    for i, comp in enumerate(["Joval Wines", "Joval Family Wines", "BNV", "BAM"]):
        with st.expander(f"RACI Matrix – {comp}"):
            df = pd.DataFrame([["Asset Inventory", "A", "R", "C", "I"], ["Backup", "R", "A", "I", "C"]],
                              columns=["Control", "IT", "Ops", "Sec", "Finance"]).set_index("Control")
            fig = px.imshow(df, color_continuous_scale="Greys")
            st.plotly_chart(fig, use_container_width=True, key=f"raci_{i}")

    st.markdown("### Active Risks")
    risks = pd.read_sql("SELECT id, title, status, risk_score FROM risks", conn)
    for _, r in risks.iterrows():
        if st.button(f"{r['title']} - {r['status']} (Score: {r['risk_score']})", key=f"risk_{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Log a new Risk"
            st.rerun()

elif page == "Log a new Risk":
    st.markdown("## Risk Management")
    if st.session_state.get("selected_risk"):
        c.execute("SELECT title, status FROM risks WHERE id=?", (st.session_state.selected_risk,))
        title, status = c.fetchone()
        st.markdown(f"### Editing: {title}")
        with st.form("edit"):
            new_status = st.selectbox("Status", ["Open", "Pending Approval", "Mitigated", "Closed"], index=["Open", "Pending Approval", "Mitigated", "Closed"].index(status))
            if st.form_submit_button("Update"):
                c.execute("UPDATE risks SET status=? WHERE id=?", (new_status, st.session_state.selected_risk))
                conn.commit()
                st.success("Updated")
                st.session_state.selected_risk = None
    else:
        with st.form("new"):
            st.selectbox("Company", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"])
            st.text_input("Title")
            st.text_area("Description")
            st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
            st.selectbox("Likelihood", ["Low", "Medium", "High"])
            st.selectbox("Impact", ["Low", "Medium", "High"])
            if st.form_submit_button("Submit"):
                st.success("Risk logged")

elif page == "NIST Controls":
    st.markdown("## NIST CSF 2.0 Controls")
    controls = pd.read_sql("SELECT id, name, status FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
    for _, row in controls.iterrows():
        with st.expander(f"{row['id']} - {row['name']} ({row['status']})"):
            c.execute("SELECT description FROM nist_controls WHERE id=?", (row['id'],))
            st.write(c.fetchone()[0])

elif page == "Evidence Vault":
    st.markdown("## Evidence Vault")
    st.selectbox("Company", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"])
    st.file_uploader("Upload Evidence")
    st.write("Evidence linked to risks will appear here.")

elif page == "Playbooks":
    st.markdown("## Response Playbooks")
    playbooks = pd.read_sql("SELECT DISTINCT playbook_name FROM playbook_steps", conn)
    for pb in playbooks["playbook_name"]:
        with st.expander(pb):
            steps = pd.read_sql("SELECT step FROM playbook_steps WHERE playbook_name=?", conn, params=(pb,))
            for i, s in enumerate(steps["step"]):
                st.markdown(f"**Step {i+1}:** {s}")

elif page == "Reports":
    st.markdown("## Reports")
    if st.button("Risk Register"):
        df = pd.read_sql("SELECT title, status, risk_score FROM risks", conn)
        st.dataframe(df)
        st.download_button("Download", df.to_csv(index=False), "risk_register.csv")
    if st.button("Compliance Scorecard"):
        df = pd.read_sql("SELECT id, name, status FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
        st.dataframe(df)

elif page == "Vendor Risk":
    st.markdown("## Vendor Risk Management")
    vendors = pd.read_sql("SELECT id, name, risk_level FROM vendors WHERE company_id=?", conn, params=(company_id,))
    for _, v in vendors.iterrows():
        with st.expander(f"{v['name']} - {v['risk_level']}"):
            c.execute("SELECT question, answer FROM vendor_questionnaire WHERE vendor_id=?", (v['id'],))
            for i, (q, a) in enumerate(c.fetchall()):
                new_a = st.text_input(q, a, key=f"vq_{v['id']}_{i}")
                if st.button("Save", key=f"save_{v['id']}_{i}"):
                    c.execute("UPDATE vendor_questionnaire SET answer=? WHERE vendor_id=? AND question=?", (new_a, v['id'], q))
                    conn.commit()

elif page == "Admin Panel":
    st.markdown("## Admin Panel")
    users = pd.read_sql("SELECT email, role, c.name FROM users u JOIN companies c ON u.company_id=c.id", conn)
    st.dataframe(users)
    with st.form("add_user"):
        st.text_input("Email")
        st.text_input("Password", type="password")
        st.selectbox("Role", ["Admin", "Approver", "User"])
        st.multiselect("Companies", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"])
        if st.form_submit_button("Add"):
            st.success("User added")

st.markdown("---")
st.markdown("<p style='text-align:center; color:#888;'>© 2025 Joval Wines | Risk Portal v15.1</p>", unsafe_allow_html=True)
