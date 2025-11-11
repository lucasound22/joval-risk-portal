# app.py – v16.0 STREAMLIT CLOUD READY
import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
from datetime import datetime
import hashlib

# === INIT DB ===
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

    # Companies
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(n,) for n in companies])

    # Users
    hashed = hashlib.sha256("admin123".encode()).hexdigest()
    for i, comp in enumerate(companies, 1):
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"admin@{comp.lower().replace(' ', '')}.com.au", hashed, "Admin", i))

    # NIST Controls
    nist_data = [
        ("ID.SC-02", "Supply Chain Risk", "Establish supply chain risk management program with vendor assessments, SOC 2, and SBOMs.", "Partial", "", 1),
        ("PR.AC-01", "Identity Management", "Implement MFA, RBAC, and quarterly access reviews.", "Implemented", "", 1),
        ("PR.DS-05", "Data Encryption", "Encrypt data at rest (AES-256) and in transit (TLS 1.3).", "Implemented", "", 1),
        ("DE.CM-01", "Continuous Monitoring", "Deploy SIEM with 24/7 alerting and log correlation.", "Implemented", "", 1),
        ("RS.MI-01", "Incident Response", "Maintain tested IR plan with quarterly tabletop exercises.", "Partial", "", 1),
        ("RC.RP-01", "Recovery Planning", "RPO < 4h, RTO < 8h, air-gapped backups.", "Implemented", "", 1)
    ]
    c.executemany("INSERT OR IGNORE INTO nist_controls VALUES (?, ?, ?, ?, ?, ?)", nist_data)

    # Playbooks (12)
    playbooks = {
        "Ransomware Response": ["Isolate systems", "Preserve evidence", "Activate IR team", "Restore backup"],
        "Phishing Attack": ["Quarantine email", "Reset passwords", "Scan endpoints", "Update filters"],
        "Data Exfiltration": ["Block egress", "Preserve logs", "Notify APRA", "Enhance DLP"],
        "Insider Threat": ["Revoke access", "Preserve logs", "HR investigation", "Update policy"],
        "DDoS Attack": ["Activate Cloudflare", "Engage ISP", "Failover", "Capacity plan"],
        "Physical Breach": ["Lock facility", "Preserve CCTV", "Audit access", "Update badges"],
        "Cloud Misconfig": ["Block public S3", "Enable GuardDuty", "Scan with Prowler", "Train DevOps"],
        "Zero-Day Exploit": ["Virtual patch", "Isolate system", "Monitor IOCs", "Apply patch"],
        "Credential Stuffing": ["Enforce MFA", "Block IPs", "Reset passwords", "Dark web scan"],
        "Supply Chain Attack": ["Isolate software", "Scan IOCs", "Notify vendor", "Update SLA"],
        "Backup Failure": ["Restore from secondary", "RCA on Veeam", "Test integrity", "Update config"],
        "API Abuse": ["Rate limit", "Audit logs", "Rotate keys", "Enable WAF"]
    }
    for name, steps in playbooks.items():
        for step in steps:
            c.execute("INSERT OR IGNORE INTO playbook_steps (playbook_name, step, checked, notes) VALUES (?, ?, ?, ?)",
                      (name, step, 0, ""))

    # Risks
    risks = [
        (1, "Phishing Campaign", "Finance targeted", "DETECT", "High", "High", "Pending Approval", "finance@jovalwines.com.au", "2025-10-01", 9),
        (2, "Laptop Lost", "Customer PII", "PROTECT", "Medium", "High", "Mitigated", "it@jovalfamilywines.com.au", "2025-09-28", 6),
        (3, "Suspicious Login", "CEO account", "IDENTIFY", "High", "Medium", "Pending Approval", "ciso@bnv.com.au", "2025-10-03", 6),
        (4, "Vendor Portal Open", "Shodan alert", "PROTECT", "High", "High", "Open", "security@bam.com.au", "2025-10-02", 9)
    ]
    c.executemany("INSERT OR IGNORE INTO risks (company_id, title, description, category, likelihood, impact, status, submitted_by, submitted_date, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", risks)

    conn.commit()
    conn.close()

# === INIT ===
if "db_init" not in st.session_state:
    init_db()
    st.session_state.db_init = True

st.set_page_config(page_title="Joval Risk Portal", layout="wide")
st.markdown("""
<style>
    .header {background: #1a1a1a; color: white; padding: 2rem; text-align: center;}
    .metric-card {background: white; padding: 1.5rem; border-radius: 12px; text-align: center; cursor f: pointer;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal</p></div>', unsafe_allow_html=True)

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

    # RACI x4
    for i, comp in enumerate(["Joval Wines", "Joval Family Wines", "BNV", "BAM"]):
        with st.expander(f"RACI – {comp}"):
            raci = pd.DataFrame([["Asset Inventory", "A", "R", "C", "I"]], columns=["Control", "IT", "Ops", "Sec", "Finance"]).set_index("Control")
            fig = px.imshow(raci, color_continuous_scale="Greys")
            st.plotly_chart(fig, use_container_width=True, key=f"raci_{i}")

    # Risks
    risks = pd.read_sql("SELECT id, title, status, risk_score FROM risks", conn)
    for _, r in risks.iterrows():
        if st.button(f"{r['title']} - {r['status']} (Score: {r['risk_score']})", key=f"risk_{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Log a new Risk"
            st.rerun()

# === LOG A NEW RISK ===
elif page == "Log a new Risk":
    st.markdown("## Risk Management")
    if st.session_state.get("selected_risk"):
        c.execute("SELECT * FROM risks WHERE id=?", (st.session_state.selected_risk,))
        risk = c.fetchone()
        with st.form("edit"):
            status = st.selectbox("Status", ["Open", "Pending Approval", "Mitigated", "Closed"], index=["Open", "Pending Approval", "Mitigated", "Closed"].index(risk[7]))
            if st.form_submit_button("Update"):
                c.execute("UPDATE risks SET status=? WHERE id=?", (status, risk[0]))
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

# === NIST CONTROLS ===
elif page == "NIST Controls":
    st.markdown("## NIST Controls")
    controls = pd.read_sql("SELECT id, name, status FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
    for _, row in controls.iterrows():
        with st.expander(f"{row['id']} - {row['name']}"):
            c.execute("SELECT description FROM nist_controls WHERE id=?", (row['id'],))
            st.write(c.fetchone()[0])

# === PLAYBOOKS ===
elif page == "Playbooks":
    st.markdown("## Playbooks")
    pbs = pd.read_sql("SELECT DISTINCT playbook_name FROM playbook_steps", conn)
    for pb in pbs["playbook_name"]:
        with st.expander(pb):
            steps = pd.read_sql("SELECT step FROM playbook_steps WHERE playbook_name=?", conn, params=(pb,))
            for i, s in enumerate(steps["step"]):
                st.markdown(f"**Step {i+1}:** {s}")

# === REPORTS ===
elif page == "Reports":
    st.markdown("## Reports")
    if st.button("Risk Register"):
        df = pd.read_sql("SELECT title, status, risk_score FROM risks", conn)
        st.dataframe(df)
        st.download_button("Download", df.to_csv(index=False), "Risk_Register.csv")

# === VENDOR RISK ===
elif page == "Vendor Risk":
    st.markdown("## Vendor Risk")
    vendors = pd.read_sql("SELECT id, name FROM vendors WHERE company_id=?", conn, params=(company_id,))
    for i, v in enumerate(vendors.itertuples()):
        with st.expander(v.name):
            c.execute("SELECT question, answer FROM vendor_questionnaire WHERE vendor_id=?", (v.id,))
            for q_idx, (q, a) in enumerate(c.fetchall()):
                st.text_input(q, a, key=f"vq_{v.id}_{q_idx}")

# === ADMIN ===
elif page == "Admin Panel":
    st.markdown("## Admin Panel")
    users = pd.read_sql("SELECT u.email, u.role, c.name FROM users u JOIN companies c ON u.company_id=c.id", conn)
    st.dataframe(users)

st.markdown("---\n© 2025 Joval Wines | v16.0")
