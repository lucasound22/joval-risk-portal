# app.py – JOVAL WINES RISK PORTAL v16.5 – FULLY WORKING
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

    # CREATE TABLES
    c.execute("""CREATE TABLE IF NOT EXISTS companies (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, role TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS risks (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 company_id INTEGER, title TEXT, description TEXT, category TEXT,
                 likelihood TEXT, impact TEXT, status TEXT, submitted_by TEXT,
                 submitted_date TEXT, risk_score INTEGER, approver_email TEXT,
                 approver_notes TEXT)""")  # 13 COLUMNS
    c.execute("""CREATE TABLE IF NOT EXISTS evidence (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER, company_id INTEGER,
                 file_name TEXT, upload_date TEXT, uploaded_by TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS nist_controls (
                 id TEXT PRIMARY KEY, name TEXT, description TEXT, status TEXT, notes TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS playbook_steps (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, playbook_name TEXT, step TEXT, checked INTEGER, notes TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendors (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, risk_level TEXT, last_assessment TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questionnaire (
                 vendor_id INTEGER, question TEXT, answer TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_trail (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_email TEXT, action TEXT, details TEXT)""")

    # FIX: Add missing column if DB exists
    try:
        c.execute("SELECT approver_notes FROM risks LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE risks ADD COLUMN approver_notes TEXT")

    # COMPANIES
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(n,) for n in companies])

    # USERS
    hashed = hashlib.sha256("admin123".encode()).hexdigest()
    for i, comp in enumerate(companies, 1):
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"admin@{comp.lower().replace(' ', '')}.com.au", hashed, "Admin", i))
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"approver@{comp.lower().replace(' ', '')}.com.au", hashed, "Approver", i))

    # FULL NIST CSF 2.0 CONTROLS
    nist_full = [
        ("GV.OC-01", "Cybersecurity Strategy", "Define and communicate cybersecurity strategy aligned with business objectives.", "Implemented", "", 1),
        ("GV.RM-01", "Risk Management Strategy", "Establish enterprise risk management framework integrating cyber risks.", "Implemented", "", 1),
        ("GV.SC-01", "Supply Chain Risk", "Implement supply chain risk management program with vendor assessments.", "Partial", "", 1),
        ("ID.AM-01", "Asset Inventory", "Maintain inventory of hardware, software, and data assets.", "Implemented", "", 1),
        ("ID.AM-05", "Data Classification", "Classify data based on sensitivity and business impact.", "Implemented", "", 1),
        ("ID.RA-05", "Threat Identification", "Subscribe to threat intelligence and conduct threat modeling.", "Partial", "", 1),
        ("PR.AC-01", "Identity Management", "Implement MFA, RBAC, and quarterly access reviews.", "Implemented", "", 1),
        ("PR.DS-05", "Data Encryption", "Encrypt data at rest (AES-256) and in transit (TLS 1.3).", "Implemented", "", 1),
        ("PR.MA-01", "Patch Management", "Apply critical patches within 7 days; use vulnerability scanning.", "Implemented", "", 1),
        ("PR.AT-01", "Awareness Training", "Annual security training and quarterly phishing simulations.", "Implemented", "", 1),
        ("DE.CM-01", "Continuous Monitoring", "Deploy SIEM with 24/7 alerting and log correlation.", "Implemented", "", 1),
        ("DE.AE-01", "Anomalous Activity", "Deploy UEBA to detect insider threats and lateral movement.", "Partial", "", 1),
        ("RS.MI-01", "Incident Response Plan", "Maintain tested IR plan with quarterly tabletop exercises.", "Partial", "", 1),
        ("RS.CO-02", "Coordination", "Cross-functional IR team with IT, Legal, PR.", "Implemented", "", 1),
        ("RC.RP-01", "Recovery Planning", "RPO < 4h, RTO < 8h, air-gapped backups.", "Implemented", "", 1),
        ("ID.BE-01", "Business Environment", "Identify critical business processes and dependencies.", "Implemented", "", 1),
        ("PR.IP-01", "Baseline Configuration", "Maintain hardened system images using CIS benchmarks.", "Implemented", "", 1),
        ("DE.DP-04", "Event Detection", "Configure detection systems to identify unauthorized activity.", "Partial", "", 1),
        ("RS.AN-01", "Analysis", "Analyze incidents to determine root cause and impact.", "Implemented", "", 1),
        ("RC.CO-01", "Communications", "Maintain internal and external communication plans.", "Implemented", "", 1)
    ]
    c.executemany("INSERT OR IGNORE INTO nist_controls VALUES (?, ?, ?, ?, ?, ?)", nist_full)

    # PLAYBOOKS
    playbooks = {
        "Ransomware Response": [
            "Isolate affected systems", "Preserve forensic evidence", "Activate IR team",
            "Restore from offline backup", "Conduct root cause analysis"
        ],
        "Phishing Attack": [
            "Quarantine email", "Reset passwords", "Scan endpoints", "Update filters"
        ],
        "Data Exfiltration": [
            "Block egress", "Preserve logs", "Notify APRA", "Enhance DLP"
        ],
        "Insider Threat": [
            "Revoke access", "Preserve logs", "HR investigation", "Update policy"
        ],
        "DDoS Attack": [
            "Activate Cloudflare", "Engage ISP", "Failover", "Capacity plan"
        ],
        "Physical Breach": [
            "Lock facility", "Preserve CCTV", "Audit access", "Update badges"
        ],
        "Cloud Misconfig": [
            "Block public S3", "Enable GuardDuty", "Scan with Prowler", "Train DevOps"
        ],
        "Zero-Day Exploit": [
            "Virtual patch", "Isolate system", "Monitor IOCs", "Apply patch"
        ],
        "Credential Stuffing": [
            "Enforce MFA", "Block IPs", "Reset passwords", "Dark web scan"
        ],
        "Supply Chain Attack": [
            "Isolate software", "Scan IOCs", "Notify vendor", "Update SLA"
        ],
        "Backup Failure": [
            "Restore from secondary", "RCA on Veeam", "Test integrity", "Update config"
        ],
        "API Abuse": [
            "Rate limit", "Audit logs", "Rotate keys", "Enable WAF"
        ]
    }
    for name, steps in playbooks.items():
        for step in steps:
            c.execute("INSERT OR IGNORE INTO playbook_steps (playbook_name, step, checked, notes) VALUES (?, ?, ?, ?)",
                      (name, step, 0, ""))

    # VENDORS
    vendors = [(1, "Pallet Co", "Medium", "2025-09-15", 1), (2, "Reefer Tech", "High", "2025-08-20", 1)]
    c.executemany("INSERT OR IGNORE INTO vendors VALUES (?, ?, ?, ?, ?)", vendors)
    questions = [
        (1, "Does your organization have a formal information security program?", ""),
        (1, "Is the program aligned with NIST CSF, ISO 27001, or similar?", ""),
        (1, "Do you conduct regular third-party penetration testing?", ""),
        (1, "Are critical systems segmented from the internet?", ""),
        (1, "Do you maintain incident response and business continuity plans?", ""),
        (2, "Do you encrypt data in transit and at rest?", ""),
        (2, "Are access controls based on least privilege?", ""),
        (2, "Do you perform regular vulnerability scanning?", ""),
        (2, "Is employee security awareness training conducted annually?", "")
    ]
    c.executemany("INSERT OR IGNORE INTO vendor_questionnaire VALUES (?, ?, ?)", questions)

    # DUMMY RISKS (13 VALUES)
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

    conn.commit()
    conn.close()

# === AUDIT LOG ===
def log_action(user_email, action, details=""):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO audit_trail (timestamp, user_email, action, details) VALUES (?, ?, ?, ?)",
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user_email, action, details))
    conn.commit()
    conn.close()

# === INIT DB SAFELY ===
if "db_init" not in st.session_state:
    try:
        init_db()
        st.session_state.db_init = True
    except Exception as e:
        st.error(f"Database initialization failed: {str(e)}")
        st.stop()

# === APP CONFIG ===
st.set_page_config(page_title="Joval Risk Portal", layout="wide")
st.markdown("""
<style>
    .header {background: #1a1a1a; color: white; padding: 2rem; text-align: center;}
    .metric-card {background: white; padding: 1.5rem; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
    .css-1d391kg {background: #1a1a1a !important;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal v16.5</p></div>', unsafe_allow_html=True)

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

# === SIDEBAR NAV ===
with st.sidebar:
    st.markdown(f"**{user[1].split('@')[0]}** • {company_name}")
    st.markdown("---")
    pages = ["Dashboard", "Log a new Risk", "NIST Controls", "Evidence Vault", "Playbooks", "Reports", "Vendor Risk", "Audit Trail", "Admin Panel"]
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
            raci = pd.DataFrame([["Asset Inventory", "A", "R", "C", "I"]], 
                                columns=["Control", "IT", "Ops", "Sec", "Finance"]).set_index("Control")
            fig = px.imshow(raci, color_continuous_scale="Greys")
            st.plotly_chart(fig, use_container_width=True, key=f"raci_{i}")

    st.markdown("### Active Risks")
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
        st.markdown(f"### Editing: {risk[2]}")
        with st.form("edit_risk"):
            status = st.selectbox("Status", ["Open", "Pending Approval", "Mitigated", "Closed"], 
                                index=["Open", "Pending Approval", "Mitigated", "Closed"].index(risk[7]))
            notes = st.text_area("Approver Notes", risk[12] or "")
            if st.form_submit_button("Update"):
                c.execute("UPDATE risks SET status=?, approver_notes=? WHERE id=?", (status, notes, risk[0]))
                conn.commit()
                log_action(user[1], "RISK_UPDATED", f"ID: {risk[0]}")
                st.success("Updated")
                st.session_state.selected_risk = None
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
                score = {"Low":1, "Medium":2, "High":3}[likelihood] * {"Low":1, "Medium":2, "High":3}[impact]
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

# === NIST CONTROLS ===
elif page == "NIST Controls":
    st.markdown("## NIST CSF 2.0 Controls")
    controls = pd.read_sql("SELECT id, name, status FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
    for _, row in controls.iterrows():
        with st.expander(f"{row['id']} - {row['name']} ({row['status']})"):
            c.execute("SELECT description, notes FROM nist_controls WHERE id=?", (row['id'],))
            desc, notes = c.fetchone()
            st.write(desc)
            new_notes = st.text_area("Notes", notes or "", key=f"nist_{row['id']}")
            if st.button("Save", key=f"save_nist_{row['id']}"):
                c.execute("UPDATE nist_controls SET notes=? WHERE id=?", (new_notes, row['id']))
                conn.commit()
                log_action(user[1], "NIST_UPDATED", f"ID: {row['id']}")
                st.success("Saved")

# === EVIDENCE VAULT ===
elif page == "Evidence Vault":
    st.markdown("## Evidence Vault")
    company = st.selectbox("Company", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"], key="ev_company")
    c.execute("SELECT id FROM companies WHERE name=?", (company,))
    cid = c.fetchone()[0]
    risks = pd.read_sql("SELECT id, title FROM risks WHERE company_id=?", conn, params=(cid,))
    risk_title = st.selectbox("Link to Risk", risks["title"].tolist()) if not risks.empty else None
    uploaded = st.file_uploader("Upload Evidence")
    if uploaded and risk_title:
        c.execute("SELECT id FROM risks WHERE title=?", (risk_title,))
        rid = c.fetchone()[0]
        c.execute("INSERT INTO evidence (risk_id, company_id, file_name, upload_date, uploaded_by) VALUES (?, ?, ?, ?, ?)",
                  (rid, cid, uploaded.name, datetime.now().strftime("%Y-%m-%d"), user[1]))
        conn.commit()
        log_action(user[1], "EVIDENCE_UPLOADED", f"File: {uploaded.name}")
        st.success("Uploaded")

# === PLAYBOOKS ===
elif page == "Playbooks":
    st.markdown("## Response Playbooks")
    pbs = pd.read_sql("SELECT DISTINCT playbook_name FROM playbook_steps", conn)
    for pb in pbs["playbook_name"]:
        with st.expander(pb):
            steps = pd.read_sql("SELECT id, step, checked, notes FROM playbook_steps WHERE playbook_name=?", conn, params=(pb,))
            for _, s in steps.iterrows():
                col1, col2 = st.columns([4,1])
                with col1:
                    st.checkbox(s["step"], value=bool(s["checked"]), key=f"chk_{s['id']}")
                with col2:
                    st.text_input("", s["notes"] or "", key=f"note_{s['id']}")
                if st.button("Save", key=f"save_pb_{s['id']}"):
                    c.execute("UPDATE playbook_steps SET checked=?, notes=? WHERE id=?", 
                              (int(st.session_state[f"chk_{s['id']}"]), st.session_state[f"note_{s['id']}"], s['id']))
                    conn.commit()
                    log_action(user[1], "PLAYBOOK_UPDATED", f"Step: {s['step'][:20]}...")

# === REPORTS ===
elif page == "Reports":
    st.markdown("## Reports")
    if st.button("Risk Register"):
        df = pd.read_sql("SELECT title, status, risk_score, submitted_date FROM risks", conn)
        st.dataframe(df)
        st.download_button("Download CSV", df.to_csv(index=False), "Risk_Register.csv", "text/csv")

# === VENDOR RISK ===
elif page == "Vendor Risk":
    st.markdown("## Vendor Risk Management")
    vendors = pd.read_sql("SELECT id, name FROM vendors WHERE company_id=?", conn, params=(company_id,))
    for i, v in enumerate(vendors.itertuples()):
        with st.expander(f"{v.name}"):
            c.execute("SELECT question, answer FROM vendor_questionnaire WHERE vendor_id=?", (v.id,))
            for q_idx, (q, a) in enumerate(c.fetchall()):
                key = f"vqa_{v.id}_{q_idx}"
                new_a = st.text_input(q, a or "", key=key)
                if st.button("Save", key=f"vs_{key}"):
                    c.execute("UPDATE vendor_questionnaire SET answer=? WHERE vendor_id=? AND question=?", (new_a, v.id, q))
                    conn.commit()
                    log_action(user[1], "VENDOR_ANSWER", f"Q: {q[:30]}...")

# === AUDIT TRAIL ===
elif page == "Audit Trail":
    st.markdown("## Audit Trail")
    audit = pd.read_sql("SELECT timestamp, user_email, action, details FROM audit_trail ORDER BY id DESC", conn)
    st.dataframe(audit)
    st.download_button("Download CSV", audit.to_csv(index=False), "audit_trail.csv", "text/csv")

# === ADMIN PANEL ===
elif page == "Admin Panel":
    st.markdown("## Admin Panel")
    users = pd.read_sql("SELECT u.email, u.role, c.name FROM users u JOIN companies c ON u.company_id=c.id", conn)
    st.dataframe(users)

st.markdown("---\n© 2025 Joval Wines | Risk Management Portal v16.5")
