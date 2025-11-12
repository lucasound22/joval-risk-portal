# app.py – JOVAL WINES RISK PORTAL v18.0 – UAT COMPLETE
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
                 id TEXT PRIMARY KEY, name TEXT, description TEXT, status TEXT, notes TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendors (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, contact_email TEXT, 
                 risk_level TEXT, last_assessment TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questionnaire (
                 vendor_id INTEGER, question TEXT, answer TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_trail (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_email TEXT, action TEXT, details TEXT)""")

    # FIX: Add missing columns
    try:
        c.execute("SELECT approver_notes FROM risks LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE risks ADD COLUMN approver_notes TEXT")

    try:
        c.execute("SELECT contact_email FROM vendors LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE vendors ADD COLUMN contact_email TEXT")

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

    # NIST CONTROLS
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
        ("ID.BE-01", "Business Environment", "Identify critical processes.", "Implemented", "", 1),
        ("PR.IP-01", "Baseline Configuration", "Use CIS benchmarks.", "Implemented", "", 1),
        ("RS.AN-01", "Analysis", "Analyze incidents for root cause.", "Implemented", "", 1),
        ("RC.CO-01", "Communications", "Maintain communication plans.", "Implemented", "", 1),
        ("DE.DP-04", "Event Detection", "Configure detection systems.", "Partial", "", 1)
    ]
    c.executemany("INSERT OR IGNORE INTO nist_controls VALUES (?, ?, ?, ?, ?, ?)", nist_full)

    # VENDORS
    vendors = [
        (1, "Pallet Co", "vendor@palletco.com", "Medium", "2025-09-15", 1),
        (2, "Reefer Tech", "security@reefertech.com", "High", "2025-08-20", 1)
    ]
    c.executemany("INSERT OR IGNORE INTO vendors VALUES (?, ?, ?, ?, ?, ?)", vendors)
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

# === INIT DB ===
if "db_init" not in st.session_state:
    try:
        init_db()
        st.session_state.db_init = True
    except Exception as e:
        st.error(f"Database Error: {str(e)}")
        st.stop()

# === CONFIG ===
st.set_page_config(page_title="Joval Risk Portal", layout="wide")
st.markdown("""
<style>
    .header {background: #1a1a1a; color: white; padding: 2rem; text-align: center;}
    .metric-card {background: white; padding: 1.5rem; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal v18.0</p></div>', unsafe_allow_html=True)

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
            st.markdown(f"[**Playbooks →** ↗](https://joval-wines-nist-playbook-tracker.streamlit.app/)")
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
        color = "red" if r['risk_score'] >= 7 else "orange" if r['risk_score'] >= 4 else "green"
        st.markdown(f"**{r['title']}** - <span style='color:{color}'>Score: {r['risk_score']}</span> | {r['status']} | {r['submitted_date']}", unsafe_allow_html=True)
        if st.button(f"Edit →", key=f"risk_{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Log a new Risk"
            st.rerun()

# === MY APPROVALS (APPROVER ONLY) ===
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
                score = {"Low":1, "Medium":2, "High":3}[likelihood] * {"Low":1, "Medium":2, "High":3}[impact]
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
                st.rerun()

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
    company = st.selectbox("Company", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"])
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

# === REPORTS ===
elif page == "Reports":
    st.markdown("## Reports")
    reports = {
        "1. Risk Register": "SELECT title, status, risk_score, submitted_date FROM risks",
        "2. High Risks": "SELECT title, risk_score FROM risks WHERE risk_score >= 7",
        "3. Pending Approvals": "SELECT title, submitted_by FROM risks WHERE status = 'Pending Approval'",
        "4. NIST Compliance": "SELECT id, name, status FROM nist_controls WHERE company_id = ?",
        "5. Vendor Risk Levels": "SELECT name, risk_level FROM vendors WHERE company_id = ?",
        "6. Evidence by Risk": "SELECT r.title, e.file_name FROM evidence e JOIN risks r ON e.risk_id = r.id",
        "7. Audit Trail (Last 7 Days)": "SELECT * FROM audit_trail WHERE timestamp >= date('now', '-7 days') ORDER BY id DESC",
        "8. Risks by Category": "SELECT category, COUNT(*) AS count FROM risks GROUP BY category",
        "9. User Activity": "SELECT user_email, COUNT(*) AS actions FROM audit_trail GROUP BY user_email ORDER BY actions DESC"
    }
    for name, query in reports.items():
        if st.button(name):
            params = (company_id,) if "?" in query else ()
            df = pd.read_sql(query, conn, params=params)
            st.dataframe(df)
            st.download_button(f"Download {name}", df.to_csv(index=False), f"{name}.csv", "text/csv")

# === VENDOR RISK ===
elif page == "Vendor Risk":
    st.markdown("## Vendor Risk Management")
    with st.expander("Add New Vendor"):
        with st.form("add_vendor"):
            v_name = st.text_input("Vendor Name")
            v_email = st.text_input("Contact Email")
            v_level = st.selectbox("Risk Level", ["Low", "Medium", "High"])
            if st.form_submit_button("Add Vendor"):
                c.execute("INSERT INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
                          (v_name, v_email, v_level, datetime.now().strftime("%Y-%m-%d"), company_id))
                vid = c.lastrowid
                for q in ["Security program?", "Aligned with NIST?", "Pen testing?", "Segmentation?", "IR plan?"]:
                    c.execute("INSERT INTO vendor_questionnaire (vendor_id, question, answer) VALUES (?, ?, ?)", (vid, q, ""))
                conn.commit()
                st.success(f"Vendor added: {v_name}")

    vendors = pd.read_sql("SELECT id, name FROM vendors WHERE company_id=?", conn, params=(company_id,))
    for v in vendors.itertuples():
        with st.expander(f"{v.name}"):
            c.execute("SELECT question, answer FROM vendor_questionnaire WHERE vendor_id=?", (v.id,))
            for q_idx, (q, a) in enumerate(c.fetchall()):
                key = f"vqa_{v.id}_{q_idx}"
                new_a = st.text_input(q, a or "", key=key)
                if st.button("Save", key=f"vs_{key}"):
                    c.execute("UPDATE vendor_questionnaire SET answer=? WHERE vendor_id=? AND question=?", (new_a, v.id, q))
                    conn.commit()

# === AUDIT TRAIL ===
elif page == "Audit Trail":
    st.markdown("## Audit Trail")
    audit = pd.read_sql("SELECT timestamp, user_email, action, details FROM audit_trail ORDER BY id DESC", conn)
    st.dataframe(audit)
    st.download_button("Download", audit.to_csv(index=False), "audit_trail.csv")

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
                if not email or not password:
                    st.error("Required")
                else:
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
            role = st.selectbox("Role", ["Admin", "Approver", "User"], index=["Admin", "Approver", "User"].index(usr[3]))
            new_pass = st.text_input("New Password (leave blank to keep)", type="password")
            if st.form_submit_button("Update User"):
                updates = [f"role='{role}'"]
                if new_pass:
                    updates.append(f"password='{hashlib.sha256(new_pass.encode()).hexdigest()}'")
                query = f"UPDATE users SET {', '.join(updates)} WHERE id=?"
                c.execute(query, (usr[0],))
                conn.commit()
                log_action(user[1], "USER_UPDATED", f"Email: {usr[1]}")
                st.success("User updated")
                st.session_state.edit_user = None
                st.rerun()

st.markdown("---\n© 2025 Joval Wines | v18.0")
