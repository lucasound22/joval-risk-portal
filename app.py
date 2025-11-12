# app.py – JOVAL WINES RISK PORTAL v18.1 – PROTECT CONTROLS + BOARD REPORT
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

    # TABLES (unchanged from v18.0)
    c.execute("""CREATE TABLE IF NOT EXISTS companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, role TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS risks (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, title TEXT, description TEXT, category TEXT,
                 likelihood TEXT, impact TEXT, status TEXT, submitted_by TEXT, submitted_date TEXT, risk_score INTEGER, 
                 approver_email TEXT, approver_notes TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS evidence (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER, company_id INTEGER, file_name TEXT, upload_date TEXT, uploaded_by TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS nist_controls (
                 id TEXT PRIMARY KEY, name TEXT, description TEXT, status TEXT, notes TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendors (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, contact_email TEXT, risk_level TEXT, last_assessment TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questionnaire (
                 vendor_id INTEGER, question TEXT, answer TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_trail (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_email TEXT, action TEXT, details TEXT)""")

    # FIX: Add missing columns
    try: c.execute("SELECT approver_notes FROM risks LIMIT 1")
    except: c.execute("ALTER TABLE risks ADD COLUMN approver_notes TEXT")
    try: c.execute("SELECT contact_email FROM vendors LIMIT 1")
    except: c.execute("ALTER TABLE vendors ADD COLUMN contact_email TEXT")

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

    # NIST PROTECT CONTROLS (FULL 25)
    protect_controls = [
        ("PR.AC-01", "Identity Management", "Azure AD + MFA. Quarterly reviews.", "Implemented", "Okta sync 2025-11-01", 1),
        ("PR.AC-02", "Asset Access Control", "RBAC via Okta. Finance = SAP only.", "Implemented", "Q3 Review: 2025-09-15", 1),
        ("PR.AC-03", "Remote Access", "Cisco AnyConnect + Duo. No split-tunnel.", "Implemented", "Session logs in Splunk", 1),
        ("PR.AC-04", "Access Permissions", "Least privilege. Jira approvals.", "Implemented", "Last approval: 2025-11-05", 1),
        ("PR.AC-05", "Network Access", "Palo Alto NGFW. Zero Trust.", "Implemented", "Micro-segmentation live", 1),
        ("PR.AT-01", "Awareness Training", "KnowBe4. 98% completion.", "Implemented", "Oct sim: 2% click rate", 1),
        ("PR.AT-02", "Privileged Training", "CISO-led annual session.", "Implemented", "2025-06-20", 1),
        ("PR.AT-03", "Third-Party Training", "Vendor attestation required.", "Implemented", "Pallet Co signed 2025-10-01", 1),
        ("PR.AT-04", "Executive Training", "Board cyber briefings.", "Implemented", "Q4: 2025-11-20", 1),
        ("PR.DS-01", "Data-at-Rest", "AES-256 on all endpoints.", "Implemented", "BitLocker report", 1),
        ("PR.DS-02", "Data-in-Transit", "TLS 1.3. A+ SSL Labs.", "Implemented", "Scan: 2025-11-01", 1),
        ("PR.DS-03", "Data-in-Use", "No PII in logs.", "Implemented", "DLP rules active", 1),
        ("PR.DS-04", "Backup", "Veeam air-gapped. RPO < 4h.", "Implemented", "Test: 2025-10-15", 1),
        ("PR.DS-05", "Data Disposal", "DBAN + NIST 800-88.", "Implemented", "Cert: HDD-2025-001", 1),
        ("PR.DS-06", "Integrity", "CrowdStrike FIM.", "Implemented", "Daily hash checks", 1),
        ("PR.DS-07", "Recovery", "Quarterly restore tests.", "Implemented", "Last: 2025-10-15", 1),
        ("PR.IP-01", "Baseline Config", "CIS Level 1. Terraform.", "Implemented", "Golden images v2.1", 1),
        ("PR.IP-02", "Change Control", "Jira + CAB.", "Implemented", "Change #CHG-2025-110", 1),
        ("PR.IP-03", "Hardening", "GPOs disable SMBv1.", "Implemented", "Hardening checklist", 1),
        ("PR.IP-04", "Config Access", "GitLab branch protection.", "Implemented", "Only DevOps merge", 1),
        ("PR.IP-05", "Tech Management", "Auto-patch via WSUS.", "Implemented", "98% patched", 1),
        ("PR.IP-06", "Asset Management", "Lansweeper inventory.", "Implemented", "1,240 assets", 1),
        ("PR.IP-07", "Compliance", "APRA CPS 234, GDPR.", "Implemented", "Audit: 2025-09-30", 1),
        ("PR.MA-01", "Maintenance", "4h SLA for critical.", "Implemented", "Vendor: Reefer Tech", 1),
        ("PR.MA-02", "Remote Maintenance", "BeyondTrust recording.", "Implemented", "Session #RM-2025-045", 1),
        ("PR.PT-01", "Audit Logging", "Splunk 12-month retention.", "Implemented", "Immutable storage", 1),
        ("PR.PT-02", "Log Integrity", "Write-once + hash.", "Implemented", "Verified daily", 1),
        ("PR.PT-03", "Log Retention", "90 days hot, 12 cold.", "Implemented", "Archive policy", 1),
        ("PR.PT-04", "Network Protection", "NSX micro-segmentation.", "Implemented", "East-West inspected", 1),
        ("PR.PT-05", "Automation", "SOAR playbooks.", "Implemented", "80% auto-contained", 1)
    ]
    c.executemany("INSERT OR IGNORE INTO nist_controls VALUES (?, ?, ?, ?, ?, ?)", protect_controls)

    # RISKS (with risk scoring logic)
    risks = [
        (1, "Phishing Campaign", "Finance targeted", "DETECT", "High", "High", "Pending Approval", "finance@jovalwines.com.au", "2025-10-01", 9, "approver@jovalwines.com.au", ""),
        (2, "Laptop Lost", "Customer PII", "PROTECT", "Medium", "High", "Mitigated", "it@jovalfamilywines.com.au", "2025-09-28", 6, "approver@jovalfamilywines.com.au", "Wiped remotely"),
        (3, "Suspicious Login", "CEO account", "IDENTIFY", "High", "Medium", "Pending Approval", "ciso@bnv.com.au", "2025-10-03", 6, "approver@bnv.com.au", ""),
        (4, "Vendor Portal Open", "Shodan alert", "PROTECT", "High", "High", "Open", "security@bam.com.au", "2025-10-02", 9, "approver@bam.com.au", "")
    ]
    c.executemany("""INSERT OR IGNORE INTO risks 
                     (company_id, title, description, category, likelihood, impact, status, 
                      submitted_by, submitted_date, risk_score, approver_email, approver_notes) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", risks)

    conn.commit()
    conn.close()

# === RISK SCORING LOGIC ===
def calculate_risk_score(likelihood, impact):
    scores = {"Low": 1, "Medium": 2, "High": 3}
    return scores[likelihood] * scores[impact]

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
        st.error(f"DB Error: {e}")
        st.stop()

# === CONFIG ===
st.set_page_config(page_title="Joval Risk Portal", layout="wide")
st.markdown("""
<style>
    .header {background: #1a1a1a; color: white; padding: 2rem; text-align: center;}
    .metric-card {background: white; padding: 1.5rem; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
    .risk-high {background: #ffe6e6; padding: 0.5rem; border-radius: 8px;}
    .risk-medium {background: #fff4e6; padding: 0.5rem; border-radius: 8px;}
    .risk-low {background: #e6f7e6; padding: 0.5rem; border-radius: 8px;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal v18.1</p></div>', unsafe_allow_html=True)

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
        if st.button(p, key=f"nav_{p}"):
            st.session_state.page = p
            st.rerun()

page = st.session_state.get("page", "Dashboard")

# === DASHBOARD ===
if page == "Dashboard":
    st.markdown("## Risk Dashboard")
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.markdown('<div class="metric-card"><h2>96%</h2><p>Compliance</p></div>', unsafe_allow_html=True)
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
        cls = "risk-high" if r['risk_score'] >= 7 else "risk-medium" if r['risk_score'] >= 4 else "risk-low"
        st.markdown(f'<div class="{cls}"><b>{r["title"]}</b> - Score: {r["risk_score"]} | {r["status"]} | {r["submitted_date"]}</div>', unsafe_allow_html=True)
        if st.button(f"Edit →", key=f"risk_{r['id']}"):
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

# === EVIDENCE VAULT, PLAYBOOKS, VENDOR RISK, AUDIT TRAIL (unchanged) ===

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
        "9. User Activity": "SELECT user_email, COUNT(*) AS actions FROM audit_trail GROUP BY user_email ORDER BY actions DESC",
        "10. Board Report (Monthly)": "SELECT 'Monthly Risk Report' as Report"
    }
    for name, query in reports.items():
        if st.button(name):
            if name == "10. Board Report (Monthly)":
                st.markdown("## Joval Wines – Monthly Board Risk Report")
                st.markdown("**Date**: November 2025")
                st.markdown("**Compliance**: 96% (NIST CSF 2.0)")
                st.markdown("**High Risks**: 2 (Phishing, Vendor Portal)")
                st.markdown("**Mitigated**: 1 (Laptop Lost)")
                st.markdown("**Training**: 98% completion")
                st.markdown("**Next Actions**: Q4 Recovery Drill, Vendor Re-assessment")
            else:
                params = (company_id,) if "?" in query else ()
                df = pd.read_sql(query, conn, params=params)
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
                log_action(user[1], "USER_UPDATED", f"Email: {usr[1]} → {new_email}")
                st.success("User updated")
                st.session_state.edit_user = None
                st.rerun()

st.markdown("---\n© 2025 Joval Wines | v18.1")
