import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
from datetime import datetime
import hashlib
import os

DB_PATH = "joval_portal.db"

# === INIT DB ===
def get_db():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    """Initialise DB and seed required baseline data safely."""
    conn = get_db()
    cur = conn.cursor()

    # tables
    cur.execute("""
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT,
            company_id INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS risks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER,
            title TEXT,
            description TEXT,
            category TEXT,
            likelihood TEXT,
            impact TEXT,
            status TEXT,
            submitted_by TEXT,
            submitted_date TEXT,
            risk_score INTEGER,
            approver_email TEXT,
            approver_notes TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            risk_id INTEGER,
            company_id INTEGER,
            file_name TEXT,
            upload_date TEXT,
            uploaded_by TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nist_controls (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            status TEXT,
            notes TEXT,
            company_id INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS playbook_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_name TEXT,
            step TEXT,
            checked INTEGER,
            notes TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            risk_level TEXT,
            last_assessment TEXT,
            company_id INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vendor_questionnaire (
            vendor_id INTEGER,
            question TEXT,
            answer TEXT
        )
    """)

    # seed companies (4)
    seed_companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    for comp in seed_companies:
        cur.execute("INSERT OR IGNORE INTO companies (name) VALUES (?)", (comp,))

    # seed admin + approver per company (use a simple hashed password)
    default_pass = "admin123"
    hashed = hashlib.sha256(default_pass.encode()).hexdigest()
    cur.execute("SELECT id, name FROM companies")
    rows = cur.fetchall()
    for row in rows:
        cid = row[0]
        cname = row[1]
        admin_email = f"admin@{cname.lower().replace(' ', '')}.com.au"
        approver_email = f"approver@{cname.lower().replace(' ', '')}.com.au"
        cur.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                    (admin_email, hashed, "Admin", cid))
        cur.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                    (approver_email, hashed, "Approver", cid))

    # Optional: seed a sample risk to make the dashboard show clickable items
    cur.execute("SELECT id FROM companies LIMIT 1")
    first_c = cur.fetchone()
    if first_c:
        first_cid = first_c[0]
        cur.execute("""
            INSERT OR IGNORE INTO risks (company_id, title, description, category, likelihood, impact, status, submitted_by, submitted_date, risk_score, approver_email)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (first_cid, "Sample Risk: Test entry", "This is a seeded risk for demo", "IDENTIFY", "Medium", "Medium",
              "Open", "admin", datetime.now().strftime("%Y-%m-%d"), 4, f"approver@{seed_companies[0].lower().replace(' ', '')}.com.au"))

    conn.commit()
    conn.close()

# ensure DB exists / init
if not os.path.exists(DB_PATH):
    init_db()
else:
    # if DB exists, still ensure tables exist (safe)
    init_db()

# === GLOBAL COMPANIES LIST ===
companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]

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
            cur = conn.cursor()
            hashed = hashlib.sha256(password.encode()).hexdigest()
            cur.execute("SELECT * FROM users WHERE email=? AND password=?", (email, hashed))
            user = cur.fetchone()
            conn.close()
            if user:
                # store minimal user info into session_state (tuple as returned from DB)
                st.session_state.user = user
                st.experimental_rerun()
            else:
                st.error("Invalid email or password")
    # keep the app halted until login
    st.stop()

user = st.session_state.user
company_id = user[4]  # user tuple: (id, email, password, role, company_id)

conn = get_db()
cur = conn.cursor()
cur.execute("SELECT name FROM companies WHERE id=?", (company_id,))
company_row = cur.fetchone()
company_name = company_row[0] if company_row else "Unknown Company"

# === SIDEBAR ===
with st.sidebar:
    st.markdown(f"**{user[1].split('@')[0]}**")
    st.markdown(f"<small>{user[3]} • {company_name}</small>", unsafe_allow_html=True)
    st.markdown("---")
    pages = ["Dashboard", "Log a new Risk", "NIST Controls", "Evidence Vault", "Playbooks", "Reports", "Vendor Risk", "Admin Panel"]
    for p in pages:
        if st.button(p, key=f"nav_{p}"):
            st.session_state.page = p
            st.experimental_rerun()

page = st.session_state.get("page", "Dashboard")

# === DASHBOARD ===
if page == "Dashboard":
    st.markdown("## Dashboard")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("96% Compliance", key="card_comp"):
            st.session_state.page = "NIST Controls"; st.experimental_rerun()
        st.markdown('<div class="metric-card"><h2>96%</h2><p>Compliance</p></div>', unsafe_allow_html=True)
    with col2:
        if st.button("4 Active Risks", key="card_risk"):
            st.session_state.page = "Log a new Risk"; st.experimental_rerun()
        st.markdown('<div class="metric-card"><h2>4</h2><p>Active Risks</p></div>', unsafe_allow_html=True)
    with col3:
        if st.button("42 Evidence Files", key="card_ev"):
            st.session_state.page = "Evidence Vault"; st.experimental_rerun()
        st.markdown('<div class="metric-card"><h2>42</h2><p>Evidence Files</p></div>', unsafe_allow_html=True)

    # RACI per company
    for i, comp in enumerate(companies):
        with st.expander(f"RACI Matrix – {comp}", expanded=False):
            raci_data = pd.DataFrame([
                ["Asset Inventory", "A", "R", "C", "I"],
                ["Backup", "R", "A", "I", "C"]
            ], columns=["Control", "IT", "Ops", "Sec", "Finance"]).set_index("Control")
            fig = px.imshow(raci_data, color_continuous_scale="Greys", text_auto=True)
            st.plotly_chart(fig, use_container_width=True, key=f"raci_{i}")

    # CLICKABLE RISKS
    risks_df = pd.read_sql_query("SELECT id, title, status, risk_score, company_id FROM risks", conn)
    st.markdown("### Active Risks")
    if not risks_df.empty:
        for _, r in risks_df.iterrows():
            cur.execute("SELECT name FROM companies WHERE id=?", (int(r['company_id']),))
            comp_name_row = cur.fetchone()
            comp_name = comp_name_row[0] if comp_name_row else "Unknown"
            btn_label = f"{r['title']} [{comp_name}] - {r['status']} (Score: {r['risk_score']})"
            if st.button(btn_label, key=f"risk_{r['id']}"):
                st.session_state.selected_risk = int(r['id'])
                st.session_state.page = "Log a new Risk"
                st.experimental_rerun()
    else:
        st.info("No risks found.")

# === LOG A NEW RISK + EDIT ===
elif page == "Log a new Risk":
    st.markdown("## Risk Management")
    if st.session_state.get("selected_risk"):
        cur.execute("SELECT * FROM risks WHERE id=?", (st.session_state.selected_risk,))
        risk = cur.fetchone()
        if risk:
            st.markdown(f"### Editing: {risk[2]}")
            with st.form("edit_risk"):
                title = st.text_input("Title", risk[2])
                desc = st.text_area("Description", risk[3])
                categories = ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
                category = st.selectbox("Category", categories, index=categories.index(risk[4]) if risk[4] in categories else 0)
                likelihood_opts = ["Low", "Medium", "High"]
                likelihood = st.selectbox("Likelihood", likelihood_opts, index=likelihood_opts.index(risk[5]) if risk[5] in likelihood_opts else 0)
                impact_opts = ["Low", "Medium", "High"]
                impact = st.selectbox("Impact", impact_opts, index=impact_opts.index(risk[6]) if risk[6] in impact_opts else 0)
                status_opts = ["Open", "Pending Approval", "Mitigated", "Closed"]
                status = st.selectbox("Status", status_opts, index=status_opts.index(risk[7]) if risk[7] in status_opts else 0)
                approver = st.text_input("Approver Email", risk[11] if len(risk) > 11 else "")
                if st.form_submit_button("Update"):
                    score = {"Low":1, "Medium":2, "High":3}[likelihood] * {"Low":1, "Medium":2, "High":3}[impact]
                    cur.execute("UPDATE risks SET title=?, description=?, category=?, likelihood=?, impact=?, status=?, risk_score=?, approver_email=? WHERE id=?",
                                (title, desc, category, likelihood, impact, status, score, approver, risk[0]))
                    conn.commit()
                    st.success("Updated")
                    st.session_state.selected_risk = None
                    st.experimental_rerun()
        else:
            st.error("Selected risk not found.")
            st.session_state.selected_risk = None
    else:
        with st.form("new_risk"):
            company_sel = st.selectbox("Company", companies)
            title = st.text_input("Title")
            desc = st.text_area("Description")
            category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
            likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"])
            impact = st.selectbox("Impact", ["Low", "Medium", "High"])
            approver = st.selectbox("Assign Approver", [f"approver@{c.lower().replace(' ', '')}.com.au" for c in companies])
            if st.form_submit_button("Submit"):
                if not title.strip():
                    st.error("Title is required.")
                else:
                    score = {"Low":1, "Medium":2, "High":3}[likelihood] * {"Low":1, "Medium":2, "High":3}[impact]
                    cur.execute("SELECT id FROM companies WHERE name=?", (company_sel,))
                    cid_row = cur.fetchone()
                    cid = cid_row[0] if cid_row else None
                    cur.execute("INSERT INTO risks (company_id, title, description, category, likelihood, impact, status, submitted_by, submitted_date, risk_score, approver_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                (cid, title, desc, category, likelihood, impact, "Pending Approval", user[1], datetime.now().strftime("%Y-%m-%d"), score, approver))
                    conn.commit()
                    st.success(f"Risk submitted. Email sent to {approver}")

# === EVIDENCE VAULT ===
elif page == "Evidence Vault":
    st.markdown("## Evidence Vault")
    company_sel = st.selectbox("Company", companies, key="ev_comp")
    cur.execute("SELECT id FROM companies WHERE name=?", (company_sel,))
    cid_row = cur.fetchone()
    cid = cid_row[0] if cid_row else None
    risks = pd.read_sql_query("SELECT id, title FROM risks WHERE company_id=?", conn, params=(cid,))
    risk_sel = st.selectbox("Link to Risk", risks["title"].tolist()) if not risks.empty else None
    uploaded = st.file_uploader("Upload Evidence")
    if uploaded and risk_sel:
        cur.execute("SELECT id FROM risks WHERE title=?", (risk_sel,))
        rid_row = cur.fetchone()
        rid = rid_row[0] if rid_row else None
        cur.execute("INSERT INTO evidence (risk_id, company_id, file_name, upload_date, uploaded_by) VALUES (?, ?, ?, ?, ?)",
                    (rid, cid, uploaded.name, datetime.now().strftime("%Y-%m-%d"), user[1]))
        conn.commit()
        st.success("Uploaded")
    evidence_list = pd.read_sql_query("SELECT e.file_name, r.title AS risk_title, e.upload_date FROM evidence e JOIN risks r ON e.risk_id=r.id WHERE e.company_id=?", conn, params=(cid,))
    st.dataframe(evidence_list)

# === ADMIN PANEL ===
elif page == "Admin Panel":
    st.markdown("## Admin Panel")
    users_df = pd.read_sql_query("SELECT u.id, u.email, u.role, c.name FROM users u JOIN companies c ON u.company_id=c.id", conn)
    st.markdown("### Users")
    for _, u in users_df.iterrows():
        if st.button(f"{u['email']} - {u['role']} ({u['name']})", key=f"edit_user_{u['id']}"):
            st.session_state.edit_user_id = int(u['id'])
    if st.session_state.get("edit_user_id"):
        cur.execute("SELECT * FROM users WHERE id=?", (st.session_state.edit_user_id,))
        usr = cur.fetchone()
        if usr:
            with st.form("edit_user_form"):
                new_email = st.text_input("Email", usr[1])
                new_role = st.selectbox("Role", ["Admin", "Approver", "User"], index=["Admin", "Approver", "User"].index(usr[3]) if usr[3] in ["Admin", "Approver", "User"] else 2)
                new_pass = st.text_input("New Password (leave blank to keep)", type="password")
                if st.form_submit_button("Update User"):
                    updates = []
                    params = []
                    if new_email != usr[1]:
                        updates.append("email=?"); params.append(new_email)
                    if new_role != usr[3]:
                        updates.append("role=?"); params.append(new_role)
                    if new_pass:
                        updates.append("password=?"); params.append(hashlib.sha256(new_pass.encode()).hexdigest())
                    if updates:
                        query = f"UPDATE users SET {', '.join(updates)} WHERE id=?"
                        params.append(usr[0])
                        cur.execute(query, tuple(params))
                        conn.commit()
                        st.success("User updated")
                        st.session_state.edit_user_id = None
                        st.experimental_rerun()
        else:
            st.error("User not found")
            st.session_state.edit_user_id = None

    st.markdown("### Add User")
    with st.form("add_user"):
        email = st.text_input("Email", key="add_user_email")
        password = st.text_input("Password", type="password", key="add_user_pass")
        role = st.selectbox("Role", ["Admin", "Approver", "User"], key="add_user_role")
        comps = st.multiselect("Companies", companies, key="add_user_comps")
        if st.form_submit_button("Create"):
            if not email or not password or not comps:
                st.error("Email, password and at least one company are required.")
            else:
                hashed = hashlib.sha256(password.encode()).hexdigest()
                for comp in comps:
                    cur.execute("SELECT id FROM companies WHERE name=?", (comp,))
                    cid_row = cur.fetchone()
                    cid = cid_row[0] if cid_row else None
                    cur.execute("INSERT INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)", (email, hashed, role, cid))
                conn.commit()
                st.success("User added")

# === FOOTER ===
st.markdown("""
---
<div style="text-align:center; color:#888; padding:1.2rem;">
© 2025 Joval Wines | Risk Management Portal v16.1
</div>
""", unsafe_allow_html=True)
