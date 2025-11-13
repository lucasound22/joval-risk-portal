# app.py – JOVAL WINES RISK PORTAL v31.0 – FULL DEPLOYMENT READY
import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import hashlib
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
import plotly.graph_objects as go
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import urllib.request

# === EMAIL CONFIG (UPDATE BEFORE DEPLOY) ===
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "joval.risk.portal@gmail.com"
SENDER_PASSWORD = "your_app_password_here"  # Use Gmail App Password

def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        st.warning(f"Email failed: {e}")

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
                 id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 username TEXT UNIQUE, email TEXT UNIQUE, password TEXT, role TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS risks (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 company_id INTEGER, title TEXT, description TEXT, category TEXT,
                 likelihood TEXT, impact TEXT, status TEXT, submitted_by TEXT,
                 submitted_date TEXT, risk_score INTEGER, approver_email TEXT,
                 approver_notes TEXT, approved_by TEXT, approved_date TEXT,
                 workflow_step TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS evidence (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER, company_id INTEGER,
                 file_name TEXT, upload_date TEXT, uploaded_by TEXT, file_data BLOB)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendors (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, contact_email TEXT, 
                 risk_level TEXT, last_assessment TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questionnaire (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, vendor_id INTEGER, question TEXT, 
                 answer TEXT, answered_date TEXT, sent_date TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questions (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, question TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_trail (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_email TEXT, action TEXT, details TEXT)""")

    # ADD COLUMNS SAFELY
    for sql in [
        "ALTER TABLE evidence ADD COLUMN file_data BLOB",
        "ALTER TABLE risks ADD COLUMN approved_by TEXT",
        "ALTER TABLE risks ADD COLUMN approved_date TEXT",
        "ALTER TABLE risks ADD COLUMN workflow_step TEXT"
    ]:
        try: c.execute(sql)
        except sqlite3.OperationalError: pass

    # COMPANIES
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(n,) for n in companies])

    # DEFAULT PASSWORD
    hashed = hashlib.sha256("Joval2025".encode()).hexdigest()

    # USERS
    for i, comp in enumerate(companies, 1):
        admin_email = f"admin@{comp.lower().replace(' ', '')}.com.au"
        c.execute("INSERT OR REPLACE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                  ("admin", admin_email, hashed, "Admin", i))
        approver_email = f"approver@{comp.lower().replace(' ', '')}.com.au"
        c.execute("INSERT OR IGNORE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                  (f"approver_{comp.lower().replace(' ', '')}", approver_email, hashed, "Approver", i))

    # SAMPLE RISK
    risks = [
        (1, "Phishing Campaign", "Finance targeted via email", "DETECT", "High", "High", "Pending Approval", "admin", "2025-10-01", 9, "approver@jovalwines.com.au", "", None, None, "awaiting_approval"),
    ]
    c.executemany("""INSERT OR IGNORE INTO risks 
                     (company_id, title, description, category, likelihood, impact, status, 
                      submitted_by, submitted_date, risk_score, approver_email, approver_notes, approved_by, approved_date, workflow_step) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", risks)

    # VENDOR
    c.execute("INSERT OR IGNORE INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
              ("Reefer Tech", "security@reefertech.com", "High", "2025-08-20", 1))

    # NIST QUESTIONS
    nist_questions = [
        "Does the vendor have a formal cybersecurity program aligned with NIST CSF?",
        "Is there a designated CISO or security officer?",
        "Are employees trained annually on cybersecurity awareness?"
    ]
    c.executemany("INSERT OR IGNORE INTO vendor_questions (question, company_id) VALUES (?, ?)", [(q, 1) for q in nist_questions])

    conn.commit()
    conn.close()

# === UTILS ===
def calculate_risk_score(likelihood, impact):
    scores = {"Low": 1, "Medium": 2, "High": 3}
    return scores.get(likelihood, 1) * scores.get(impact, 1)

def get_risk_color(score):
    if score >= 7: return "red"
    elif score >= 4: return "orange"
    else: return "green"

def log_action(user_email, action, details=""):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO audit_trail (timestamp, user_email, action, details) VALUES (?, ?, ?, ?)",
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user_email, action, details))
    conn.commit()
    conn.close()

# === PDF REPORT ===
def generate_pdf_report(title, content):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1.2*inch)
    styles = getSampleStyleSheet()
    story = []

    try:
        with urllib.request.urlopen("https://jovalwines.com.au/wp-content/uploads/2020/06/Joval-Wines-Logo.png") as r:
            img = Image(BytesIO(r.read()), width=2*inch, height=0.6*inch)
            story.append(img)
    except:
        story.append(Paragraph("JOVAL WINES", styles['Title']))

    story.append(Spacer(1, 12))
    story.append(Paragraph(title, styles['Heading1']))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%d %B %Y')}", styles['Normal']))
    story.append(Paragraph("jovalwines.com.au", styles['Normal']))
    story.append(Spacer(1, 20))

    if isinstance(content, pd.DataFrame):
        data = [content.columns.tolist()] + content.values.tolist()
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a1a')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        story.append(table)

    story.append(Spacer(1, 30))
    story.append(Paragraph("© 2025 Joval Wines", styles['Normal']))
    doc.build(story)
    buffer.seek(0)
    return buffer

# === INIT DB ===
if "db_init" not in st.session_state:
    init_db()
    st.session_state.db_init = True

# === CONFIG ===
st.set_page_config(page_title="Joval Risk Portal", layout="wide")
st.markdown("""
<style>
    .header {background: #1a1a1a; color: white; padding: 2rem; text-align: center;}
    .header h1 {font-weight: normal !important; margin:0;}
    .metric-card {background: white; padding: 1.5rem; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal</p></div>', unsafe_allow_html=True)

# === LOGIN ===
if "user" not in st.session_state:
    with st.sidebar:
        st.markdown("### Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            conn = get_db()
            c = conn.cursor()
            hashed = hashlib.sha256(password.encode()).hexdigest()
            c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed))
            user = c.fetchone()
            conn.close()
            if user:
                st.session_state.user = user
                log_action(user[2], "LOGIN")
                st.rerun()
            else:
                st.error("Invalid credentials")
    st.stop()

user = st.session_state.user
company_id = user[5]
conn = get_db()
c = conn.cursor()
c.execute("SELECT name FROM companies WHERE id=?", (company_id,))
company_name = c.fetchone()[0]

# === SIDEBAR ===
with st.sidebar:
    st.markdown("### Playbook Tracker")
    st.markdown("**[Open Playbook Tracker App](https://joval-wines-nist-playbook-tracker.streamlit.app/)**")
    st.markdown("---")
    st.markdown(f"**{user[1]}** • {company_name}")
    st.markdown("---")

    pages = ["Dashboard", "Log a new Risk", "Evidence Vault", "Vendor Management", "Reports"]
    if user[4] == "Approver": pages.insert(1, "My Approvals")
    if user[4] == "Admin": pages += ["Audit Trail", "Admin Panel"]

    for p in pages:
        if st.button(p, key=f"nav_{p}"):
            st.session_state.page = p
            st.rerun()

page = st.session_state.get("page", "Dashboard")

# === DASHBOARD ===
if page == "Dashboard":
    st.markdown("## Dashboard")
    high_risks = pd.read_sql("SELECT COUNT(*) FROM risks WHERE risk_score >= 7 AND company_id=?", conn, params=(company_id,)).iloc[0,0]
    total_risks = pd.read_sql("SELECT COUNT(*) FROM risks WHERE company_id=?", conn, params=(company_id,)).iloc[0,0]
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f'<div class="metric-card"><h2>{high_risks}</h2><p>High Risks</p></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="metric-card"><h2>{total_risks}</h2><p>Total Risks</p></div>', unsafe_allow_html=True)

# === LOG A NEW RISK ===
elif page == "Log a new Risk":
    st.markdown("## Log a New Risk")
    companies_df = pd.read_sql("SELECT id, name FROM companies", conn)
    company_options = companies_df['name'].tolist()

    with st.form("new_risk"):
        title = st.text_input("Title *")
        desc = st.text_area("Description *")
        category = st.selectbox("Category *", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
        likelihood = st.selectbox("Likelihood *", ["Low", "Medium", "High"])
        impact = st.selectbox("Impact *", ["Low", "Medium", "High"])
        selected_company_name = st.selectbox("Company *", company_options)
        selected_company_id = companies_df[companies_df['name'] == selected_company_name].iloc[0]['id']

        approvers_df = pd.read_sql("SELECT email FROM users WHERE role='Approver' AND company_id=?", conn, params=(selected_company_id,))
        approver_list = approvers_df['email'].tolist()

        if approver_list:
            assigned_approver = st.selectbox("Assign to Approver *", approver_list)
        else:
            st.warning("No approvers in selected company.")
            assigned_approver = None

        submitted = st.form_submit_button("Submit Risk")
        if submitted:
            if not all([title, desc, assigned_approver]):
                st.error("Please fill all required fields.")
            else:
                score = calculate_risk_score(likelihood, impact)
                c.execute("""INSERT INTO risks 
                             (company_id, title, description, category, likelihood, impact, status, 
                              submitted_by, submitted_date, risk_score, approver_email, workflow_step)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                          (selected_company_id, title, desc, category, likelihood, impact, "Pending Approval",
                           user[1], datetime.now().strftime("%Y-%m-%d"), score, assigned_approver, "awaiting_approval"))
                conn.commit()
                log_action(user[2], "RISK_SUBMITTED", title)
                send_email(assigned_approver, "New Risk Assigned", f"Risk: {title}\nSubmitted by: {user[2]}")
                st.success("Risk submitted!")
                st.rerun()

# === ADMIN PANEL ===
elif page == "Admin Panel" and user[4] == "Admin":
    st.markdown("## Admin Panel")

    # ADD USER
    with st.expander("Add New User"):
        with st.form("add_user"):
            new_username = st.text_input("Username")
            new_email = st.text_input("Email")
            new_password = st.text_input("Password", type="password")
            new_role = st.selectbox("Role", ["Admin", "Approver", "User"])
            new_company = st.selectbox("Company", companies_df['name'])
            if st.form_submit_button("Create"):
                if not all([new_username, new_email, new_password]):
                    st.error("All fields required.")
                else:
                    hashed = hashlib.sha256(new_password.encode()).hexdigest()
                    comp_id = companies_df[companies_df['name'] == new_company].iloc[0]['id']
                    c.execute("INSERT OR IGNORE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                              (new_username, new_email, hashed, new_role, comp_id))
                    conn.commit()
                    if c.rowcount > 0:
                        st.success(f"User {new_username} created.")
                    else:
                        st.warning("User exists.")
                    st.rerun()

    # EDIT USER
    st.markdown("### Users")
    users_df = pd.read_sql("SELECT id, username, email, role, company_id FROM users", conn)
    comp_map = dict(zip(companies_df['id'], companies_df['name']))
    users_df['company'] = users_df['company_id'].map(comp_map)

    for _, row in users_df.iterrows():
        col1, col2 = st.columns([3, 1])
        with col1:
            if st.button(f"**{row['username']}** – {row['email']} – {row['role']} – {row['company']}", key=f"user_{row['id']}"):
                st.session_state.edit_user = row.to_dict()
                st.rerun()
        with col2:
            if st.button("Reset Password", key=f"reset_{row['id']}"):
                new_pass = "Joval2025"
                hashed = hashlib.sha256(new_pass.encode()).hexdigest()
                c.execute("UPDATE users SET password=? WHERE id=?", (hashed, row['id']))
                conn.commit()
                st.success(f"Password reset to: {new_pass}")
                send_email(row['email'], "Password Reset", f"New password: {new_pass}")

    if "edit_user" in st.session_state:
        edit_data = st.session_state.edit_user
        with st.form("edit_user_form"):
            edit_username = st.text_input("Username", edit_data['username'])
            edit_email = st.text_input("Email", edit_data['email'])
            edit_role = st.selectbox("Role", ["Admin", "Approver", "User"], 
                                     index=["Admin", "Approver", "User"].index(edit_data['role']))
            current_comp_id = edit_data['company_id']
            company_idx = companies_df[companies_df['id'] == current_comp_id].index
            company_idx = company_idx[0] if len(company_idx) > 0 else 0
            edit_company = st.selectbox("Company", companies_df['name'], index=company_idx)

            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button("Save Changes"):
                    comp_id = companies_df[companies_df['name'] == edit_company].iloc[0]['id']
                    c.execute("UPDATE users SET username=?, email=?, role=?, company_id=? WHERE id=?",
                              (edit_username, edit_email, edit_role, comp_id, edit_data['id']))
                    conn.commit()
                    st.success("User updated")
                    del st.session_state.edit_user
                    st.rerun()
            with col2:
                if st.form_submit_button("Cancel"):
                    del st.session_state.edit_user
                    st.rerun()

# === REPORTS ===
elif page == "Reports":
    st.markdown("## Reports")
    risks_df = pd.read_sql("SELECT risk_score FROM risks WHERE company_id=?", conn, params=(company_id,))
    high = len(risks_df[risks_df['risk_score'] >= 7])
    med = len(risks_df[(risks_df['risk_score'] >= 4) & (risks_df['risk_score'] < 7)])
    low = len(risks_df[risks_df['risk_score'] < 4])

    fig = go.Figure(data=[go.Bar(x=['High', 'Medium', 'Low'], y=[high, med, low], marker_color=['red', 'orange', 'green'])])
    fig.update_layout(title="Risk Heatmap", xaxis_title="Level", yaxis_title="Count")
    st.plotly_chart(fig, use_container_width=True)

    risk_df = pd.read_sql("SELECT title, category, likelihood, impact, risk_score, status FROM risks WHERE company_id=?", conn, params=(company_id,))
    if st.button("Download PDF"):
        pdf = generate_pdf_report("Risk Register", risk_df)
        st.download_button("Download PDF", pdf, "risk_register.pdf", "application/pdf")

# === FOOTER ===
st.markdown("---\n© 2025 Joval Wines | jovalwines.com.au")
