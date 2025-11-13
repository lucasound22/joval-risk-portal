# app.py – JOVAL WINES RISK PORTAL v28.1 – FINAL & COMPLETE
import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import hashlib
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, KeepInFrame
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
import plotly.express as px
import plotly.graph_objects as go
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
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
                 id INTEGER PRIMARY KEY AUTOINTEGRITY, risk_id INTEGER, company_id INTEGER,
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
        try:
            c.execute(sql)
        except sqlite3.OperationalError:
            pass

    # 4 COMPANIES
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(n,) for n in companies])

    # HASHED PASSWORD: Joval2025
    hashed = hashlib.sha256("Joval2025".encode()).hexdigest()

    # USERS PER COMPANY
    for i, comp in enumerate(companies, 1):
        admin_user = "admin"
        admin_email = f"admin@{comp.lower().replace(' ', '')}.com.au"
        c.execute("INSERT OR REPLACE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                  (admin_user, admin_email, hashed, "Admin", i))
        approver_user = f"approver_{comp.lower().replace(' ', '')}"
        approver_email = f"approver@{comp.lower().replace(' ', '')}.com.au"
        c.execute("INSERT OR IGNORE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                  (approver_user, approver_email, hashed, "Approver", i))

    # SAMPLE RISKS
    risks = [
        (1, "Phishing Campaign", "Finance targeted via email", "DETECT", "High", "High", "Pending Approval", "admin", "2025-10-01", 9, "approver@jovalwines.com.au", "", None, None, "awaiting_approval"),
        (1, "Laptop Lost", "Customer PII on unencrypted device", "PROTECT", "Medium", "High", "Approved", "it@jovalwines.com.au", "2025-09-28", 6, "approver@jovalwines.com.au", "Remote wipe executed", "approver@jovalwines.com.au", "2025-09-29", "approved"),
        (1, "Ransomware Attack", "Encrypted SAP backup", "RECOVER", "High", "High", "Pending Approval", "ciso@jovalwines.com.au", "2025-11-05", 9, "approver@jovalwines.com.au", "", None, None, "awaiting_approval"),
        (2, "Data Leak", "Customer data exposed", "PROTECT", "Medium", "High", "Approved", "admin", "2025-09-15", 6, "approver@jovalfamilywines.com.au", "Contained", "approver@jovalfamilywines.com.au", "2025-09-16", "approved"),
    ]
    c.executemany("""INSERT OR IGNORE INTO risks 
                     (company_id, title, description, category, likelihood, impact, status, 
                      submitted_by, submitted_date, risk_score, approver_email, approver_notes, approved_by, approved_date, workflow_step) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", risks)

    # VENDORS
    c.execute("INSERT OR IGNORE INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
              ("Reefer Tech", "security@reefertech.com", "High", "2025-08-20", 1))
    c.execute("INSERT OR IGNORE INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
              ("Pallet Co", "vendor@palletco.com", "Medium", "2025-09-15", 1))

    # NIST CSF VENDOR QUESTIONNAIRE – 20 REAL NIST-ALIGNED QUESTIONS
    nist_questions = [
        "Does the vendor have a formal cybersecurity program aligned with NIST CSF?",
        "Is there a designated CISO or security officer?",
        "Are employees trained annually on cybersecurity awareness?",
        "Is multi-factor authentication (MFA) enforced for all privileged access?",
        "Are regular vulnerability scans performed (at least quarterly)?",
        "Is there a documented and tested incident response plan?",
        "Are security logs retained for at least 12 months?",
        "Is sensitive data encrypted at rest and in transit using AES-256?",
        "Are third-party risk assessments conducted on sub-vendors?",
        "Is there a formal patch management policy with SLA < 30 days?",
        "Are penetration tests conducted annually by a qualified firm?",
        "Is there a business continuity plan with RTO < 4 hours for critical systems?",
        "Is administrative access restricted using Role-Based Access Control (RBAC)?",
        "Are Data Loss Prevention (DLP) tools deployed?",
        "Is there a formal data classification and handling policy?",
        "Is a Software Bill of Materials (SBOM) provided for all software?",
        "Does the vendor carry cyber liability insurance (>$5M)?",
        "Is compliance with NIST 800-53, ISO 27001, or SOC 2 certified?",
        "Is remote access secured via VPN with MFA and endpoint verification?",
        "Is there a formal offboarding process to revoke access within 24 hours?"
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

# === PDF REPORT WITH JOVAL BRANDING + CHARTS ===
def generate_pdf_report(title, content, chart_img=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1.2*inch, bottomMargin=1*inch)
    styles = getSampleStyleSheet()
    story = []

    # JOVAL LOGO
    logo_url = "https://jovalwines.com.au/wp-content/uploads/2020/06/Joval-Wines-Logo.png"
    try:
        with urllib.request.urlopen(logo_url) as response:
            img_data = response.read()
            img = Image(BytesIO(img_data), width=2*inch, height=0.6*inch)
            story.append(img)
    except:
        story.append(Paragraph("JOVAL WINES", styles['Title']))

    story.append(Spacer(1, 12))
    story.append(Paragraph(title, styles['Heading1']))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%d %B %Y at %H:%M')}", styles['Normal']))
    story.append(Paragraph("jovalwines.com.au", styles['Normal']))
    story.append(Spacer(1, 20))

    if chart_img:
        chart = Image(BytesIO(chart_img), width=6*inch, height=3*inch)
        story.append(KeepInFrame(6*inch, 3*inch, [chart]))
        story.append(Spacer(1, 12))

    if isinstance(content, list):
        for line in content:
            story.append(Paragraph(line, styles['Normal']))
            story.append(Spacer(1, 6))
    elif isinstance(content, pd.DataFrame):
        data = [content.columns.tolist()] + content.values.tolist()
        table = Table(data, colWidths=[1.2*inch, 1*inch, 1*inch, 1*inch, 1*inch, 1.2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a1a')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8f9fa')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTSIZE', (0,1), (-1,-1), 9),
        ]))
        story.append(table)

    story.append(Spacer(1, 30))
    story.append(Paragraph("© 2025 Joval Wines. All rights reserved. | jovalwines.com.au", styles['Normal']))
    doc.build(story)
    buffer.seek(0)
    return buffer

# === INIT DB ONCE ===
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
    .clickable-risk {cursor: pointer; padding: 0.75rem; border-radius: 8px; margin: 0.25rem 0;}
    .approval-badge {background: #e6f7ff; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.8rem;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal</p></div>', unsafe_allow_html=True)

# === LOGIN ===
if "user" not in st.session_state:
    with st.sidebar:
        st.markdown("### Login")
        username = st.text_input("Username", placeholder="Enter username")
        password = st.text_input("Password", type="password", placeholder="Enter password")
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
                st.error("Invalid username or password")
    st.stop()

user = st.session_state.user
company_id = user[5]
conn = get_db()
c = conn.cursor()
c.execute("SELECT name FROM companies WHERE id=?", (company_id,))
company_name = c.fetchone()[0]

# === METRICS ===
high_risks_open = pd.read_sql("SELECT COUNT(*) FROM risks WHERE risk_score >= 7 AND status != 'Mitigated' AND company_id=?", conn, params=(company_id,)).iloc[0,0]
total_risks = pd.read_sql("SELECT COUNT(*) FROM risks WHERE company_id=?", conn, params=(company_id,)).iloc[0,0]

# === SIDEBAR ===
with st.sidebar:
    st.markdown("### Playbook Tracker")
    st.markdown("**[Open Playbook Tracker App](https://joval-wines-nist-playbook-tracker.streamlit.app/)**")
    st.markdown("---")
    st.markdown(f"**{user[1]}** • {company_name}")
    st.markdown("---")

    pages = ["Dashboard", "Log a new Risk", "Evidence Vault", "Vendor Management", "Reports"]
    if user[4] == "Approver":
        pages.insert(1, "My Approvals")
    if user[4] == "Admin":
        pages += ["Audit Trail", "Admin Panel"]

    for p in pages:
        if st.button(p, key=f"nav_{p}"):
            st.session_state.page = p
            st.rerun()

page = st.session_state.get("page", "Dashboard")

# === MY APPROVALS ===
if page == "My Approvals" and user[4] == "Approver":
    st.markdown("## My Approvals")
    pending = pd.read_sql("SELECT id, title, risk_score, submitted_by, submitted_date FROM risks WHERE approver_email=? AND status='Pending Approval' AND company_id=?", conn, params=(user[2], company_id))
    if not pending.empty:
        for _, r in pending.iterrows():
            with st.container():
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.markdown(f"**{r['title']}** – Score: {r['risk_score']} – Submitted by {r['submitted_by']} on {r['submitted_date']}")
                with col2:
                    if st.button("Review", key=f"rev_{r['id']}"):
                        st.session_state.selected_risk = r['id']
                        st.session_state.page = "Risk Detail"
                        st.rerun()
    else:
        st.info("No pending approvals.")

# === DASHBOARD ===
if page == "Dashboard":
    st.markdown("## Progress Dashboard")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f'<div class="metric-card"><h2>{high_risks_open}</h2><p>High Risks Open</p></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="metric-card"><h2>{total_risks}</h2><p>Total Risks</p></div>', unsafe_allow_html=True)

    risks_df = pd.read_sql("SELECT status, risk_score FROM risks WHERE company_id=?", conn, params=(company_id,))
    if not risks_df.empty:
        risks_df['color'] = risks_df['risk_score'].apply(get_risk_color)
        fig = px.pie(risks_df, names='status', color='color',
                     color_discrete_map={'red': '#ff4d4d', 'orange': '#ffa500', 'green': '#90ee90'},
                     title="Risk Status Distribution")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Active Risks")
    risks = pd.read_sql("SELECT id, title, status, risk_score, description, approved_by FROM risks WHERE company_id=?", conn, params=(company_id,))
    for _, r in risks.iterrows():
        color = get_risk_color(r['risk_score'])
        bg = "#ffe6e6" if color == "red" else "#fff4e6" if color == "orange" else "#e6f7e6"
        approval = f"<span class='approval-badge'>Approved by {r['approved_by']}</span>" if r['approved_by'] else ""
        if st.button(f"**{r['title']}** – Score: {r['risk_score']} | {r['status']}", key=f"risk_{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Risk Detail"
            st.rerun()
        st.markdown(f'<div class="clickable-risk" style="background:{bg};"><small>{r["description"][:100]}... {approval}</small></div>', unsafe_allow_html=True)

# === LOG A NEW RISK (COMPANY + APPROVER LOGIC) ===
elif page == "Log a new Risk":
    st.markdown("## Log a New Risk")
    companies_df = pd.read_sql("SELECT id, name FROM companies", conn)
    company_options = companies_df['name'].tolist()

    with st.form("new_risk"):
        title = st.text_input("Title")
        desc = st.text_area("Description")
        category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
        likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"])
        impact = st.selectbox("Impact", ["Low", "Medium", "High"])
        selected_company_name = st.selectbox("Company", company_options)
        selected_company_id = companies_df[companies_df['name'] == selected_company_name].iloc[0]['id']

        # SHOW ONLY APPROVERS FROM SELECTED COMPANY
        approvers = pd.read_sql("SELECT email FROM users WHERE role='Approver' AND company_id=?", conn, params=(selected_company_id,))
        approver_list = approvers['email'].tolist()
        if approver_list:
            assigned_approver = st.selectbox("Assign to Approver", approver_list)
        else:
            st.warning("No approvers in selected company.")
            assigned_approver = None

        if st.form_submit_button("Submit") and assigned_approver:
            score = calculate_risk_score(likelihood, impact)
            c.execute("""INSERT INTO risks 
                         (company_id, title, description, category, likelihood, impact, status, 
                          submitted_by, submitted_date, risk_score, approver_email, approver_notes, 
                          approved_by, approved_date, workflow_step)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (selected_company_id, title, desc, category, likelihood, impact, "Pending Approval",
                       user[1], datetime.now().strftime("%Y-%m-%d"), score, assigned_approver, "", None, None, "awaiting_approval"))
            conn.commit()
            log_action(user[2], "RISK_SUBMITTED", f"{title} → {assigned_approver}")
            send_email(assigned_approver, f"[ACTION] New Risk: {title}", f"Submitted by {user[2]}")
            st.success("Risk submitted")
            st.rerun()

# === RISK DETAIL ===
elif page == "Risk Detail" and "selected_risk" in st.session_state:
    risk_id = st.session_state.selected_risk
    risk = pd.read_sql("SELECT * FROM risks WHERE id=?", conn, params=(risk_id,)).iloc[0]
    st.markdown(f"## Edit Risk: {risk['title']}")

    with st.form("edit_risk"):
        title = st.text_input("Title", risk['title'])
        desc = st.text_area("Description", risk['description'])
        category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"], 
                                index=["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"].index(risk['category']))
        likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"], 
                                 index=["Low", "Medium", "High"].index(risk['likelihood']))
        impact = st.selectbox("Impact", ["Low", "Medium", "High"], 
                              index=["Low", "Medium", "High"].index(risk['impact']))
        status = st.selectbox("Status", ["Pending Approval", "Approved", "Rejected", "Mitigated"], 
                              index=["Pending Approval", "Approved", "Rejected", "Mitigated"].index(risk['status']))
        notes = st.text_area("Approver Notes", risk['approver_notes'])

        col1, col2 = st.columns(2)
        with col1:
            if st.form_submit_button("Save Changes"):
                score = calculate_risk_score(likelihood, impact)
                approved_by = user[2] if status in ["Approved", "Rejected"] else risk['approved_by']
                approved_date = datetime.now().strftime("%Y-%m-%d") if status in ["Approved", "Rejected"] else risk['approved_date']
                workflow_step = "approved" if status == "Approved" else "rejected" if status == "Rejected" else "mitigated" if status == "Mitigated" else "awaiting_approval"
                c.execute("""UPDATE risks SET title=?, description=?, category=?, likelihood=?, impact=?, 
                             status=?, risk_score=?, approver_notes=?, approved_by=?, approved_date=?, workflow_step=? WHERE id=?""",
                          (title, desc, category, likelihood, impact, status, score, notes, approved_by, approved_date, workflow_step, risk_id))
                conn.commit()
                log_action(user[2], "RISK_UPDATED", f"{title} → {status}")
                st.success("Risk updated")
                st.rerun()
        with col2:
            if st.form_submit_button("Back to Dashboard"):
                del st.session_state.selected_risk
                st.session_state.page = "Dashboard"
                st.rerun()

    evidence = pd.read_sql("SELECT file_name, upload_date, uploaded_by FROM evidence WHERE risk_id=?", conn, params=(risk_id,))
    if not evidence.empty:
        st.markdown("### Evidence")
        for _, e in evidence.iterrows():
            st.write(f"**{e['file_name']}** – {e['upload_date']} by {e['uploaded_by']}")

# === EVIDENCE VAULT ===
elif page == "Evidence Vault":
    st.markdown("## Evidence Vault")
    risks = pd.read_sql("SELECT id, title FROM risks WHERE company_id=?", conn, params=(company_id,))
    risk_options = {r['title']: r['id'] for _, r in risks.iterrows()}
    if risk_options:
        selected_risk = st.selectbox("Select Risk", options=list(risk_options.keys()))
        risk_id = risk_options[selected_risk]
        uploaded = st.file_uploader("Upload Evidence", type=["pdf", "png", "jpg", "docx"])
        if uploaded:
            c.execute("INSERT INTO evidence (risk_id, company_id, file_name, upload_date, uploaded_by, file_data) VALUES (?, ?, ?, ?, ?, ?)",
                      (risk_id, company_id, uploaded.name, datetime.now().strftime("%Y-%m-%d"), user[1], uploaded.getvalue()))
            conn.commit()
            st.success("Uploaded")
            st.rerun()
        evidence = pd.read_sql("SELECT id, file_name, upload_date, uploaded_by FROM evidence WHERE risk_id=?", conn, params=(risk_id,))
        if not evidence.empty:
            st.markdown("### Uploaded Evidence")
            for _, e in evidence.iterrows():
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"**{e['file_name']}** – {e['upload_date']} by {e['uploaded_by']}")
                with col2:
                    if st.button("Delete", key=f"del_ev_{e['id']}"):
                        c.execute("DELETE FROM evidence WHERE id=?", (e['id'],))
                        conn.commit()
                        st.rerun()
        else:
            st.info("No evidence.")
    else:
        st.info("No risks.")

# === VENDOR MANAGEMENT ===
elif page == "Vendor Management":
    st.markdown("## Vendor NIST Compliant Questionnaire")
    
    with st.expander("Vendor NIST Compliant Questionnaire", expanded=True):
        questions = pd.read_sql("SELECT id, question FROM vendor_questions WHERE company_id=?", conn, params=(company_id,))
        if questions.empty:
            init_db()
            questions = pd.read_sql("SELECT id, question FROM vendor_questions WHERE company_id=?", conn, params=(company_id,))
        edited = st.data_editor(questions, num_rows="dynamic", key="nist_editor")
        if st.button("Save NIST Questionnaire"):
            c.execute("DELETE FROM vendor_questions WHERE company_id=?", (company_id,))
            for _, row in edited.iterrows():
                if row['question'] and row['question'].strip():
                    c.execute("INSERT INTO vendor_questions (question, company_id) VALUES (?, ?)", (row['question'].strip(), company_id))
            conn.commit()
            st.success("NIST Questionnaire updated")
            st.rerun()

    with st.expander("Add New Vendor"):
        with st.form("new_vendor"):
            v_name = st.text_input("Name")
            v_email = st.text_input("Email")
            v_level = st.selectbox("Risk Level", ["Low", "Medium", "High"])
            if st.form_submit_button("Add"):
                c.execute("INSERT INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
                          (v_name, v_email, v_level, datetime.now().strftime("%Y-%m-%d"), company_id))
                conn.commit()
                st.rerun()

    vendors = pd.read_sql("SELECT id, name, risk_level FROM vendors WHERE company_id=?", conn, params=(company_id,))
    for _, v in vendors.iterrows():
        with st.expander(f"{v['name']} – {v['risk_level']}"):
            if st.button("Send Questionnaire", key=f"send_{v['id']}"):
                qs = pd.read_sql("SELECT question FROM vendor_questions WHERE company_id=?", conn, params=(company_id,))
                for _, q in qs.iterrows():
                    c.execute("INSERT OR IGNORE INTO vendor_questionnaire (vendor_id, question, sent_date) VALUES (?, ?, ?)",
                              (v['id'], q['question'], datetime.now().strftime("%Y-%m-%d")))
                conn.commit()
                st.success("Questionnaire sent")
            q_df = pd.read_sql("SELECT id, question, answer FROM vendor_questionnaire WHERE vendor_id=?", conn, params=(v['id'],))
            if q_df.empty:
                st.info("No questions sent yet.")
            else:
                edited = st.data_editor(q_df, num_rows="dynamic", key=f"q_{v['id']}")
                if st.button("Save Answers", key=f"saveq_{v['id']}"):
                    for _, row in edited.iterrows():
                        c.execute("UPDATE vendor_questionnaire SET answer=?, answered_date=? WHERE id=?", 
                                  (row['answer'], datetime.now().strftime("%Y-%m-%d"), row['id']))
                    conn.commit()
                    st.success("Answers saved")

# === REPORTS ===
elif page == "Reports":
    st.markdown("## Board-Ready Reports")

    # TRAFFIC LIGHT CHART
    risks_df = pd.read_sql("SELECT risk_score FROM risks WHERE company_id=?", conn, params=(company_id,))
    high = len(risks_df[risks_df['risk_score'] >= 7])
    med = len(risks_df[(risks_df['risk_score'] >= 4) & (risks_df['risk_score'] < 7)])
    low = len(risks_df[risks_df['risk_score'] < 4])
    fig = go.Figure(data=[go.Bar(x=['High', 'Medium', 'Low'], y=[high, med, low], marker_color=['red', 'orange', 'green'])])
    fig.update_layout(title="Risk Heatmap by Score", xaxis_title="Risk Level", yaxis_title="Count")
    chart_img = fig.to_image(format="png")

    col1, col2 = st.columns([3, 1])
    with col1:
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        if st.button("Download PDF", key="dl_heatmap"):
            pdf = generate_pdf_report("Risk Heatmap Report", [f"High: {high}", f"Medium: {med}", f"Low: {low}"], chart_img)
            st.download_button("Download Heatmap", pdf, "risk_heatmap.pdf", "application/pdf")

    risk_df = pd.read_sql("SELECT title, category, likelihood, impact, risk_score, status FROM risks WHERE company_id=?", conn, params=(company_id,))
    col1, col2 = st.columns([3, 1])
    with col1:
        st.write("**Risk Register**")
        st.dataframe(risk_df)
    with col2:
        if st.button("Download PDF", key="dl_risk"):
            pdf = generate_pdf_report("Risk Register", risk_df)
            st.download_button("Download", pdf, "risk_register.pdf", "application/pdf")

    vendor_df = pd.read_sql("SELECT name, risk_level, last_assessment FROM vendors WHERE company_id=?", conn, params=(company_id,))
    col1, col2 = st.columns([3, 1])
    with col1:
        st.write("**Vendor Risk Profile**")
        st.dataframe(vendor_df)
    with col2:
        if st.button("Download PDF", key="dl_vendor"):
            pdf = generate_pdf_report("Vendor Risk Profile", vendor_df)
            st.download_button("Download", pdf, "vendor_report.pdf", "application/pdf")

# === ADMIN PANEL ===
elif page == "Admin Panel" and user[4] == "Admin":
    st.markdown("## Admin Panel")
    with st.expander("Add New User"):
        with st.form("add_user_form"):
            new_username = st.text_input("Username")
            new_email = st.text_input("Email")
            new_password = st.text_input("Password", type="password")
            new_role = st.selectbox("Role", ["Admin", "Approver", "User"])
            companies_df = pd.read_sql("SELECT name FROM companies", conn)
            new_company = st.selectbox("Company", companies_df['name'])
            if st.form_submit_button("Create User"):
                hashed = hashlib.sha256(new_password.encode()).hexdigest()
                comp_id = pd.read_sql("SELECT id FROM companies WHERE name=?", conn, params=(new_company,)).iloc[0]['id']
                try:
                    c.execute("INSERT INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                              (new_username, new_email, hashed, new_role, comp_id))
                    conn.commit()
                    log_action(user[2], "USER_CREATED", new_username)
                    st.success("User created")
                    st.rerun()
                except sqlite3.IntegrityError as e:
                    st.error(f"Error: {e}")

# === AUDIT TRAIL ===
elif page == "Audit Trail" and user[4] == "Admin":
    st.markdown("## Audit Trail")
    trail = pd.read_sql("SELECT id, timestamp, user_email, action, details FROM audit_trail ORDER BY timestamp DESC", conn)
    for _, row in trail.iterrows():
        with st.expander(f"{row['timestamp']} – {row['user_email']} – {row['action']}"):
            st.write(f"**Details**: {row['details'] or '—'}")

# === FOOTER ===
st.markdown("---\n© 2025 Joval Wines | jovalwines.com.au")
