# app.py – JOVAL WINES RISK PORTAL v35.0 – FULL PRODUCTION VERSION
import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime, timedelta
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
# === EMAIL CONFIG ===
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "joval.risk.portal@gmail.com"
SENDER_PASSWORD = "your_app_password_here" # Use Gmail App Password
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
    for sql in [
        "ALTER TABLE evidence ADD COLUMN file_data BLOB",
        "ALTER TABLE risks ADD COLUMN approved_by TEXT",
        "ALTER TABLE risks ADD COLUMN approved_date TEXT",
        "ALTER TABLE risks ADD COLUMN workflow_step TEXT"
    ]:
        try: c.execute(sql)
        except sqlite3.OperationalError: pass
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(n,) for n in companies])
    hashed = hashlib.sha256("Joval2025".encode()).hexdigest()
    for i, comp in enumerate(companies, 1):
        admin_email = f"admin@{comp.lower().replace(' ', '')}.com.au"
        c.execute("INSERT OR REPLACE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                  ("admin", admin_email, hashed, "Admin", i))
        approver_email = f"approver@{comp.lower().replace(' ', '')}.com.au"
        c.execute("INSERT OR IGNORE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                  (f"approver_{comp.lower().replace(' ', '')}", approver_email, hashed, "Approver", i))
    risks = [
        (1, "Phishing Campaign", "Finance targeted via email", "DETECT", "High", "High", "Pending Approval", "admin", "2025-10-01", 9, "approver@jovalwines.com.au", "", None, None, "awaiting_approval"),
    ]
    c.executemany("""INSERT OR IGNORE INTO risks
                     (company_id, title, description, category, likelihood, impact, status,
                      submitted_by, submitted_date, risk_score, approver_email, approver_notes, approved_by, approved_date, workflow_step)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", risks)
    c.execute("INSERT OR IGNORE INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
              ("Reefer Tech", "security@reefertech.com", "High", "2025-08-20", 1))
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
        # Truncate long strings to prevent table overflow
        content_str = content.astype(str).applymap(lambda x: (x[:75] + '...') if len(x) > 78 else x)
        data = [content.columns.tolist()] + content_str.values.tolist()
        table = Table(data, hAlign='LEFT')
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a1a')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('BOX', (0,0), (-1,-1), 0.5, colors.black),
        ]))
        story.append(table)
    story.append(Spacer(1, 30))
    story.append(Paragraph("© 2025 Joval Wines", styles['Normal']))
    doc.build(story)
    buffer.seek(0)
    return buffer
# === INIT ===
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
</style>""", unsafe_allow_html=True)
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
    st.markdown("**Open Playbook Tracker App**")
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
    risks = pd.read_sql("SELECT id, title, status, risk_score, description, approved_by FROM risks WHERE company_id=?", conn, params=(company_id,))
    
    for _, r in risks.iterrows():
        color = get_risk_color(r['risk_score'])
        bg = "#ffe6e6" if color == "red" else "#fff4e6" if color == "orange" else "#e6f7e6"
        approval = f"<span class='approval-badge'>Approved by {r['approved_by']}</span>" if r['approved_by'] else ""
        if st.button(f"**{r['title']}** – Score: {r['risk_score']} | {r['status']}", key=f"risk*{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Risk Detail"
            st.rerun()
        st.markdown(f'<div class="clickable-risk" style="background:{bg};"><small>{r["description"][:100]}... {approval}</small></div>', unsafe_allow_html=True)
# === MY APPROVALS ===
elif page == "My Approvals" and user[4] == "Approver":
    st.markdown("## My Approvals")
    pending = pd.read_sql("SELECT id, title, risk_score, submitted_by, submitted_date FROM risks WHERE approver_email=? AND status='Pending Approval' AND company_id=?", conn, params=(user[2], company_id))
    for _, r in pending.iterrows():
        if st.button(f"**{r['title']}** – Score: {r['risk_score']} – {r['submitted_by']} on {r['submitted_date']}", key=f"rev*{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Risk Detail"
            st.rerun()
# === RISK DETAIL ===
elif page == "Risk Detail" and "selected_risk" in st.session_state:
    risk_id = st.session_state.selected_risk
    risk = pd.read_sql("SELECT * FROM risks WHERE id=?", conn, params=(risk_id,)).iloc[0]
    st.markdown(f"## Edit Risk: {risk['title']}")
    with st.form("edit_risk"):
        title = st.text_input("Title", risk['title'])
        desc = st.text_area("Description", risk['description'])
        category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"], index=["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"].index(risk['category']))
        likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"], index=["Low", "Medium", "High"].index(risk['likelihood']))
        impact = st.selectbox("Impact", ["Low", "Medium", "High"], index=["Low", "Medium", "High"].index(risk['impact']))
        status = st.selectbox("Status", ["Pending Approval", "Approved", "Rejected", "Mitigated"], index=["Pending Approval", "Approved", "Rejected", "Mitigated"].index(risk['status']))
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
            if st.form_submit_button("Back"):
                del st.session_state.selected_risk
                st.session_state.page = "Dashboard"
                st.rerun()
    evidence = pd.read_sql("SELECT file_name, upload_date, uploaded_by FROM evidence WHERE risk_id=?", conn, params=(risk_id,))
    if not evidence.empty:
        st.markdown("### Evidence")
        for _, e in evidence.iterrows():
            st.write(f"**{e['file_name']}** – {e['upload_date']} by {e['uploaded_by']}")
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
        
        # === START: BUG FIX & LOGIC IMPROVEMENT ===
        submit_disabled = False
        submit_help = "Click to submit the risk."
        
        if approver_list:
            assigned_approver = st.selectbox("Assign to Approver *", approver_list)
        else:
            st.error("Cannot submit risk: No approvers are assigned to this company. Please add one in the Admin Panel.")
            assigned_approver = None # This will be None
            submit_disabled = True
            submit_help = "You must assign an approver to this company before logging a risk."

        submitted = st.form_submit_button("Submit Risk", disabled=submit_disabled, help=submit_help)
        
        if submitted:
            # Check for title and desc. Approver is handled by the disabled logic.
            if not all([title, desc]):
                st.error("Please fill all required fields (Title and Description).")
            # This 'elif' is a safety net, but should be unreachable if button is disabled
            elif not assigned_approver: 
                st.error("An approver must be selected.")
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
                send_email(assigned_approver, "New Risk Submission", f"Title: {title}\nSubmitted by: {user[2]}\nCompany: {selected_company_name}")
                st.success("Risk submitted successfully!")
                st.rerun()
        # === END: BUG FIX ===

# === EVIDENCE VAULT ===
elif page == "Evidence Vault":
    st.markdown("## Evidence Vault")
    risks = pd.read_sql("SELECT id, title FROM risks WHERE company_id=?", conn, params=(company_id,))
    if risks.empty:
        st.info("No risks logged yet.")
        if st.button("Log a New Risk", type="primary"):
            st.session_state.page = "Log a new Risk"
            st.rerun()
    else:
        risk_options = {row['title']: row['id'] for _, row in risks.iterrows()}
        selected_risk_title = st.selectbox("Select Risk", options=list(risk_options.keys()))
        risk_id = risk_options[selected_risk_title]
        uploaded = st.file_uploader("Upload Evidence", type=["pdf", "png", "jpg", "jpeg", "docx", "txt"], key="upload")
        if uploaded:
            c.execute("""INSERT INTO evidence
                           (risk_id, company_id, file_name, upload_date, uploaded_by, file_data)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                      (risk_id, company_id, uploaded.name, datetime.now().strftime("%Y-%m-%d"), user[1], uploaded.getvalue()))
            conn.commit()
            st.success(f"Uploaded: {uploaded.name}")
            st.rerun()
        evidence = pd.read_sql("""SELECT id, file_name, upload_date, uploaded_by, file_data
                                   FROM evidence WHERE risk_id=?""", conn, params=(risk_id,))
        if not evidence.empty:
            st.markdown("### Uploaded Evidence")
            for _, e in evidence.iterrows():
                col1, col2, col3 = st.columns([3, 1, 1])
                with col1:
                    st.write(f"**{e['file_name']}**")
                    st.caption(f"Uploaded by {e['uploaded_by']} on {e['upload_date']}")
                with col2:
                    st.download_button("Download", data=e['file_data'], file_name=e['file_name'], key=f"dl*{e['id']}")
                with col3:
                    if st.button("Delete", key=f"del*{e['id']}"):
                        c.execute("DELETE FROM evidence WHERE id=?", (e['id'],))
                        conn.commit()
                        st.rerun()
        else:
            st.info("No evidence uploaded for this risk yet.")
# === VENDOR MANAGEMENT ===
elif page == "Vendor Management":
    st.markdown("## Vendor NIST Questionnaire")
    with st.expander("NIST Questions", expanded=True):
        questions = pd.read_sql("SELECT id, question FROM vendor_questions WHERE company_id=?", conn, params=(company_id,))
        if questions.empty:
            init_db()
            questions = pd.read_sql("SELECT id, question FROM vendor_questions WHERE company_id=?", conn, params=(company_id,))
        edited = st.data_editor(questions, num_rows="dynamic")
        if st.button("Save Questions"):
            c.execute("DELETE FROM vendor_questions WHERE company_id=?", (company_id,))
            for _, row in edited.iterrows():
                if row['question']: c.execute("INSERT INTO vendor_questions (question, company_id) VALUES (?, ?)", (row['question'], company_id))
            conn.commit()
            st.rerun()
    with st.expander("Add Vendor"):
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
            if st.button("Send Questionnaire", key=f"send*{v['id']}"):
                qs = pd.read_sql("SELECT question FROM vendor_questions WHERE company_id=?", conn, params=(company_id,))
                for _, q in qs.iterrows():
                    c.execute("INSERT OR IGNORE INTO vendor_questionnaire (vendor_id, question, sent_date) VALUES (?, ?, ?)",
                              (v['id'], q['question'], datetime.now().strftime("%Y-%m-%d")))
                conn.commit()
                st.success("Sent")
            q_df = pd.read_sql("SELECT id, question, answer FROM vendor_questionnaire WHERE vendor_id=?", conn, params=(v['id'],))
            if not q_df.empty:
                edited = st.data_editor(q_df, num_rows="dynamic", key=f"q*{v['id']}")
                if st.button("Save Answers", key=f"saveq*{v['id']}"):
                    for _, row in edited.iterrows():
                        c.execute("UPDATE vendor_questionnaire SET answer=?, answered_date=? WHERE id=?",
                                  (row['answer'], datetime.now().strftime("%Y-%m-%d"), row['id']))
                    conn.commit()
                    st.success("Saved")
# === REPORTS ===
elif page == "Reports":
    st.markdown("## Reports")
    
    # === START: NEW REPORTING SECTION ===
    nist_categories = ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
    
    tab1, tab2 = st.tabs(["NIST & Compliance Reports", "Custom Report Builder"])

    with tab1:
        st.subheader("NIST & Compliance Reports")
        
        # Function to create downloadable PDF for pre-built reports
        def create_download_button(df, title, key):
            if not df.empty:
                pdf_data = generate_pdf_report(title, df)
                st.download_button(
                    label="Download as PDF",
                    data=pdf_data,
                    file_name=f"{title.lower().replace(' ', '_')}.pdf",
                    mime="application/pdf",
                    key=key
                )
            else:
                st.info("No data available for this report.")

        nist_tab1, nist_tab2, nist_tab3, nist_tab4, nist_tab5 = st.tabs([
            "Risk Heatmap", "Risk Count by Category", "High-Risk by Category", "Pending Risks by Category", "Mitigated Risks by Category"
        ])
        
        with nist_tab1:
            st.markdown("### Overall Risk Heatmap")
            risks_df = pd.read_sql("SELECT risk_score FROM risks WHERE company_id=?", conn, params=(company_id,))
            high = len(risks_df[risks_df['risk_score'] >= 7])
            med = len(risks_df[(risks_df['risk_score'] >= 4) & (risks_df['risk_score'] < 7)])
            low = len(risks_df[risks_df['risk_score'] < 4])
            fig = go.Figure(data=[go.Bar(x=['High', 'Medium', 'Low'], y=[high, med, low], marker_color=['red', 'orange', 'green'])])
            fig.update_layout(title="Risk Distribution", xaxis_title="Level", yaxis_title="Count")
            st.plotly_chart(fig, use_container_width=True)

        with nist_tab2:
            st.markdown("### Risk Count by NIST Category")
            df_cat = pd.read_sql(
                "SELECT category, COUNT(*) as count FROM risks WHERE company_id=? GROUP BY category", 
                conn, params=(company_id,)
            )
            df_cat = df_cat.set_index("category")
            st.bar_chart(df_cat)
            create_download_button(df_cat.reset_index(), "Risk Count by Category", "pdf_cat")

        with nist_tab3:
            st.markdown("### High-Risk Items by Category")
            df_high = pd.read_sql(
                "SELECT title, category, risk_score, status, submitted_by FROM risks WHERE company_id=? AND risk_score >= 7 ORDER BY category",
                conn, params=(company_id,)
            )
            st.dataframe(df_high)
            create_download_button(df_high, "High Risk Items", "pdf_high")

        with nist_tab4:
            st.markdown("### Pending Risks by Category")
            df_pending = pd.read_sql(
                "SELECT title, category, submitted_by, submitted_date, approver_email FROM risks WHERE company_id=? AND status = 'Pending Approval' ORDER BY category",
                conn, params=(company_id,)
            )
            st.dataframe(df_pending)
            create_download_button(df_pending, "Pending Risks", "pdf_pending")

        with nist_tab5:
            st.markdown("### Mitigated Risks by Category")
            df_mitigated = pd.read_sql(
                "SELECT title, category, approved_by, approved_date FROM risks WHERE company_id=? AND status = 'Mitigated' ORDER BY category",
                conn, params=(company_id,)
            )
            st.dataframe(df_mitigated)
            create_download_button(df_mitigated, "Mitigated Risks", "pdf_mitigated")

    with tab2:
        st.subheader("Custom Report Builder")
        
        all_cols = ["id", "title", "description", "category", "likelihood", "impact", "status", "submitted_by", "submitted_date", "risk_score", "approver_email", "approved_by", "approved_date"]
        default_cols = ["title", "category", "status", "risk_score", "submitted_date", "approved_by"]
        
        with st.form("custom_report_form"):
            selected_cols = st.multiselect("1. Select Columns", all_cols, default=default_cols)
            
            col1, col2 = st.columns(2)
            with col1:
                selected_statuses = st.multiselect("2. Filter by Status (Optional)", ["Pending Approval", "Approved", "Rejected", "Mitigated"])
            with col2:
                selected_categories = st.multiselect("3. Filter by Category (Optional)", nist_categories)
            
            start_date = datetime.now() - timedelta(days=365)
            end_date = datetime.now()
            selected_date_range = st.date_input("4. Filter by Submitted Date (Optional)", [start_date, end_date])
            
            submit_report = st.form_submit_button("Generate Report")

        if submit_report:
            if not selected_cols:
                st.error("Please select at least one column.")
            elif len(selected_date_range) != 2:
                st.error("Please select a valid date range (start and end).")
            else:
                # Build Dynamic Query
                query = f"SELECT {', '.join(selected_cols)} FROM risks WHERE company_id=?"
                params = [company_id]
                
                # Date Range
                query += " AND submitted_date BETWEEN ? AND ?"
                params.extend([selected_date_range[0].strftime('%Y-%m-%d'), selected_date_range[1].strftime('%Y-%m-%d')])
                
                # Statuses
                if selected_statuses:
                    query += f" AND status IN ({','.join(['?'] * len(selected_statuses))})"
                    params.extend(selected_statuses)
                
                # Categories
                if selected_categories:
                    query += f" AND category IN ({','.join(['?'] * len(selected_categories))})"
                    params.extend(selected_categories)
                
                query += " ORDER BY submitted_date DESC"
                
                # Execute query and display
                custom_df = pd.read_sql(query, conn, params=tuple(params))
                st.dataframe(custom_df)
                
                # Store in session state for download
                st.session_state.custom_report_df = custom_df

        # Handle PDF Download outside the form
        if "custom_report_df" in st.session_state and not st.session_state.custom_report_df.empty:
            st.markdown("---")
            pdf_data = generate_pdf_report("Custom Risk Report", st.session_state.custom_report_df)
            st.download_button(
                label="Download Custom Report as PDF",
                data=pdf_data,
                file_name="custom_risk_report.pdf",
                mime="application/pdf"
            )

    # === END: NEW REPORTING SECTION ===

# === ADMIN PANEL ===
elif page == "Admin Panel" and user[4] == "Admin":
    st.markdown("## Admin Panel")
    companies_df = pd.read_sql("SELECT id, name FROM companies", conn)
    with st.expander("Add User"):
        with st.form("add_user"):
            new_username = st.text_input("Username")
            new_email = st.text_input("Email")
            new_password = st.text_input("Password", type="password")
            new_role = st.selectbox("Role", ["Admin", "Approver", "User"])
            new_company = st.selectbox("Company", companies_df['name'])
            if st.form_submit_button("Create"):
                if not all([new_username, new_email, new_password]):
                    st.error("Required")
                else:
                    hashed = hashlib.sha256(new_password.encode()).hexdigest()
                    comp_id = companies_df[companies_df['name'] == new_company].iloc[0]['id']
                    c.execute("INSERT OR IGNORE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                              (new_username, new_email, hashed, new_role, comp_id))
                    conn.commit()
                    st.success("Created")
                    st.rerun()
    users_df = pd.read_sql("SELECT id, username, email, role, company_id FROM users", conn)
    comp_map = dict(zip(companies_df['id'], companies_df['name']))
    users_df['company'] = users_df['company_id'].map(comp_map)
    for _, row in users_df.iterrows():
        col1, col2 = st.columns([3, 1])
        with col1:
            if st.button(f"**{row['username']}** – {row['email']} – {row['role']} – {row['company']}", key=f"user*{row['id']}"):
                st.session_state.edit_user = row.to_dict()
                st.rerun()
        with col2:
            if st.button("Reset", key=f"reset_{row['id']}"):
                new_pass = "Joval2025"
                hashed = hashlib.sha256(new_pass.encode()).hexdigest()
                c.execute("UPDATE users SET password=? WHERE id=?", (hashed, row['id']))
                conn.commit()
                st.success(f"Reset to: {new_pass}")
                send_email(row['email'], "Password Reset", f"New: {new_pass}")
    if "edit_user" in st.session_state:
        edit_data = st.session_state.edit_user
        with st.form("edit_user_form"):
            edit_username = st.text_input("Username", edit_data['username'])
            edit_email = st.text_input("Email", edit_data['email'])
            edit_role = st.selectbox("Role", ["Admin", "Approver", "User"], index=["Admin", "Approver", "User"].index(edit_data['role']))
            
            company_names_list = companies_df['name'].tolist()
            current_comp_id = edit_data['company_id']
            current_comp_name = comp_map.get(current_comp_id)
            company_idx = 0 
            if current_comp_name in company_names_list:
                company_idx = company_names_list.index(current_comp_name)
                
            edit_company = st.selectbox("Company", company_names_list, index=company_idx)

            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button("Save"):
                    comp_id = companies_df[companies_df['name'] == edit_company].iloc[0]['id']
                    c.execute("UPDATE users SET username=?, email=?, role=?, company_id=? WHERE id=?",
                              (edit_username, edit_email, edit_role, comp_id, edit_data['id']))
                    conn.commit()
                    st.success("Updated")
                    del st.session_state.edit_user
                    st.rerun()
            with col2:
                if st.form_submit_button("Cancel"):
                    del st.session_state.edit_user
                    st.rerun()
# === AUDIT TRAIL ===
elif page == "Audit Trail" and user[4] == "Admin":
    st.markdown("## Audit Trail")
    trail = pd.read_sql("SELECT timestamp, user_email, action, details FROM audit_trail ORDER BY timestamp DESC", conn)
    for _, row in trail.iterrows():
        with st.expander(f"{row['timestamp']} – {row['user_email']} – {row['action']}"):
            st.write(row['details'] or "—")
# === FOOTER ===
st.markdown("---\n© 2025 Joval Wines | jovalwines.com.au")
