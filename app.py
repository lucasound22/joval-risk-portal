# app.py – JOVAL WINES RISK PORTAL v40.0 – DIRECT CONNECTION FIX
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

# === CONFIGURATION ===
DB_FILE = "joval_portal.db"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "joval.risk.portal@gmail.com"
SENDER_PASSWORD = "your_app_password_here" 

# === DATABASE MANAGER (The Fix) ===
# We remove @st.cache_resource. We open/close on EVERY operation to ensure data freshness.
def run_query(query, params=None, is_write=False):
    """
    Executes a query against the database.
    If is_write=True: Returns the number of rows affected (int).
    If is_write=False: Returns a pandas DataFrame of the results.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        if is_write:
            c = conn.cursor()
            c.execute(query, params or ())
            conn.commit()
            return c.rowcount
        else:
            return pd.read_sql(query, conn, params=params)
    except Exception as e:
        st.error(f"Database Error: {e}")
        return 0 if is_write else pd.DataFrame()
    finally:
        if conn:
            conn.close()

def init_db():
    """Ensures all tables exist on startup."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Core Tables
    c.execute("""CREATE TABLE IF NOT EXISTS companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT UNIQUE, password TEXT, role TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS risks (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, title TEXT, description TEXT, category TEXT, likelihood TEXT, impact TEXT, status TEXT, submitted_by TEXT, submitted_date TEXT, risk_score INTEGER, approver_email TEXT, approver_notes TEXT, approved_by TEXT, approved_date TEXT, workflow_step TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER, company_id INTEGER, file_name TEXT, upload_date TEXT, uploaded_by TEXT, file_data BLOB)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendors (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, contact_email TEXT, risk_level TEXT, last_assessment TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questionnaire (id INTEGER PRIMARY KEY AUTOINCREMENT, vendor_id INTEGER, question TEXT, answer TEXT, answered_date TEXT, sent_date TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questions (id INTEGER PRIMARY KEY AUTOINCREMENT, question TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_trail (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_email TEXT, action TEXT, details TEXT)""")

    # Seed Data (Only if empty)
    c.execute("SELECT count(*) FROM companies")
    if c.fetchone()[0] == 0:
        companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
        c.executemany("INSERT INTO companies (name) VALUES (?)", [(n,) for n in companies])
        
        hashed = hashlib.sha256("Joval2025".encode()).hexdigest()
        # Create Admins and Approvers
        for i, comp in enumerate(companies, 1):
            admin_email = f"admin@{comp.lower().replace(' ', '')}.com.au"
            c.execute("INSERT INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)", ("admin", admin_email, hashed, "Admin", i))
            approver_email = f"approver@{comp.lower().replace(' ', '')}.com.au"
            c.execute("INSERT INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)", (f"approver_{comp.lower().replace(' ', '')}", approver_email, hashed, "Approver", i))

    conn.commit()
    conn.close()

# === EMAIL UTILS ===
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
        print(f"Email failed: {e}")

# === HELPERS ===
def calculate_risk_score(likelihood, impact):
    scores = {"Low": 1, "Medium": 2, "High": 3}
    return scores.get(likelihood, 1) * scores.get(impact, 1)

def get_risk_color(score):
    if score >= 7: return "red"
    elif score >= 4: return "orange"
    else: return "green"

def log_action(user_email, action, details=""):
    run_query("INSERT INTO audit_trail (timestamp, user_email, action, details) VALUES (?, ?, ?, ?)", 
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user_email, action, details), is_write=True)

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

# === INITIALIZATION ===
if "init_done" not in st.session_state:
    init_db()
    st.session_state.init_done = True

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
            hashed = hashlib.sha256(password.encode()).hexdigest()
            users = run_query("SELECT * FROM users WHERE username=? AND password=?", (username, hashed))
            if not users.empty:
                st.session_state.user = users.iloc[0].to_list() # Convert df row to list
                log_action(st.session_state.user[2], "LOGIN")
                st.rerun()
            else:
                st.error("Invalid credentials")
    st.stop()

user = st.session_state.user
# user structure: [id, username, email, password, role, company_id]
company_id = user[5]
company_name_df = run_query("SELECT name FROM companies WHERE id=?", (company_id,))
company_name = company_name_df.iloc[0]['name'] if not company_name_df.empty else "Unknown"

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
    
    # Direct queries - no caching
    risks = run_query("SELECT id, title, status, risk_score, description, approved_by FROM risks WHERE company_id=?", (company_id,))
    
    high_risks = len(risks[risks['risk_score'] >= 7])
    total_risks = len(risks)
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f'<div class="metric-card"><h2>{high_risks}</h2><p>High Risks</p></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="metric-card"><h2>{total_risks}</h2><p>Total Risks</p></div>', unsafe_allow_html=True)
    
    st.markdown("---")
    if risks.empty:
        st.info("No risks logged for this company yet.")
    else:
        for _, r in risks.iterrows():
            color = get_risk_color(r['risk_score'])
            bg = "#ffe6e6" if color == "red" else "#fff4e6" if color == "orange" else "#e6f7e6"
            approval = f"<span class='approval-badge'>Approved by {r['approved_by']}</span>" if r['approved_by'] else ""
            
            if st.button(f"**{r['title']}** – Score: {r['risk_score']} | {r['status']}", key=f"risk*{r['id']}"):
                st.session_state.selected_risk = r['id']
                st.session_state.page = "Risk Detail"
                st.rerun()
            st.markdown(f'<div class="clickable-risk" style="background:{bg};"><small>{r["description"][:100]}... {approval}</small></div>', unsafe_allow_html=True)

# === LOG A NEW RISK (REWRITTEN) ===
elif page == "Log a new Risk":
    st.markdown("## Log a New Risk")
    
    # 1. Fetch Companies
    companies_df = run_query("SELECT id, name FROM companies")
    company_options = companies_df['name'].tolist()
    
    # 2. Selection Logic
    try:
        default_idx = company_options.index(company_name)
    except ValueError:
        default_idx = 0
        
    st.markdown("### 1. Select Company")
    selected_company_name = st.selectbox("Company *", company_options, index=default_idx)
    
    selected_company_id = companies_df[companies_df['name'] == selected_company_name].iloc[0]['id']
    
    # 3. Fetch Approvers for selected company
    approvers_df = run_query("SELECT email FROM users WHERE role='Approver' AND company_id=?", (selected_company_id,))
    approver_list = approvers_df['email'].tolist()

    st.markdown("---") 
    st.markdown("### 2. Enter Risk Details")

    with st.form("new_risk_form"):
        title = st.text_input("Title *")
        desc = st.text_area("Description *")
        category = st.selectbox("Category *", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
        likelihood = st.selectbox("Likelihood *", ["Low", "Medium", "High"])
        impact = st.selectbox("Impact *", ["Low", "Medium", "High"])
        
        submit_disabled = False
        if approver_list:
            assigned_approver = st.selectbox("Assign to Approver *", approver_list)
        else:
            st.error(f"No approvers found for {selected_company_name}. Please add one in Admin Panel.")
            assigned_approver = None
            submit_disabled = True

        submitted = st.form_submit_button("Submit Risk", disabled=submit_disabled)
        
        if submitted:
            if not title or not desc:
                st.error("Title and Description are required.")
            elif not assigned_approver:
                st.error("Approver required.")
            else:
                score = calculate_risk_score(likelihood, impact)
                # Direct Write
                rows = run_query("""INSERT INTO risks 
                                    (company_id, title, description, category, likelihood, impact, status, 
                                     submitted_by, submitted_date, risk_score, approver_email, workflow_step) 
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                 (selected_company_id, title, desc, category, likelihood, impact, "Pending Approval",
                                  user[2], datetime.now().strftime("%Y-%m-%d"), score, assigned_approver, "awaiting_approval"),
                                 is_write=True)
                
                if rows > 0:
                    log_action(user[2], "RISK_SUBMITTED", title)
                    send_email(assigned_approver, "New Risk", f"Risk '{title}' logged by {user[2]}")
                    st.success("Risk Logged Successfully!")
                    st.session_state.page = "Dashboard"
                    st.rerun()
                else:
                    st.error("Database write failed. No rows affected.")

    # --- DEBUG SECTION (Visible to Admin Only) ---
    if user[4] == "Admin":
        with st.expander("System Diagnostics (Debug)"):
            count = run_query("SELECT count(*) as c FROM risks").iloc[0]['c']
            st.write(f"Total Risks in DB: {count}")
            last_5 = run_query("SELECT * FROM risks ORDER BY id DESC LIMIT 5")
            st.write("Last 5 Risks in DB:", last_5)

# === MY APPROVALS ===
elif page == "My Approvals" and user[4] == "Approver":
    st.markdown("## My Approvals")
    pending = run_query("SELECT id, title, risk_score, submitted_by, submitted_date FROM risks WHERE approver_email=? AND status='Pending Approval' AND company_id=?", (user[2], company_id))
    if pending.empty:
        st.info("No pending approvals.")
    for _, r in pending.iterrows():
        if st.button(f"**{r['title']}** – Score: {r['risk_score']} – {r['submitted_by']}", key=f"rev*{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Risk Detail"
            st.rerun()

# === RISK DETAIL ===
elif page == "Risk Detail" and "selected_risk" in st.session_state:
    risk_id = st.session_state.selected_risk
    risk_df = run_query("SELECT * FROM risks WHERE id=?", (risk_id,))
    if not risk_df.empty:
        risk = risk_df.iloc[0]
        st.markdown(f"## Edit Risk: {risk['title']}")
        with st.form("edit_risk"):
            title = st.text_input("Title", risk['title'])
            desc = st.text_area("Description", risk['description'])
            category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"], index=["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"].index(risk['category']))
            likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"], index=["Low", "Medium", "High"].index(risk['likelihood']))
            impact = st.selectbox("Impact", ["Low", "Medium", "High"], index=["Low", "Medium", "High"].index(risk['impact']))
            status = st.selectbox("Status", ["Pending Approval", "Approved", "Rejected", "Mitigated"], index=["Pending Approval", "Approved", "Rejected", "Mitigated"].index(risk['status']))
            notes = st.text_area("Approver Notes", risk['approver_notes'] or "")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button("Save Changes"):
                    score = calculate_risk_score(likelihood, impact)
                    rows = run_query("""UPDATE risks SET title=?, description=?, category=?, likelihood=?, impact=?,
                                 status=?, risk_score=?, approver_notes=? WHERE id=?""",
                              (title, desc, category, likelihood, impact, status, score, notes, risk_id), is_write=True)
                    if rows > 0:
                        st.success("Updated!")
                        st.rerun()
            with col2:
                if st.form_submit_button("Back"):
                    del st.session_state.selected_risk
                    st.session_state.page = "Dashboard"
                    st.rerun()
                    
        evidence = run_query("SELECT file_name, upload_date, uploaded_by FROM evidence WHERE risk_id=?", (risk_id,))
        if not evidence.empty:
            st.markdown("### Evidence")
            for _, e in evidence.iterrows():
                st.write(f"**{e['file_name']}**")
    else:
        st.error("Risk not found.")
        if st.button("Back"):
            del st.session_state.selected_risk
            st.session_state.page = "Dashboard"
            st.rerun()

# === EVIDENCE VAULT ===
elif page == "Evidence Vault":
    st.markdown("## Evidence Vault")
    risks = run_query("SELECT id, title FROM risks WHERE company_id=?", (company_id,))
    if risks.empty:
        st.info("No risks logged yet.")
    else:
        risk_options = {row['title']: row['id'] for _, row in risks.iterrows()}
        selected_risk_title = st.selectbox("Select Risk", options=list(risk_options.keys()))
        risk_id = risk_options[selected_risk_title]
        uploaded = st.file_uploader("Upload Evidence", type=["pdf", "png", "jpg", "jpeg", "docx", "txt"], key="upload")
        if uploaded:
            run_query("INSERT INTO evidence (risk_id, company_id, file_name, upload_date, uploaded_by, file_data) VALUES (?, ?, ?, ?, ?, ?)",
                      (risk_id, company_id, uploaded.name, datetime.now().strftime("%Y-%m-%d"), user[1], uploaded.getvalue()), is_write=True)
            st.success("Uploaded!")
            st.rerun()
            
        evidence = run_query("SELECT id, file_name, upload_date, uploaded_by, file_data FROM evidence WHERE risk_id=?", (risk_id,))
        if not evidence.empty:
            st.markdown("### Uploaded Evidence")
            for _, e in evidence.iterrows():
                col1, col2, col3 = st.columns([3, 1, 1])
                with col1: st.write(f"**{e['file_name']}**")
                with col2: st.download_button("Download", data=e['file_data'], file_name=e['file_name'], key=f"dl{e['id']}")
                with col3: 
                    if st.button("Delete", key=f"del{e['id']}"):
                        run_query("DELETE FROM evidence WHERE id=?", (e['id'],), is_write=True)
                        st.rerun()

# === VENDOR MANAGEMENT ===
elif page == "Vendor Management":
    st.markdown("## Vendor NIST Questionnaire")
    with st.expander("NIST Questions", expanded=True):
        questions = run_query("SELECT id, question FROM vendor_questions WHERE company_id=?", (company_id,))
        edited = st.data_editor(questions, num_rows="dynamic")
        if st.button("Save Questions"):
            run_query("DELETE FROM vendor_questions WHERE company_id=?", (company_id,), is_write=True)
            for _, row in edited.iterrows():
                if row['question']:
                    run_query("INSERT INTO vendor_questions (question, company_id) VALUES (?, ?)", (row['question'], company_id), is_write=True)
            st.rerun()
            
    with st.expander("Add Vendor"):
        with st.form("new_vendor"):
            v_name = st.text_input("Name")
            v_email = st.text_input("Email")
            v_level = st.selectbox("Risk Level", ["Low", "Medium", "High"])
            if st.form_submit_button("Add"):
                run_query("INSERT INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
                          (v_name, v_email, v_level, datetime.now().strftime("%Y-%m-%d"), company_id), is_write=True)
                st.rerun()
                
    vendors = run_query("SELECT id, name, risk_level FROM vendors WHERE company_id=?", (company_id,))
    for _, v in vendors.iterrows():
        with st.expander(f"{v['name']} – {v['risk_level']}"):
            if st.button("Send Questionnaire", key=f"send{v['id']}"):
                qs = run_query("SELECT question FROM vendor_questions WHERE company_id=?", (company_id,))
                for _, q in qs.iterrows():
                    run_query("INSERT OR IGNORE INTO vendor_questionnaire (vendor_id, question, sent_date) VALUES (?, ?, ?)",
                              (v['id'], q['question'], datetime.now().strftime("%Y-%m-%d")), is_write=True)
                st.success("Sent")
            
            q_df = run_query("SELECT id, question, answer FROM vendor_questionnaire WHERE vendor_id=?", (v['id'],))
            if not q_df.empty:
                edited = st.data_editor(q_df, num_rows="dynamic", key=f"q{v['id']}")
                if st.button("Save Answers", key=f"saveq{v['id']}"):
                    for _, row in edited.iterrows():
                        run_query("UPDATE vendor_questionnaire SET answer=?, answered_date=? WHERE id=?",
                                  (row['answer'], datetime.now().strftime("%Y-%m-%d"), row['id']), is_write=True)
                    st.success("Saved")

# === REPORTS ===
elif page == "Reports":
    st.markdown("## Reports")
    tab1, tab2 = st.tabs(["NIST & Compliance Reports", "Custom Report Builder"])
    with tab1:
        risks_df = run_query("SELECT risk_score FROM risks WHERE company_id=?", (company_id,))
        if not risks_df.empty:
            high = len(risks_df[risks_df['risk_score'] >= 7])
            med = len(risks_df[(risks_df['risk_score'] >= 4) & (risks_df['risk_score'] < 7)])
            low = len(risks_df[risks_df['risk_score'] < 4])
            fig = go.Figure(data=[go.Bar(x=['High', 'Medium', 'Low'], y=[high, med, low], marker_color=['red', 'orange', 'green'])])
            st.plotly_chart(fig, use_container_width=True)
        
        if st.button("Download Risk Register"):
            full_df = run_query("SELECT * FROM risks WHERE company_id=?", (company_id,))
            pdf = generate_pdf_report("Risk Register", full_df)
            st.download_button("Download PDF", pdf, "risk_register.pdf", "application/pdf")

    with tab2:
        st.write("Custom Builder")
        # (Simplified for brevity in this stable version, core report logic is same)
        all_risks = run_query("SELECT * FROM risks WHERE company_id=?", (company_id,))
        st.dataframe(all_risks)

# === ADMIN PANEL ===
elif page == "Admin Panel" and user[4] == "Admin":
    st.markdown("## Admin Panel")
    companies_df = run_query("SELECT id, name FROM companies")
    
    with st.expander("Add User"):
        with st.form("add_user"):
            new_username = st.text_input("Username")
            new_email = st.text_input("Email")
            new_password = st.text_input("Password", type="password")
            new_role = st.selectbox("Role", ["Admin", "Approver", "User"])
            new_company = st.selectbox("Company", companies_df['name'])
            if st.form_submit_button("Create"):
                hashed = hashlib.sha256(new_password.encode()).hexdigest()
                comp_id = companies_df[companies_df['name'] == new_company].iloc[0]['id']
                run_query("INSERT INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                          (new_username, new_email, hashed, new_role, comp_id), is_write=True)
                st.success("Created")
                st.rerun()
    
    users_df = run_query("SELECT id, username, email, role, company_id FROM users")
    # Map company names
    comp_map = dict(zip(companies_df['id'], companies_df['name']))
    users_df['company'] = users_df['company_id'].map(comp_map)
    
    for _, row in users_df.iterrows():
        col1, col2 = st.columns([3, 1])
        with col1:
            if st.button(f"**{row['username']}** – {row['email']} – {row['company']}", key=f"u{row['id']}"):
                st.session_state.edit_user = row.to_dict()
                st.rerun()
        with col2:
            if st.button("Reset", key=f"r{row['id']}"):
                hashed = hashlib.sha256("Joval2025".encode()).hexdigest()
                run_query("UPDATE users SET password=? WHERE id=?", (hashed, row['id']), is_write=True)
                st.success("Reset to Joval2025")

    if "edit_user" in st.session_state:
        edit = st.session_state.edit_user
        with st.form("edit_u"):
            uname = st.text_input("Username", edit['username'])
            uemail = st.text_input("Email", edit['email'])
            # Safe index finding
            try:
                curr_comp_name = comp_map.get(edit['company_id'], companies_df['name'].iloc[0])
                c_idx = companies_df['name'].tolist().index(curr_comp_name)
            except:
                c_idx = 0
            
            ucomp = st.selectbox("Company", companies_df['name'], index=c_idx)
            
            if st.form_submit_button("Save"):
                cid = companies_df[companies_df['name'] == ucomp].iloc[0]['id']
                run_query("UPDATE users SET username=?, email=?, company_id=? WHERE id=?", (uname, uemail, cid, edit['id']), is_write=True)
                del st.session_state.edit_user
                st.rerun()

# === AUDIT TRAIL ===
elif page == "Audit Trail" and user[4] == "Admin":
    st.markdown("## Audit Trail")
    trail = run_query("SELECT timestamp, user_email, action, details FROM audit_trail ORDER BY timestamp DESC")
    st.dataframe(trail)

# === FOOTER ===
st.markdown("---\n© 2025 Joval Wines | jovalwines.com.au")
