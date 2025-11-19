import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import os
import smtplib
import urllib.request
from datetime import datetime
from io import BytesIO

# ReportLab Imports for PDF Generation
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch

# Plotly for Charts
import plotly.graph_objects as go

# Email Imports
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ==========================================
# 1. CONFIGURATION & CONSTANTS
# ==========================================
DB_FILE = "joval_portal.db"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "joval.risk.portal@gmail.com"
SENDER_PASSWORD = "your_app_password_here" 

# ==========================================
# 2. DATABASE ENGINE (Direct Connection)
# ==========================================
def get_connection():
    """Creates a fresh connection to the DB for every operation."""
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def run_query(query, params=None, is_write=False):
    """
    Executes a SQL query.
    - is_write=True: Commits changes and returns the number of affected rows.
    - is_write=False: Returns a Pandas DataFrame of the results.
    """
    conn = get_connection()
    try:
        c = conn.cursor()
        if is_write:
            c.execute(query, params or ())
            conn.commit()
            return c.rowcount
        else:
            return pd.read_sql(query, conn, params=params)
    except Exception as e:
        st.error(f"Database Error: {e}")
        return 0 if is_write else pd.DataFrame()
    finally:
        conn.close()

def init_db():
    """Ensures tables exist on startup."""
    conn = get_connection()
    c = conn.cursor()
    
    # Schema Definition
    c.execute("""CREATE TABLE IF NOT EXISTS companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT UNIQUE, password TEXT, role TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS risks (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, title TEXT, description TEXT, category TEXT, likelihood TEXT, impact TEXT, status TEXT, submitted_by TEXT, submitted_date TEXT, risk_score INTEGER, approver_email TEXT, approver_notes TEXT, approved_by TEXT, approved_date TEXT, workflow_step TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER, company_id INTEGER, file_name TEXT, upload_date TEXT, uploaded_by TEXT, file_data BLOB)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendors (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, contact_email TEXT, risk_level TEXT, last_assessment TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questionnaire (id INTEGER PRIMARY KEY AUTOINCREMENT, vendor_id INTEGER, question TEXT, answer TEXT, answered_date TEXT, sent_date TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questions (id INTEGER PRIMARY KEY AUTOINCREMENT, question TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_trail (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_email TEXT, action TEXT, details TEXT)""")

    # Seed Companies if empty
    c.execute("SELECT count(*) FROM companies")
    if c.fetchone()[0] == 0:
        companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
        for comp in companies:
            c.execute("INSERT OR IGNORE INTO companies (name) VALUES (?)", (comp,))
        
        # Map IDs
        c.execute("SELECT id, name FROM companies")
        comp_rows = c.fetchall()
        
        hashed = hashlib.sha256("Joval2025".encode()).hexdigest()
        
        for c_id, c_name in comp_rows:
            # Create Admin (Only once generally, but per company logic here)
            admin_email = f"admin@{c_name.lower().replace(' ', '')}.com.au"
            if c_name == "Joval Wines": # Main Admin
                 c.execute("INSERT OR IGNORE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)", 
                          ("admin", "admin@jovalwines.com.au", hashed, "Admin", c_id))
            
            # Create Approvers
            approver_email = f"approver@{c_name.lower().replace(' ', '')}.com.au"
            c.execute("INSERT OR IGNORE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)", 
                      (f"approver_{c_name.lower().replace(' ', '')}", approver_email, hashed, "Approver", c_id))

    conn.commit()
    conn.close()

# Run Init
if not os.path.exists(DB_FILE):
    init_db()
else:
    init_db() # Run anyway to ensure schema

# ==========================================
# 3. HELPER FUNCTIONS
# ==========================================
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
        print(f"Email Error: {e}")

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
    story.append(Spacer(1, 20))
    if isinstance(content, pd.DataFrame):
        content_str = content.astype(str).applymap(lambda x: (x[:50] + '...') if len(x) > 50 else x)
        data = [content.columns.tolist()] + content_str.values.tolist()
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a1a')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTSIZE', (0,0), (-1,-1), 8)
        ]))
        story.append(table)
    doc.build(story)
    buffer.seek(0)
    return buffer

# ==========================================
# 4. UI SETUP
# ==========================================
st.set_page_config(page_title="Joval Risk Portal", layout="wide")
st.markdown("""
<style>
    .header {background: #1a1a1a; color: white; padding: 2rem; text-align: center;}
    .metric-card {background: white; padding: 1.5rem; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
    .clickable-risk {cursor: pointer; padding: 0.75rem; border-radius: 8px; margin: 0.25rem 0;}
    .approval-badge {background: #e6f7ff; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.8rem;}
</style>""", unsafe_allow_html=True)
st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal</p></div>', unsafe_allow_html=True)

# ==========================================
# 5. AUTHENTICATION
# ==========================================
if "user" not in st.session_state:
    with st.sidebar:
        st.markdown("### Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            hashed = hashlib.sha256(password.encode()).hexdigest()
            users = run_query("SELECT * FROM users WHERE username=? AND password=?", (username, hashed))
            if not users.empty:
                st.session_state.user = users.iloc[0].to_list()
                log_action(st.session_state.user[2], "LOGIN")
                st.rerun()
            else:
                st.error("Invalid credentials")
    st.stop()

user = st.session_state.user
# user schema: [id, username, email, password, role, company_id]

# Fetch Company Name
comp_df = run_query("SELECT name FROM companies WHERE id=?", (user[5],))
user_company_name = comp_df.iloc[0]['name'] if not comp_df.empty else "Unknown"

# ==========================================
# 6. SIDEBAR NAVIGATION
# ==========================================
with st.sidebar:
    st.markdown("### Playbook Tracker")
    st.markdown("**Open Playbook Tracker App**")
    st.markdown("---")
    st.markdown(f"**{user[1]}** • {user_company_name}")
    st.markdown("---")
    
    pages = ["Dashboard", "Log a new Risk", "Evidence Vault", "Vendor Management", "Reports"]
    if user[4] == "Approver": pages.insert(1, "My Approvals")
    if user[4] == "Admin": pages += ["Audit Trail", "Admin Panel"]
    
    for p in pages:
        if st.button(p, key=f"nav_{p}"):
            st.session_state.page = p
            st.rerun()

page = st.session_state.get("page", "Dashboard")

# ==========================================
# 7. PAGE: DASHBOARD
# ==========================================
if page == "Dashboard":
    st.markdown("## Dashboard")
    
    # Admin View Logic
    view_company_id = user[5]
    if user[4] == "Admin":
        all_comps = run_query("SELECT id, name FROM companies")
        comp_opts = all_comps['name'].tolist()
        try:
            def_idx = comp_opts.index(user_company_name)
        except:
            def_idx = 0
        view_name = st.selectbox("Viewing Dashboard For:", comp_opts, index=def_idx)
        view_company_id = all_comps[all_comps['name'] == view_name].iloc[0]['id']
    
    risks = run_query("SELECT * FROM risks WHERE company_id=?", (view_company_id,))
    
    col1, col2 = st.columns(2)
    with col1:
        high = len(risks[risks['risk_score'] >= 7])
        st.markdown(f'<div class="metric-card"><h2>{high}</h2><p>High Risks</p></div>', unsafe_allow_html=True)
    with col2:
        total = len(risks)
        st.markdown(f'<div class="metric-card"><h2>{total}</h2><p>Total Risks</p></div>', unsafe_allow_html=True)
        
    st.write("---")
    if risks.empty:
        st.info(f"No risks logged for this company yet.")
    else:
        for _, r in risks.iterrows():
            color = get_risk_color(r['risk_score'])
            bg = "#ffe6e6" if color == "red" else "#fff4e6" if color == "orange" else "#e6f7e6"
            
            if st.button(f"{r['title']} (Score: {r['risk_score']}) - {r['status']}", key=f"r_{r['id']}"):
                st.session_state.selected_risk = r['id']
                st.session_state.page = "Risk Detail"
                st.rerun()
            st.markdown(f'<div class="clickable-risk" style="background:{bg};"><small>{r["description"]}</small></div>', unsafe_allow_html=True)

# ==========================================
# 8. PAGE: LOG A NEW RISK
# ==========================================
elif page == "Log a new Risk":
    st.markdown("## Log a New Risk")
    comps = run_query("SELECT id, name FROM companies")
    
    # Default selection
    try:
        def_idx = comps['name'].tolist().index(user_company_name)
    except:
        def_idx = 0
        
    c_name = st.selectbox("Company", comps['name'].tolist(), index=def_idx)
    c_id = comps[comps['name'] == c_name].iloc[0]['id']
    
    approvers = run_query("SELECT email FROM users WHERE role='Approver' AND company_id=?", (c_id,))
    
    # Fallback if no approver exists
    if approvers.empty:
        approver_list = ["admin@jovalwines.com.au"]
        st.warning("No approvers found for this company. Defaulting to Admin.")
    else:
        approver_list = approvers['email'].tolist()
        
    approver = st.selectbox("Approver", approver_list)
    
    with st.form("risk_form"):
        title = st.text_input("Title")
        desc = st.text_area("Description")
        cat = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
        lik = st.selectbox("Likelihood", ["Low", "Medium", "High"])
        imp = st.selectbox("Impact", ["Low", "Medium", "High"])
        
        if st.form_submit_button("Submit Risk"):
            if not title or not desc:
                st.error("Title and Description are required.")
            else:
                score = calculate_risk_score(lik, imp)
                rows = run_query("""INSERT INTO risks (company_id, title, description, category, likelihood, impact, status, 
                                    submitted_by, submitted_date, risk_score, approver_email, workflow_step)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                 (c_id, title, desc, cat, lik, imp, "Pending Approval", user[2], 
                                  datetime.now().strftime("%Y-%m-%d"), score, approver, "awaiting"), is_write=True)
                
                if rows > 0:
                    st.success("Risk Logged Successfully!")
                    send_email(approver, "New Risk", f"Risk: {title}")
                    st.session_state.page = "Dashboard"
                    st.rerun()
                else:
                    st.error("Database Write Failed.")

# ==========================================
# 9. PAGE: RISK DETAIL
# ==========================================
elif page == "Risk Detail" and "selected_risk" in st.session_state:
    rid = st.session_state.selected_risk
    risk_df = run_query("SELECT * FROM risks WHERE id=?", (rid,))
    
    if not risk_df.empty:
        risk = risk_df.iloc[0]
        st.markdown(f"## Edit: {risk['title']}")
        with st.form("edit"):
            new_status = st.selectbox("Status", ["Pending Approval", "Approved", "Rejected", "Mitigated"], index=["Pending Approval", "Approved", "Rejected", "Mitigated"].index(risk['status']))
            new_notes = st.text_area("Notes", risk['approver_notes'] or "")
            if st.form_submit_button("Save"):
                run_query("UPDATE risks SET status=?, approver_notes=? WHERE id=?", (new_status, new_notes, rid), is_write=True)
                st.success("Saved!")
                st.rerun()
        
        st.write("### Evidence Vault")
        uploaded = st.file_uploader("Upload File")
        if uploaded:
            run_query("INSERT INTO evidence (risk_id, company_id, file_name, upload_date, uploaded_by, file_data) VALUES (?, ?, ?, ?, ?, ?)", 
                      (rid, risk['company_id'], uploaded.name, datetime.now().strftime("%Y-%m-%d"), user[1], uploaded.getvalue()), is_write=True)
            st.rerun()
        
        files = run_query("SELECT id, file_name, file_data FROM evidence WHERE risk_id=?", (rid,))
        for _, f in files.iterrows():
            col1, col2 = st.columns([3,1])
            col1.write(f['file_name'])
            col2.download_button("Download", f['file_data'], f['file_name'], key=f['id'])

        if st.button("Back"):
            del st.session_state.selected_risk
            st.session_state.page = "Dashboard"
            st.rerun()
    else:
        st.error("Risk not found.")
        st.session_state.page = "Dashboard"
        st.rerun()

# ==========================================
# 10. PAGE: EVIDENCE VAULT
# ==========================================
elif page == "Evidence Vault":
    st.markdown("## Evidence Vault")
    # Show all files for the current view company context
    # For admin, we might want to select company, but sticking to simple for stability:
    target_id = user[5]
    if user[4] == "Admin":
         comps = run_query("SELECT id, name FROM companies")
         c_view = st.selectbox("Select Company Vault", comps['name'].tolist())
         target_id = comps[comps['name'] == c_view].iloc[0]['id']

    files = run_query("SELECT id, file_name, upload_date, uploaded_by, file_data FROM evidence WHERE company_id=?", (target_id,))
    
    if files.empty:
        st.info("No evidence files found.")
    else:
        for _, f in files.iterrows():
             with st.expander(f"{f['file_name']} ({f['upload_date']})"):
                 st.download_button("Download", f['file_data'], f['file_name'], key=f"ev_{f['id']}")

# ==========================================
# 11. PAGE: VENDOR MANAGEMENT
# ==========================================
elif page == "Vendor Management":
    st.markdown("## Vendor Management")
    
    with st.form("add_ven"):
        vname = st.text_input("Vendor Name")
        vemail = st.text_input("Contact Email")
        vrisk = st.selectbox("Risk Level", ["Low", "Medium", "High"])
        if st.form_submit_button("Add Vendor"):
            run_query("INSERT INTO vendors (name, contact_email, risk_level, company_id) VALUES (?, ?, ?, ?)", 
                      (vname, vemail, vrisk, user[5]), is_write=True)
            st.success("Vendor Added")
            st.rerun()
            
    vendors = run_query("SELECT * FROM vendors WHERE company_id=?", (user[5],))
    st.dataframe(vendors)

# ==========================================
# 12. PAGE: REPORTS
# ==========================================
elif page == "Reports":
    st.markdown("## Reports")
    
    target_id = user[5]
    if user[4] == "Admin":
        comps = run_query("SELECT id, name FROM companies")
        c_view = st.selectbox("Select Company Report", comps['name'].tolist())
        target_id = comps[comps['name'] == c_view].iloc[0]['id']

    tab1, tab2 = st.tabs(["NIST & Compliance Reports", "Custom Report Builder"])

    with tab1:
        st.subheader("NIST & Compliance Reports")
        
        def create_download_button(df, title, key):
            if not df.empty:
                pdf_data = generate_pdf_report(title, df)
                st.download_button(label="Download PDF", data=pdf_data, file_name=f"{key}.pdf", mime="application/pdf", key=key)
            else:
                st.info("No data.")

        t1, t2, t3, t4 = st.tabs(["Risk Heatmap", "Risk by Category", "High Risks", "Pending Risks"])
        
        with t1:
            risks_df = run_query("SELECT risk_score FROM risks WHERE company_id=?", (target_id,))
            high = len(risks_df[risks_df['risk_score'] >= 7])
            med = len(risks_df[(risks_df['risk_score'] >= 4) & (risks_df['risk_score'] < 7)])
            low = len(risks_df[risks_df['risk_score'] < 4])
            fig = go.Figure(data=[go.Bar(x=['High', 'Medium', 'Low'], y=[high, med, low], marker_color=['red', 'orange', 'green'])])
            st.plotly_chart(fig, use_container_width=True)

        with t2:
            cat_df = run_query("SELECT category, count(*) as count FROM risks WHERE company_id=? GROUP BY category", (target_id,))
            if not cat_df.empty:
                st.bar_chart(cat_df.set_index("category"))

        with t3:
            high_df = run_query("SELECT title, risk_score, status FROM risks WHERE company_id=? AND risk_score >= 7", (target_id,))
            st.dataframe(high_df)
            create_download_button(high_df, "High Risks", "high_risks")

        with t4:
            pend_df = run_query("SELECT title, submitted_by, submitted_date FROM risks WHERE company_id=? AND status='Pending Approval'", (target_id,))
            st.dataframe(pend_df)
            create_download_button(pend_df, "Pending Risks", "pending_risks")

    with tab2:
        st.subheader("Custom Report Builder")
        all_cols = ["title", "category", "likelihood", "impact", "status", "submitted_by", "risk_score"]
        sel_cols = st.multiselect("Select Columns", all_cols, default=["title", "status", "risk_score"])
        
        if st.button("Generate"):
            col_str = ", ".join(sel_cols)
            custom_df = run_query(f"SELECT {col_str} FROM risks WHERE company_id=?", (target_id,))
            st.dataframe(custom_df)
            pdf = generate_pdf_report("Custom Report", custom_df)
            st.download_button("Download Custom PDF", pdf, "custom.pdf")

# ==========================================
# 13. PAGE: ADMIN PANEL
# ==========================================
elif page == "Admin Panel" and user[4] == "Admin":
    st.markdown("## Admin Panel")
    companies_df = run_query("SELECT id, name FROM companies")
    
    with st.expander("Add User"):
        with st.form("new_u"):
            u = st.text_input("Username")
            e = st.text_input("Email")
            p = st.text_input("Password", type="password")
            r = st.selectbox("Role", ["Admin", "Approver", "User"])
            c = st.selectbox("Company", companies_df['name'].tolist())
            
            if st.form_submit_button("Create"):
                cid = companies_df[companies_df['name'] == c].iloc[0]['id']
                h = hashlib.sha256(p.encode()).hexdigest()
                res = run_query("INSERT INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)", 
                          (u, e, h, r, cid), is_write=True)
                if res:
                    st.success("Created")
                    st.rerun()
                else:
                    st.error("User likely exists.")

    st.markdown("### System Users")
    users_df = run_query("SELECT id, username, email, role, company_id FROM users")
    
    # Helper map
    comp_map = dict(zip(companies_df['id'], companies_df['name']))
    display_df = users_df.copy()
    display_df['company'] = display_df['company_id'].map(comp_map)
    
    for _, row in display_df.iterrows():
        col1, col2 = st.columns([4, 1])
        with col1:
            st.text(f"{row['username']} ({row['role']}) - {row['company']}")
        with col2:
            if st.button("Edit", key=f"ed_{row['id']}"):
                st.session_state.edit_user = row.to_dict()
                st.rerun()

    if "edit_user" in st.session_state:
        st.markdown("---")
        st.markdown(f"#### Editing: {st.session_state.edit_user['username']}")
        edit_data = st.session_state.edit_user
        
        with st.form("edit_u_form"):
            # Determine defaults safely
            curr_comp_name = comp_map.get(edit_data['company_id'], companies_df['name'].iloc[0])
            try:
                c_idx = companies_df['name'].tolist().index(curr_comp_name)
            except: c_idx = 0
            
            role_opts = ["Admin", "Approver", "User"]
            try:
                r_idx = role_opts.index(edit_data['role'])
            except: r_idx = 0

            new_u = st.text_input("Username", edit_data['username'])
            new_e = st.text_input("Email", edit_data['email'])
            new_r = st.selectbox("Role", role_opts, index=r_idx)
            new_c = st.selectbox("Company", companies_df['name'].tolist(), index=c_idx)
            
            if st.form_submit_button("Save Changes"):
                new_cid = companies_df[companies_df['name'] == new_c].iloc[0]['id']
                run_query("UPDATE users SET username=?, email=?, role=?, company_id=? WHERE id=?", 
                          (new_u, new_e, new_r, new_cid, edit_data['id']), is_write=True)
                st.success("Updated!")
                del st.session_state.edit_user
                st.rerun()
        
        if st.button("Cancel Edit"):
            del st.session_state.edit_user
            st.rerun()

# ==========================================
# 14. PAGE: AUDIT TRAIL
# ==========================================
elif page == "Audit Trail" and user[4] == "Admin":
    st.markdown("## Audit Trail")
    st.dataframe(run_query("SELECT * FROM audit_trail ORDER BY id DESC"))

# ==========================================
# 15. PAGE: MY APPROVALS
# ==========================================
elif page == "My Approvals" and user[4] == "Approver":
    st.markdown("## My Approvals")
    pending = run_query("SELECT id, title, risk_score, submitted_by FROM risks WHERE approver_email=? AND status='Pending Approval'", (user[2],))
    for _, r in pending.iterrows():
        if st.button(f"Review: {r['title']}", key=f"app_{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Risk Detail"
            st.rerun()

# ==========================================
# FOOTER
# ==========================================
st.markdown("---\n© 2025 Joval Wines")
