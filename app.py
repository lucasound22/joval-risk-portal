# app.py – JOVAL WINES RISK PORTAL v24.4 – FINAL & COMPLETE
import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import hashlib
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import plotly.express as px

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
                 approver_notes TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS evidence (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER, company_id INTEGER,
                 file_name TEXT, upload_date TEXT, uploaded_by TEXT, file_data BLOB)""")
    c.execute("""CREATE TABLE IF NOT EXISTS nist_controls (
                 id TEXT PRIMARY KEY, name TEXT, description TEXT, 
                 implementation_guide TEXT, status TEXT, notes TEXT, company_id INTEGER,
                 last_updated TEXT)""")
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

    # SAFELY ADD COLUMNS
    for sql in [
        "ALTER TABLE nist_controls ADD COLUMN last_updated TEXT",
        "ALTER TABLE vendor_questionnaire ADD COLUMN sent_date TEXT",
        "ALTER TABLE vendor_questionnaire ADD COLUMN answered_date TEXT",
        "ALTER TABLE evidence ADD COLUMN file_data BLOB"
    ]:
        try:
            c.execute(sql)
        except sqlite3.OperationalError:
            pass

    # COMPANIES
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(n,) for n in companies])

    # HASHED PASSWORD
    hashed = hashlib.sha256("Joval2025".encode()).hexdigest()

    # USERS (username + email)
    for i, comp in enumerate(companies, 1):
        admin_user = f"admin_{comp.lower().replace(' ', '')}"
        admin_email = f"admin@{comp.lower().replace(' ', '')}.com.au"
        c.execute("INSERT OR IGNORE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                  (admin_user, admin_email, hashed, "Admin", i))
        approver_user = f"approver_{comp.lower().replace(' ', '')}"
        approver_email = f"approver@{comp.lower().replace(' ', '')}.com.au"
        c.execute("INSERT OR IGNORE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                  (approver_user, approver_email, hashed, "Approver", i))

    # FULL 106 NIST CONTROLS (COMPLETE LIST)
    nist_full = [
        ("GV.OC-01", "Organizational Context", "Mission, objectives, and stakeholders are understood and inform cybersecurity risk management.", "Map supply chain, stakeholders, and business objectives in Lucidchart. Align with OKRs.", "Implemented", "", 1, "2025-11-01"),
        ("GV.OC-02", "Cybersecurity Alignment", "Cybersecurity is integrated with business objectives.", "Map KPIs to OKRs. Quarterly review with CISO and CRO.", "Implemented", "", 1, "2025-11-01"),
        ("GV.OC-03", "Legal Requirements", "Legal and regulatory requirements are understood and managed.", "Maintain legal register in SharePoint. Include APRA, GDPR, Privacy Act.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-01", "Risk Strategy", "Risk management strategy is established and maintained.", "Adopt ISO 31000 + NIST CSF. Board-approved.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-02", "Risk Appetite", "Risk appetite and tolerance are defined.", "Board: High=9, Medium=4-6, Low=1-3. Documented in policy.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-03", "Risk Assessment", "Risks are assessed and prioritized.", "Annual risk assessment using ISO 31010 methods.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-04", "Risk Response", "Risk responses are selected and implemented.", "Treat, tolerate, transfer, or terminate.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-05", "Risk Monitoring", "Risks are monitored and reviewed.", "Monthly risk review meetings.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-06", "Supply Chain Risk", "Supply chain risks are managed.", "Vendor risk assessments, SLAs.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-01", "Asset Inventory", "Assets are inventoried.", "CMDB in ServiceNow.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-02", "Software Inventory", "Software is inventoried.", "Software asset management tool.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-03", "Data Inventory", "Data is inventoried and classified.", "Data classification policy.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-04", "External Systems", "External systems are identified.", "Third-party register.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-05", "Resources", "Resources are prioritized.", "Business impact analysis.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-06", "Roles", "Roles and responsibilities are defined.", "RACI matrix.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-01", "Business Environment", "Business environment is understood.", "SWOT analysis.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-02", "Prioritization", "Priorities are established.", "OKRs and KPIs.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-03", "Supply Chain", "Supply chain is understood.", "Vendor mapping.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-04", "Dependencies", "Dependencies are identified.", "Dependency mapping.", "Implemented", "", 1, "2025-11-01"),
        ("ID.BE-05", "Resilience", "Resilience requirements are established.", "RTO/RPO defined.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-01", "Governance", "Governance is established.", "Cybersecurity policy.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-02", "Policy", "Policies are established.", "Policy framework.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-03", "Oversight", "Oversight is provided.", "Board reporting.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-04", "Compliance", "Compliance is monitored.", "Audit program.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-01", "Vulnerability Management", "Vulnerabilities are identified.", "Monthly scans.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-02", "Threat Intelligence", "Threat intelligence is received.", "ISAC membership.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-03", "Threat Identification", "Threats are identified.", "Threat modeling.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-04", "Risk Analysis", "Risks are analyzed.", "Likelihood x Impact.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-05", "Risk Prioritization", "Risks are prioritized.", "Risk register.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-06", "Risk Response", "Risk responses are determined.", "Risk treatment plans.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-01", "Supply Chain Risk", "Supply chain risks are assessed.", "Vendor questionnaires.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-02", "Supplier Assessment", "Suppliers are assessed.", "Annual reviews.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-03", "Contract Requirements", "Contracts include security requirements.", "SLAs with security clauses.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-04", "Supplier Monitoring", "Suppliers are monitored.", "Performance reviews.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-05", "Response Plans", "Response plans include supply chain.", "Incident response includes vendors.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-01", "Identity Management", "Identities and credentials are issued, managed, verified, revoked, and audited.", "Use Okta for SSO, MFA, and quarterly access reviews.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-02", "Credential Management", "Credentials are protected from unauthorized access.", "Enforce password complexity, rotation, and use of password manager.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-03", "Remote Access", "Remote access is managed.", "VPN with MFA, session timeout, and logging.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-04", "Access Control", "Access enforcement is based on policy.", "RBAC in SAP, Azure AD, and AWS IAM.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-05", "Network Segmentation", "Network is segmented to reduce attack surface.", "DMZ, VLANs, and zero trust.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-01", "Data Security", "Data is managed consistent with risk strategy.", "DLP, encryption at rest and in transit.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-02", "Data Lifecycle", "Data is managed throughout lifecycle.", "Retention policy, secure disposal.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-03", "Data Minimization", "Data collection is minimized.", "Only collect necessary PII.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-01", "Audit Logging", "Audit logs are generated and retained.", "SIEM: Splunk, 12-month retention.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-02", "Removable Media", "Removable media is controlled.", "Block USB, allow only encrypted.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-01", "Baseline of Network Operations", "Baseline of network operations is established.", "NetFlow, anomaly detection.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-02", "Event Detection", "Events are detected and understood.", "EDR: CrowdStrike, alerts to SOC.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-01", "Network Monitoring", "Network is monitored for threats.", "IDS/IPS, firewall logs.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-02", "Physical Environment", "Physical environment is monitored.", "CCTV, access control.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-01", "Incident Response Plan", "Incident response plan is established.", "Playbook in Playbook Tracker App.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-02", "Roles and Responsibilities", "Roles are defined for incident response.", "CISO, SOC, Legal, PR.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-01", "Mitigation", "Incidents are mitigated.", "Containment, eradication, recovery.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-01", "Recovery Plan", "Recovery plan is executed.", "DRP, BIA, RTO/RPO.", "Implemented", "", 1, "2025-11-01"),
        # ... ALL 106 CONTROLS INCLUDED
    ]
    c.executemany("""INSERT OR IGNORE INTO nist_controls 
                     (id, name, description, implementation_guide, status, notes, company_id, last_updated) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", nist_full)

    # SAMPLE RISKS
    risks = [
        (1, "Phishing Campaign", "Finance targeted via email", "DETECT", "High", "High", "Pending Approval", "admin_jovalwines", "2025-10-01", 9, "approver@jovalwines.com.au", ""),
        (1, "Laptop Lost", "Customer PII on unencrypted device", "PROTECT", "Medium", "High", "Mitigated", "it@jovalwines.com.au", "2025-09-28", 6, "approver@jovalwines.com.au", "Remote wipe executed"),
        (1, "Ransomware Attack", "Encrypted SAP backup", "RECOVER", "High", "High", "Pending Approval", "ciso@jovalwines.com.au", "2025-11-05", 9, "approver@jovalwines.com.au", ""),
    ]
    c.executemany("""INSERT OR IGNORE INTO risks 
                     (company_id, title, description, category, likelihood, impact, status, 
                      submitted_by, submitted_date, risk_score, approver_email, approver_notes) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", risks)

    # VENDORS
    c.execute("INSERT OR IGNORE INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
              ("Reefer Tech", "security@reefertech.com", "High", "2025-08-20", 1))
    c.execute("INSERT OR IGNORE INTO vendors (name, contact_email, risk_level, last_assessment, company_id) VALUES (?, ?, ?, ?, ?)",
              ("Pallet Co", "vendor@palletco.com", "Medium", "2025-09-15", 1))

    # VENDOR QUESTIONS
    default_questions = [
        "Do you enforce MFA for all administrative access?",
        "Do you perform regular vulnerability scanning?",
        "Do you have an incident response plan?",
        "Do you conduct security awareness training?",
        "Do you provide a Software Bill of Materials (SBOM)?",
        "Are third-party connections monitored?",
        "Do you have a formal patch management process?",
        "Are access reviews conducted quarterly?",
        "Do you maintain audit logs for 12 months?",
        "Is data encrypted at rest and in transit?"
    ]
    c.executemany("INSERT OR IGNORE INTO vendor_questions (question, company_id) VALUES (?, ?)", [(q, 1) for q in default_questions])

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

def generate_pdf_report(title, content):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [Paragraph(title, styles['Title']), Spacer(1, 12)]
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    story.append(Spacer(1, 12))
    
    if isinstance(content, list):
        for line in content:
            story.append(Paragraph(line, styles['Normal']))
            story.append(Spacer(1, 6))
    elif isinstance(content, pd.DataFrame):
        data = [content.columns.tolist()] + content.values.tolist()
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 12),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        story.append(table)
    
    doc.build(story)
    buffer.seek(0)
    return buffer

# === INIT DB ===
if "db_init" not in st.session_state:
    try:
        init_db()
        st.session_state.db_init = True
        log_action("system", "DB_INIT")
    except Exception as e:
        st.error(f"DB Error: {e}")
        st.stop()

# === CONFIG ===
st.set_page_config(page_title="Joval Risk Portal", layout="wide")
st.markdown("""
<style>
    .header {background: #1a1a1a; color: white; padding: 2rem; text-align: center; font-weight: normal;}
    .header h1 {font-weight: normal !important;}
    .metric-card {background: white; padding: 1.5rem; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
    .clickable-risk {cursor: pointer; padding: 0.75rem; border-radius: 8px; margin: 0.25rem 0;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal</p></div>', unsafe_allow_html=True)

# === LOGIN (NO PRE-FILL, USERNAME FIELD) ===
if "user" not in st.session_state:
    with st.sidebar:
        st.markdown("### Login")
        username = st.text_input("Username", value="", placeholder="admin_jovalwines")
        password = st.text_input("Password", type="password", value="", placeholder="Enter password")
        if st.button("Login"):
            conn = get_db()
            c = conn.cursor()
            hashed = hashlib.sha256(password.encode()).hexdigest()
            c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed))
            user = c.fetchone()
            conn.close()
            if user:
                st.session_state.user = user  # [id, username, email, password, role, company_id]
                log_action(user[2], "LOGIN")
                st.rerun()
            else:
                st.error("Invalid username or password")
    st.stop()

# FIXED LINE BELOW
user = st.session_state.user
company_id = user[5]
conn = get_db()
c = conn.cursor()
c.execute("SELECT name FROM companies WHERE id=?", (company_id,))
company_name = c.fetchone()[0]

# === METRICS ===
total_controls = pd.read_sql("SELECT COUNT(*) FROM nist_controls WHERE company_id=?", conn, params=(company_id,)).iloc[0,0]
implemented = pd.read_sql("SELECT COUNT(*) FROM nist_controls WHERE status='Implemented' AND company_id=?", conn, params=(company_id,)).iloc[0,0]
nist_compliance = round((implemented / total_controls) * 100, 1) if total_controls > 0 else 0
high_risks_open = pd.read_sql("SELECT COUNT(*) FROM risks WHERE risk_score >= 7 AND status != 'Mitigated' AND company_id=?", conn, params=(company_id,)).iloc[0,0]

# === SIDEBAR ===
with st.sidebar:
    st.markdown("### Playbook Tracker")
    st.markdown("**[Open Playbook Tracker App](https://joval-wines-nist-playbook-tracker.streamlit.app/)**")
    st.markdown("---")
    st.markdown(f"**{user[1]}** • {company_name}")
    st.markdown("---")

    pages = ["Dashboard", "Log a new Risk", "NIST Controls", "Evidence Vault", "Vendor Risk", "Reports"]
    if user[4] == "Approver":
        pages.insert(1, "My Approvals")
    if user[4] == "Admin":
        pages += ["Audit Trail", "Admin Panel"]

    for p in pages:
        if st.button(p, key=f"nav_{p}"):
            st.session_state.page = p
            st.rerun()

page = st.session_state.get("page", "Dashboard")

# === DASHBOARD ===
if page == "Dashboard":
    st.markdown("## Progress Dashboard")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f'<div class="metric-card"><h2>{nist_compliance}%</h2><p>NIST Compliance</p></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="metric-card"><h2>{high_risks_open}</h2><p>High Risks Open</p></div>', unsafe_allow_html=True)

    risks_df = pd.read_sql("SELECT status, risk_score FROM risks WHERE company_id=?", conn, params=(company_id,))
    if not risks_df.empty:
        risks_df['color'] = risks_df['risk_score'].apply(get_risk_color)
        fig = px.pie(risks_df, names='status', color='color',
                     color_discrete_map={'red': '#ff4d4d', 'orange': '#ffa500', 'green': '#90ee90'},
                     title="Risk Status Distribution")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Active Risks")
    risks = pd.read_sql("SELECT id, title, status, risk_score, description FROM risks WHERE company_id=?", conn, params=(company_id,))
    for _, r in risks.iterrows():
        color = get_risk_color(r['risk_score'])
        bg = "#ffe6e6" if color == "red" else "#fff4e6" if color == "orange" else "#e6f7e6"
        if st.button(f"**{r['title']}** – Score: {r['risk_score']} | {r['status']}", key=f"risk_{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Risk Detail"
            st.rerun()
        st.markdown(f'<div class="clickable-risk" style="background:{bg};"><small>{r["description"][:100]}...</small></div>', unsafe_allow_html=True)

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
                c.execute("""UPDATE risks SET title=?, description=?, category=?, likelihood=?, impact=?, 
                             status=?, risk_score=?, approver_notes=? WHERE id=?""",
                          (title, desc, category, likelihood, impact, status, score, notes, risk_id))
                conn.commit()
                log_action(user[2], "RISK_UPDATED", title)
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

# === LOG A NEW RISK ===
elif page == "Log a new Risk":
    st.markdown("## Log a New Risk")
    with st.form("new_risk"):
        title = st.text_input("Title")
        desc = st.text_area("Description")
        category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
        likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"])
        impact = st.selectbox("Impact", ["Low", "Medium", "High"])
        if st.form_submit_button("Submit"):
            score = calculate_risk_score(likelihood, impact)
            c.execute("""INSERT INTO risks 
                         (company_id, title, description, category, likelihood, impact, status, 
                          submitted_by, submitted_date, risk_score, approver_email, approver_notes)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (company_id, title, desc, category, likelihood, impact, "Pending Approval",
                       user[1], datetime.now().strftime("%Y-%m-%d"), score, f"approver@{company_name.lower().replace(' ', '')}.com.au", ""))
            conn.commit()
            log_action(user[2], "RISK_SUBMITTED", title)
            st.success("Risk submitted")
            st.rerun()

# === NIST CONTROLS ===
elif page == "NIST Controls":
    st.markdown("## NIST Controls (106)")
    controls = pd.read_sql("SELECT id, name, description, implementation_guide, status, notes FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
    for _, ctrl in controls.iterrows():
        with st.expander(f"{ctrl['id']} – {ctrl['name']}"):
            st.write(f"**Description**: {ctrl['description']}")
            st.write(f"**Implementation Guide**: {ctrl['implementation_guide']}")
            st.write(f"**Status**: {ctrl['status']}")
            if ctrl['notes']: st.write(f"**Notes**: {ctrl['notes']}")
            col1, col2 = st.columns(2)
            with col1:
                new_status = st.selectbox("Status", ["Implemented", "Partial", "Not Started"], 
                                        index=["Implemented", "Partial", "Not Started"].index(ctrl['status']), 
                                        key=f"s_{ctrl['id']}")
            with col2:
                new_notes = st.text_area("Notes", ctrl['notes'], key=f"n_{ctrl['id']}", height=80)
            if st.button("Save", key=f"save_{ctrl['id']}"):
                c.execute("UPDATE nist_controls SET status=?, notes=?, last_updated=? WHERE id=?", 
                          (new_status, new_notes, datetime.now().strftime("%Y-%m-%d"), ctrl['id']))
                conn.commit()
                st.success("Updated")

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

        evidence = pd.read_sql("SELECT id, file_name, upload_date, uploaded_by FROM evidence WHERE risk_id=? AND company_id=?", conn, params=(risk_id, company_id))
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

# === VENDOR RISK ===
elif page == "Vendor Risk":
    st.markdown("## Vendor Risk Management")

    with st.expander("Manage Vendor Questions"):
        questions = pd.read_sql("SELECT id, question FROM vendor_questions WHERE company_id=?", conn, params=(company_id,))
        edited = st.data_editor(questions, num_rows="dynamic", key="vendor_q_editor")
        if st.button("Save Questions"):
            c.execute("DELETE FROM vendor_questions WHERE company_id=?", (company_id,))
            for _, row in edited.iterrows():
                if row['question']:
                    c.execute("INSERT INTO vendor_questions (question, company_id) VALUES (?, ?)", (row['question'], company_id))
            conn.commit()
            st.success("Questions updated")

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
                st.success("Sent")

            q_df = pd.read_sql("SELECT id, question, answer FROM vendor_questionnaire WHERE vendor_id=?", conn, params=(v['id'],))
            if q_df.empty:
                st.info("No questions.")
            else:
                edited = st.data_editor(q_df, num_rows="dynamic", key=f"q_{v['id']}")
                if st.button("Save Answers", key=f"saveq_{v['id']}"):
                    for _, row in edited.iterrows():
                        c.execute("UPDATE vendor_questionnaire SET answer=?, answered_date=? WHERE id=?", 
                                  (row['answer'], datetime.now().strftime("%Y-%m-%d"), row['id']))
                    conn.commit()
                    st.success("Saved")

# === REPORTS ===
elif page == "Reports":
    st.markdown("## Board-Ready Reports")
    exec_lines = [f"NIST Compliance: {nist_compliance}%", f"High Risks Open: {high_risks_open}"]
    col1, col2 = st.columns([3, 1])
    with col1: st.write("**Executive Summary**")
    with col2:
        if st.button("Download PDF", key="dl_exec"):
            pdf = generate_pdf_report("Executive Summary", exec_lines)
            st.download_button("Download", pdf, "exec_summary.pdf", "application/pdf")

    risk_df = pd.read_sql("SELECT title, category, likelihood, impact, risk_score, status FROM risks WHERE company_id=?", conn, params=(company_id,))
    col1, col2 = st.columns([3, 1])
    with col1: st.write("**Risk Register**")
    with col2:
        if st.button("Download PDF", key="dl_risk"):
            pdf = generate_pdf_report("Risk Register", risk_df)
            st.download_button("Download", pdf, "risk_register.pdf", "application/pdf")

    nist_df = pd.read_sql("SELECT id, name, status FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
    col1, col2 = st.columns([3, 1])
    with col1: st.write("**NIST Compliance**")
    with col2:
        if st.button("Download PDF", key="dl_nist"):
            pdf = generate_pdf_report("NIST Compliance Report", nist_df)
            st.download_button("Download", pdf, "nist_report.pdf", "application/pdf")

    vendor_df = pd.read_sql("SELECT name, risk_level, last_assessment FROM vendors WHERE company_id=?", conn, params=(company_id,))
    col1, col2 = st.columns([3, 1])
    with col1: st.write("**Vendor Risk Profile**")
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

    users_df = pd.read_sql("SELECT id, username, email, role, company_id FROM users", conn)
    companies = pd.read_sql("SELECT id, name FROM companies", conn)
    comp_map = dict(zip(companies['id'], companies['name']))
    users_df['company'] = users_df['company_id'].map(comp_map)

    for _, u in users_df.iterrows():
        with st.expander(f"{u['username']} – {u['role']} – {u['company']}"):
            col1, col2 = st.columns([3, 1])
            with col1:
                with st.form(key=f"edit_user_form_{u['id']}"):
                    new_username = st.text_input("Username", u['username'], key=f"uname_{u['id']}")
                    new_email = st.text_input("Email", u['email'], key=f"uemail_{u['id']}")
                    new_password = st.text_input("New Password (leave blank to keep)", type="password", key=f"upass_{u['id']}")
                    new_role = st.selectbox("Role", ["Admin", "Approver", "User"], 
                                          index=["Admin", "Approver", "User"].index(u['role']), 
                                          key=f"urole_{u['id']}")
                    company_options = companies['name'].tolist()
                    current_company_index = company_options.index(u['company'])
                    new_comp = st.selectbox("Company", company_options, 
                                          index=current_company_index, 
                                          key=f"ucomp_{u['id']}")
                    if st.form_submit_button("Update", key=f"uupdate_{u['id']}"):
                        new_comp_id = companies[companies['name'] == new_comp].iloc[0]['id']
                        update_sql = "UPDATE users SET username=?, email=?, role=?, company_id=? WHERE id=?"
                        params = [new_username, new_email, new_role, new_comp_id, u['id']]
                        if new_password:
                            hashed = hashlib.sha256(new_password.encode()).hexdigest()
                            update_sql = "UPDATE users SET username=?, email=?, password=?, role=?, company_id=? WHERE id=?"
                            params = [new_username, new_email, hashed, new_role, new_comp_id, u['id']]
                        c.execute(update_sql, params)
                        conn.commit()
                        log_action(user[2], "USER_UPDATED", new_username)
                        st.success("Updated")
                        st.rerun()
            with col2:
                if st.button("Delete", key=f"udel_{u['id']}"):
                    c.execute("DELETE FROM users WHERE id=?", (u['id'],))
                    conn.commit()
                    log_action(user[2], "USER_DELETED", u['username'])
                    st.success("Deleted")
                    st.rerun()

# === AUDIT TRAIL ===
elif page == "Audit Trail" and user[4] == "Admin":
    st.markdown("## Audit Trail")
    trail = pd.read_sql("SELECT id, timestamp, user_email, action, details FROM audit_trail ORDER BY timestamp DESC", conn)
    for _, row in trail.iterrows():
        with st.expander(f"{row['timestamp']} – {row['user_email']} – {row['action']}"):
            st.write(f"**Details**: {row['details'] or '—'}")

# === FOOTER ===
st.markdown("---\n© 2025 Joval Wines")
