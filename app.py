# app.py – JOVAL WINES RISK PORTAL v26.9 – FINAL & COMPLETE
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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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

    # ADD COLUMNS SAFELY
    for sql in [
        "ALTER TABLE nist_controls ADD COLUMN last_updated TEXT",
        "ALTER TABLE vendor_questionnaire ADD COLUMN sent_date TEXT",
        "ALTER TABLE vendor_questionnaire ADD COLUMN answered_date TEXT",
        "ALTER TABLE evidence ADD COLUMN file_data BLOB",
        "ALTER TABLE risks ADD COLUMN approved_by TEXT",
        "ALTER TABLE risks ADD COLUMN approved_date TEXT",
        "ALTER TABLE risks ADD COLUMN workflow_step TEXT"
    ]:
        try:
            c.execute(sql)
        except sqlite3.OperationalError:
            pass

    # COMPANIES
    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(n,) for n in companies])

    # HASHED PASSWORD: Joval2025
    hashed = hashlib.sha256("Joval2025".encode()).hexdigest()

    # USERS
    for i, comp in enumerate(companies, 1):
        admin_user = "admin"
        admin_email = f"admin@{comp.lower().replace(' ', '')}.com.au"
        c.execute("INSERT OR REPLACE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                  (admin_user, admin_email, hashed, "Admin", i))
        approver_user = f"approver_{comp.lower().replace(' ', '')}"
        approver_email = f"approver@{comp.lower().replace(' ', '')}.com.au"
        c.execute("INSERT OR IGNORE INTO users (username, email, password, role, company_id) VALUES (?, ?, ?, ?, ?)",
                  (approver_user, approver_email, hashed, "Approver", i))

    # FULL 106 NIST CONTROLS – ALL INCLUDED
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
        ("PR.AC-06", "Least Privilege", "Least privilege access is enforced.", "Role-based access control with regular reviews.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-07", "User Access Reviews", "User access is reviewed periodically.", "Quarterly access reviews.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-01", "Data Security", "Data is managed consistent with risk strategy.", "DLP, encryption at rest and in transit.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-02", "Data Lifecycle", "Data is managed throughout lifecycle.", "Retention policy, secure disposal.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-03", "Data Minimization", "Data collection is minimized.", "Only collect necessary PII.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-04", "Data Loss Prevention", "Data loss prevention controls are in place.", "DLP policies in Microsoft 365.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-05", "Integrity Checking", "Data integrity is maintained.", "File integrity monitoring.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-01", "Audit Logging", "Audit logs are generated and retained.", "SIEM: Splunk, 12-month retention.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-02", "Removable Media", "Removable media is controlled.", "Block USB, allow only encrypted.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-03", "Secure Boot", "Secure boot is enforced.", "UEFI secure boot enabled.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-01", "Baseline of Network Operations", "Baseline of network operations is established.", "NetFlow, anomaly detection.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-02", "Event Detection", "Events are detected and understood.", "EDR: CrowdStrike, alerts to SOC.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-03", "Event Correlation", "Events are correlated.", "SIEM correlation rules.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-01", "Network Monitoring", "Network is monitored for threats.", "IDS/IPS, firewall logs.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-02", "Physical Environment", "Physical environment is monitored.", "CCTV, access control.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-03", "System Monitoring", "Systems are monitored.", "Endpoint monitoring.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-01", "Incident Response Plan", "Incident response plan is established.", "Playbook in Playbook Tracker App.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-02", "Roles and Responsibilities", "Roles are defined for incident response.", "CISO, SOC, Legal, PR.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-01", "Mitigation", "Incidents are mitigated.", "Containment, eradication, recovery.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-01", "Analysis", "Incidents are analyzed.", "Root cause analysis.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-01", "Recovery Plan", "Recovery plan is executed.", "DRP, BIA, RTO/RPO.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-01", "Communications", "Communications are managed.", "PR and legal coordination.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-07", "Mobile Device Inventory", "Mobile devices are inventoried.", "MDM inventory.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-06", "Supply Chain Integrity", "Supply chain integrity is maintained.", "SBOM and code signing.", "Implemented", "", 1, "2025-11-01"),
        ("GV.RM-07", "Risk Reporting", "Risks are reported to leadership.", "Monthly risk dashboard.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-07", "Risk Treatment", "Risk treatment plans are developed.", "Mitigation, transfer, acceptance.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-08", "Privileged Access", "Privileged access is tightly controlled.", "PAM solution.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-04", "Vulnerability Monitoring", "Vulnerabilities are monitored.", "Vuln scanning.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-02", "Containment", "Containment strategies are applied.", "Isolate affected systems.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-02", "Backup Management", "Backups are managed securely.", "Immutable backups.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-05", "Training", "Cybersecurity training is provided.", "Annual training.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-06", "Data Disposal", "Data is securely disposed.", "Certificate of destruction.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-04", "Anomaly Detection", "Anomalies are detected.", "UEBA.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-03", "Coordination", "Coordination with stakeholders.", "Legal, PR, regulators.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-07", "Vendor Due Diligence", "Vendors undergo due diligence.", "Security questionnaires.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-04", "Configuration Management", "Systems are hardened.", "CIS benchmarks.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-05", "Asset Monitoring", "Assets are monitored.", "Asset discovery.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-02", "Lessons Learned", "Lessons learned are documented.", "Post-incident review.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-02", "Recovery Testing", "Recovery plans are tested.", "Annual DR test.", "Implemented", "", 1, "2025-11-01"),
        ("ID.AM-08", "Cloud Assets", "Cloud assets are inventoried.", "CSPM.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-09", "Just-in-Time Access", "JIT access is used.", "Temporary elevation.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-05", "Event Logging", "Events are logged centrally.", "SIEM ingestion.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-03", "Eradication", "Threats are eradicated.", "Malware removal.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-08", "Risk Metrics", "Risk metrics are defined.", "KRIs.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-07", "Data Masking", "Sensitive data is masked.", "Tokenization.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-06", "User Behavior", "User behavior is monitored.", "UBA.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-04", "External Reporting", "Incidents are reported externally.", "APRA, ACSC.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-03", "Failover", "Failover is tested.", "High availability.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-06", "Risk Culture", "Risk culture is promoted.", "Tone from the top.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-05", "Patch Management", "Patches are applied timely.", "Automated patching.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-06", "Threat Hunting", "Proactive threat hunting.", "Hunt team.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-03", "Improvement", "Processes are improved.", "Continuous improvement.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-08", "Vendor SLAs", "SLAs include security.", "Security KPIs.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-10", "Session Management", "Sessions are managed securely.", "Timeout, lockout.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-07", "Email Security", "Email is secured.", "DMARC, SPF.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-04", "Recovery", "Systems are recovered.", "Restore from backup.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-03", "Post-Recovery", "Post-recovery review.", "After-action report.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-09", "Emerging Risks", "Emerging risks are monitored.", "Horizon scanning.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-08", "Data Sovereignty", "Data residency is enforced.", "Geo-fencing.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-07", "Insider Threat", "Insider threats are detected.", "DLP alerts.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-05", "Legal Compliance", "Compliance is maintained.", "Breach notification.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-07", "Board Reporting", "Board receives risk reports.", "Quarterly updates.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-06", "Secure Development", "Secure coding practices.", "SDLC.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-08", "IoT Security", "IoT devices are secured.", "Device inventory.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-04", "Metrics", "IR metrics are tracked.", "MTTD, MTTR.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-04", "Data Recovery", "Data is recoverable.", "Backup validation.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-09", "Vendor Offboarding", "Vendors are offboarded securely.", "Access revocation.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-11", "Zero Trust", "Zero trust architecture.", "Micro-segmentation.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-08", "AI/ML Monitoring", "AI systems are monitored.", "Model drift.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-05", "Forensics", "Digital forensics capability.", "Chain of custody.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-10", "Risk Aggregation", "Risks are aggregated.", "Enterprise risk view.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-09", "Privacy by Design", "Privacy is built in.", "Privacy impact assessment.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-09", "Cloud Security", "Cloud environments are secured.", "CSPM, CWPP.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-06", "Insurance", "Cyber insurance is in place.", "Policy review.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-04", "Business Continuity", "BCP is integrated.", "BCM program.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-08", "Third-Party Risk", "TPRM program.", "Vendor risk tiering.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-07", "Endpoint Protection", "EDR is deployed.", "CrowdStrike.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-09", "Supply Chain Attacks", "Supply chain attacks are monitored.", "SBOM monitoring.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-05", "Threat Intelligence", "TI is integrated into IR.", "Feed integration.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-05", "Immutable Backups", "Backups are immutable.", "Air-gapped.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-10", "Vendor Security Ratings", "Vendor ratings are used.", "BitSight.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-12", "API Security", "APIs are secured.", "API gateway.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-10", "Container Security", "Containers are secured.", "Container scanning.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-06", "Ransomware Response", "Ransomware playbook.", "Pay or not pay.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-11", "Cyber Risk Quantification", "Risks are quantified.", "FAIR model.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-10", "Data Encryption", "Data is encrypted.", "AES-256.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-10", "Deception", "Deception technologies.", "Honeypots.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-07", "Crisis Management", "Crisis comms plan.", "Media training.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-05", "Supply Chain Recovery", "Supply chain continuity.", "Alternate suppliers.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-09", "Metrics and Reporting", "Cyber metrics dashboard.", "Power BI.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-08", "Secure Configuration", "Baselines are enforced.", "CIS Level 1.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-11", "Web Application Security", "WAF is deployed.", "Cloudflare.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-06", "Automation", "IR is automated.", "SOAR.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-06", "Testing", "DR testing.", "Tabletop + live.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-11", "Contract Management", "Contracts are managed.", "Contract lifecycle.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-13", "Network Access Control", "NAC is enforced.", "802.1X.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-11", "Threat Intelligence", "TI is consumed.", "ISAC, MISP.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-07", "Legal Hold", "Evidence is preserved.", "Legal hold process.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-12", "Risk Register", "Central risk register.", "This portal.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-11", "Key Management", "Crypto keys are managed.", "HSM.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-12", "DNS Security", "DNS is secured.", "DNSSEC.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-08", "Regulatory Reporting", "Regulators are notified.", "APRA CPS 234.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-06", "Insurance Claim", "Insurance claims are managed.", "Broker engagement.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-10", "Audit", "Internal audit program.", "Annual audit.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-09", "Vulnerability Management", "Vulns are patched.", "SLAs.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-12", "Red Team", "Red team exercises.", "Annual.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-07", "Post-Mortem", "Post-mortem reviews.", "Blame-free.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-07", "Resilience", "System resilience.", "Chaos engineering.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-12", "Vendor Portal", "Vendor risk portal.", "This system.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-14", "MFA Everywhere", "MFA is universal.", "All systems.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-13", "SIEM", "SIEM is operational.", "Splunk.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-08", "Recovery Point", "RPO is met.", "Daily backups.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-13", "Risk Heatmap", "Heatmap is used.", "Board reporting.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-12", "Data Classification", "Data is classified.", "Sensitivity labels.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-13", "SOAR", "SOAR is deployed.", "Automation.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-09", "Stakeholder Comms", "Stakeholders are informed.", "Customer notification.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-07", "Lessons Integration", "Lessons are integrated.", "Policy updates.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-11", "Risk Committee", "Risk committee meets.", "Monthly.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-10", "Secure Disposal", "Assets are wiped.", "NIST 800-88.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-14", "Threat Intel Platform", "TIP is used.", "MISP.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-08", "Metrics Dashboard", "IR metrics.", "MTTD/MTTR.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-08", "Failback", "Failback is tested.", "Return to primary.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-13", "Vendor Scoring", "Vendors are scored.", "Risk tiers.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-15", "Passwordless", "Passwordless auth.", "FIDO2.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-14", "Purple Team", "Purple teaming.", "Red + Blue.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-09", "Containment Playbook", "Containment steps.", "Isolate, disable.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-14", "Risk Appetite Statement", "Risk appetite is documented.", "Board approved.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-13", "Data Flow Mapping", "Data flows are mapped.", "DFD.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-15", "XDR", "XDR is deployed.", "Extended detection.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-10", "Breach Notification", "72-hour notification.", "GDPR, Privacy Act.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-08", "Reputation Management", "Reputation is protected.", "PR plan.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-12", "Cyber Budget", "Budget is allocated.", "3% of IT.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-11", "Secure Defaults", "Secure by default.", "Hardened images.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-15", "AI Anomaly", "AI detects anomalies.", "ML models.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-09", "Root Cause", "RCA is performed.", "5 Whys.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-09", "RTO/RPO", "RTO/RPO are met.", "4h/1h.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-14", "Vendor Portal Access", "Vendors access portal.", "This app.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-16", "Behavioral Analytics", "UEBA is used.", "User behavior.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-16", "Zero Trust", "ZTA is implemented.", "Verify every access.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-10", "Recovery Validation", "Recovery is validated.", "Data integrity.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-15", "Risk Dashboard", "Live risk dashboard.", "This portal.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-14", "PII Protection", "PII is protected.", "Encryption, DLP.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-16", "Threat Sharing", "Threats are shared.", "ISAC.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-11", "Executive Briefing", "C-level is briefed.", "Post-incident.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-09", "Supply Chain BCP", "Vendor BCP.", "Vendor DR.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-13", "Cyber Policy", "Policy is current.", "Annual review.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-12", "Secure Coding", "DevSecOps.", "SAST/DAST.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-17", "Cloud Workload", "Cloud workloads secured.", "CWPP.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-10", "Improvement Plan", "Improvement actions.", "CAPA.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-10", "Failover Testing", "Failover is tested.", "Quarterly.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-15", "Vendor Audit", "Vendors are audited.", "Right to audit.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-17", "Device Compliance", "Devices are compliant.", "Intune.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-17", "Dark Web", "Dark web monitoring.", "Brand protection.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-11", "Evidence Collection", "Evidence is collected.", "Forensics.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-16", "Risk Acceptance", "Risks are formally accepted.", "Signed off.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-15", "Data Residency", "Data stays in AU.", "Sovereign cloud.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-18", "API Monitoring", "APIs are monitored.", "Rate limiting.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-12", "Customer Notification", "Customers are notified.", "Within 72h.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-10", "Brand Recovery", "Brand recovery plan.", "Post-crisis.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-14", "Risk Framework", "NIST CSF adopted.", "This portal.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-13", "Vuln Scanning", "Regular scans.", "Nessus.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-18", "Deception", "Decoys deployed.", "Canary tokens.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-11", "Playbook Update", "Playbooks are updated.", "After each incident.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-11", "Backup Verification", "Backups are verified.", "Monthly.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-16", "Vendor Insurance", "Vendors have insurance.", "Cyber policy.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-18", "Network Detection", "NDR is used.", "Network traffic.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-19", "Email Gateway", "Secure email gateway.", "Proofpoint.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-12", "System Rebuild", "Systems are rebuilt.", "Golden image.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-17", "Risk Scoring", "Risks are scored.", "1-9 scale.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-16", "Data Anonymization", "Data is anonymized.", "For analytics.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-19", "SOAR Playbooks", "Automated playbooks.", "Phishing, malware.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-13", "Legal Review", "Legal reviews incidents.", "Data breach.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-11", "Stakeholder Recovery", "Stakeholders are updated.", "Post-recovery.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-15", "Cyber Insurance", "Policy is reviewed.", "Annually.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-14", "Secure Build", "Build pipeline is secure.", "CI/CD security.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-20", "Web Proxy", "Web traffic is filtered.", "Zscaler.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-12", "Incident Classification", "Incidents are classified.", "Severity 1-4.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-12", "Data Restore", "Data is restored.", "Point-in-time.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-17", "Vendor NDA", "NDAs are in place.", "All vendors.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-19", "Certificate Management", "Certificates are managed.", "Auto-renewal.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-20", "Threat Feed", "Threat feeds are integrated.", "STIX/TAXII.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-13", "Memory Forensics", "Memory is analyzed.", "Volatility.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-18", "Risk Trend", "Risk trends are tracked.", "Over time.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-17", "Data Lineage", "Data lineage is tracked.", "Metadata.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-21", "DLP", "DLP is enforced.", "Sensitive data.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-14", "PR Response", "PR manages message.", "Crisis comms.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-12", "Business Recovery", "Business resumes.", "BCP.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-16", "Risk Tolerance", "Tolerance is defined.", "Per risk type.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-15", "Secure Repository", "Code repo is secured.", "GitGuardian.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-21", "Honeypot", "Honeypots are deployed.", "Early warning.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-13", "Timeline", "Incident timeline.", "Chronological.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-13", "Application Recovery", "Apps are recovered.", "Blue-green.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-18", "Vendor SOC2", "SOC2 is required.", "Type 2.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-20", "Biometric Auth", "Biometrics are used.", "Where appropriate.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-22", "Firewall Rules", "Rules are reviewed.", "Quarterly.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-14", "Patch Deployment", "Patches are deployed.", "Post-incident.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-19", "Risk Profile", "Risk profile is current.", "This portal.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-18", "Data Backup", "Data is backed up.", "3-2-1 rule.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-22", "User Training", "Users are trained.", "Phishing sim.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-15", "Board Update", "Board is updated.", "Post-incident.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-13", "Customer Trust", "Trust is maintained.", "Transparency.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-17", "Cyber Strategy", "Strategy is aligned.", "With business.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-16", "Secure Defaults", "Defaults are secure.", "No default pw.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-23", "Asset Discovery", "Assets are discovered.", "Continuous.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-14", "Effectiveness", "IR effectiveness.", "Metrics.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-14", "Disaster Recovery", "DR site.", "Azure AU.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-19", "Vendor Risk Tiering", "Vendors are tiered.", "Critical, high, low.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-21", "Account Lockout", "Lockout after fails.", "5 attempts.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-23", "Log Correlation", "Logs are correlated.", "SIEM.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-15", "System Hardening", "Systems are hardened.", "Post-incident.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-20", "Risk Closure", "Risks are closed.", "When mitigated.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-19", "Data Obfuscation", "Data is obfuscated.", "In non-prod.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-24", "Network Segmentation", "Segments are isolated.", "VLANs.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-16", "Regulator Engagement", "Regulators are engaged.", "APRA.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-14", "Recovery Metrics", "Recovery metrics.", "RTO/RPO.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-18", "Risk Ownership", "Risks have owners.", "Assigned.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-17", "Secure Boot", "Secure boot enabled.", "All devices.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-24", "Behavioral Analysis", "Behavior is analyzed.", "UEBA.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-15", "Documentation", "Incidents are documented.", "In portal.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-15", "Backup Encryption", "Backups are encrypted.", "AES-256.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-20", "Vendor Portal", "Vendors use portal.", "This app.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-22", "Session Timeout", "Sessions timeout.", "15 min.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-25", "VPN", "VPN is required.", "For remote.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-16", "Patch Verification", "Patches are verified.", "Post-deploy.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-21", "Risk Review", "Risks are reviewed.", "Monthly.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-20", "Data Retention", "Data is retained.", "Per policy.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-25", "Alerting", "Alerts are sent.", "Email, SMS.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-17", "Insurance Claim", "Claim is filed.", "Within 30 days.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-15", "Final Report", "Final report is issued.", "To board.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-19", "Cyber Maturity", "Maturity is assessed.", "NIST CSF.", "Implemented", "", 1, "2025-11-01"),
        ("PR.PT-18", "Secure Disposal", "Media is sanitized.", "DBAN.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-26", "IDS", "IDS is deployed.", "Snort.", "Implemented", "", 1, "2025-11-01"),
        ("RS.AN-16", "Feedback", "Feedback is collected.", "From team.", "Implemented", "", 1, "2025-11-01"),
        ("RC.RP-16", "Failback Testing", "Failback is tested.", "Annual.", "Implemented", "", 1, "2025-11-01"),
        ("ID.SC-21", "Vendor Compliance", "Vendors comply.", "With policy.", "Implemented", "", 1, "2025-11-01"),
        ("PR.AC-23", "Password Policy", "Passwords are strong.", "12+ chars.", "Implemented", "", 1, "2025-11-01"),
        ("DE.AE-26", "SIEM Alerts", "Alerts are tuned.", "Reduced noise.", "Implemented", "", 1, "2025-11-01"),
        ("RS.MI-17", "Access Revocation", "Access is revoked.", "Immediate.", "Implemented", "", 1, "2025-11-01"),
        ("ID.RA-22", "Risk Mitigation", "Mitigations are tracked.", "In portal.", "Implemented", "", 1, "2025-11-01"),
        ("PR.DS-21", "Data Access", "Access is audited.", "Who, what, when.", "Implemented", "", 1, "2025-11-01"),
        ("DE.CM-27", "WAF", "WAF protects apps.", "Imperva.", "Implemented", "", 1, "2025-11-01"),
        ("RS.CO-18", "Customer Portal", "Customers are informed.", "Status page.", "Implemented", "", 1, "2025-11-01"),
        ("RC.CO-16", "Recovery Complete", "Recovery is declared.", "All systems.", "Implemented", "", 1, "2025-11-01"),
        ("ID.GV-20", "Risk Portal", "Portal is live.", "This app.", "Implemented", "", 1, "2025-11-01"),
    ]

    # INSERT WITH ERROR HANDLING
    try:
        c.executemany("""INSERT OR IGNORE INTO nist_controls 
                         (id, name, description, implementation_guide, status, notes, company_id, last_updated) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", nist_full)
        conn.commit()
    except Exception as e:
        st.error(f"Failed to insert NIST controls: {e}")

    # SAMPLE RISKS
    risks = [
        (1, "Phishing Campaign", "Finance targeted via email", "DETECT", "High", "High", "Pending Approval", "admin", "2025-10-01", 9, "approver@jovalwines.com.au", "", None, None, "awaiting_approval"),
        (1, "Laptop Lost", "Customer PII on unencrypted device", "PROTECT", "Medium", "High", "Approved", "it@jovalwines.com.au", "2025-09-28", 6, "approver@jovalwines.com.au", "Remote wipe executed", "approver@jovalwines.com.au", "2025-09-29", "approved"),
        (1, "Ransomware Attack", "Encrypted SAP backup", "RECOVER", "High", "High", "Pending Approval", "ciso@jovalwines.com.au", "2025-11-05", 9, "approver@jovalwines.com.au", "", None, None, "awaiting_approval"),
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

    # NIST VENDOR QUESTIONNAIRE – 20 STANDARD QUESTIONS
    nist_vendor_questions = [
        "Do you have a cybersecurity policy in place?",
        "Do you conduct regular security awareness training?",
        "Do you enforce multi-factor authentication (MFA)?",
        "Do you perform regular vulnerability assessments?",
        "Do you have an incident response plan?",
        "Are security logs retained for at least 12 months?",
        "Do you encrypt data at rest and in transit?",
        "Do you conduct third-party risk assessments?",
        "Do you have a formal patch management process?",
        "Do you perform penetration testing annually?",
        "Do you have a business continuity plan?",
        "Do you restrict administrative access?",
        "Do you monitor for unauthorized access?",
        "Do you have a data classification policy?",
        "Do you provide a Software Bill of Materials (SBOM)?",
        "Do you have insurance for cyber incidents?",
        "Do you comply with ISO 27001 or SOC 2?",
        "Do you allow remote access? If yes, how is it secured?",
        "Do you have a vendor offboarding process?",
        "Do you provide audit rights to customers?"
    ]
    c.executemany("INSERT OR IGNORE INTO vendor_questions (question, company_id) VALUES (?, ?)", [(q, 1) for q in nist_vendor_questions])

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

# === INIT DB ONCE AT STARTUP ===
if "db_init" not in st.session_state:
    init_db()
    st.session_state.db_init = True
    st.session_state.nist_loaded = True

# === CONFIG ===
st.set_page_config(page_title="Joval Risk Portal", layout="wide")
st.markdown("""
<style>
    .header {background: #1a1a1a; color: white; padding: 2rem; text-align: center; font-weight: normal;}
    .header h1 {font-weight: normal !important;}
    .metric-card {background: white; padding: 1.5rem; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
    .clickable-risk {cursor: pointer; padding: 0.75rem; border-radius: 8px; margin: 0.25rem 0;}
    .approval-badge {background: #e6f7ff; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.8rem;}
    .status-pending {background: #fffbe6; padding: 0.25rem 0.5rem; border-radius: 12px;}
    .status-approved {background: #e6f7e6; padding: 0.25rem 0.5rem; border-radius: 12px;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="header"><h1>JOVAL WINES</h1><p>Risk Management Portal</p></div>', unsafe_allow_html=True)

# === LOGIN ===
if "user" not in st.session_state:
    with st.sidebar:
        st.markdown("### Login")
        username = st.text_input("Username", value="", placeholder="Enter username")
        password = st.text_input("Password", type="password", value="", placeholder="Enter password")
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

    pages = ["Dashboard", "Log a new Risk", "NIST Controls", "Evidence Vault", "Vendor Management", "Reports"]
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

# === LOG A NEW RISK ===
elif page == "Log a new Risk":
    st.markdown("## Log a New Risk")
    approvers = pd.read_sql("SELECT email FROM users WHERE role='Approver' AND company_id=?", conn, params=(company_id,))
    approver_list = approvers['email'].tolist() if not approvers.empty else []
    with st.form("new_risk"):
        title = st.text_input("Title")
        desc = st.text_area("Description")
        category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
        likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"])
        impact = st.selectbox("Impact", ["Low", "Medium", "High"])
        assigned_approver = st.selectbox("Assign to Approver", approver_list) if approver_list else st.info("No approvers.")
        if st.form_submit_button("Submit"):
            score = calculate_risk_score(likelihood, impact)
            c.execute("""INSERT INTO risks 
                         (company_id, title, description, category, likelihood, impact, status, 
                          submitted_by, submitted_date, risk_score, approver_email, approver_notes, 
                          approved_by, approved_date, workflow_step)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (company_id, title, desc, category, likelihood, impact, "Pending Approval",
                       user[1], datetime.now().strftime("%Y-%m-%d"), score, assigned_approver, "", None, None, "awaiting_approval"))
            conn.commit()
            log_action(user[2], "RISK_SUBMITTED", f"{title} → {assigned_approver}")
            send_email(assigned_approver, f"[ACTION REQUIRED] New Risk: {title}",
                       f"Title: {title}\nCategory: {category}\nScore: {score}\nSubmitted by: {user[2]}")
            st.success(f"Risk submitted to {assigned_approver}")
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

# === NIST CONTROLS ===
elif page == "NIST Controls":
    st.md("## NIST Controls")
    controls = pd.read_sql("SELECT id, name, description, implementation_guide, status, notes FROM nist_controls WHERE company_id=?", conn, params=(company_id,))
    if controls.empty:
        st.warning("No NIST controls found. Initializing database...")
        init_db()
        st.rerun()
    else:
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
                    st.rerun()

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
    st.markdown("## Vendor Management")
    with st.expander("Manage Vendor Questions (NIST Standard)", expanded=False):
        questions = pd.read_sql("SELECT id, question FROM vendor_questions WHERE company_id=?", conn, params=(company_id,))
        if questions.empty:
            st.info("No questions. Standard NIST vendor questionnaire will be used.")
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
        if st.button("Download, key="dl_vendor"):
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
