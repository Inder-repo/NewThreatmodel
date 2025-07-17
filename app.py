import streamlit as st
import base64
import json
import re
from graphviz import Digraph

# Streamlit UI
st.title("Threat Modeling Application")

# Initialize session state
if 'step' not in st.session_state:
    st.session_state.step = 1
if 'text_input' not in st.session_state:
    st.session_state.text_input = ""
if 'diagram' not in st.session_state:
    st.session_state.diagram = None
if 'data_flows' not in st.session_state:
    st.session_state.data_flows = []
if 'trust_boundaries' not in st.session_state:
    st.session_state.trust_boundaries = []
if 'threat_model' not in st.session_state:
    st.session_state.threat_model = None
if 'error' not in st.session_state:
    st.session_state.error = ""
if 'generated_diagram' not in st.session_state:
    st.session_state.generated_diagram = None

def generate_diagram():
    """Generate a diagram from data flows and trust boundaries using Graphviz."""
    dot = Digraph(comment="Data Flow Diagram", format="png")
    dot.attr(rankdir="LR", size="8,5")

    # Add nodes for data flow sources and destinations
    nodes = set()
    for flow in st.session_state.data_flows:
        nodes.add(flow["source"])
        nodes.add(flow["destination"])
    for node in nodes:
        dot.node(node, node, shape="box")

    # Add data flow edges
    for flow in st.session_state.data_flows:
        dot.edge(flow["source"], flow["destination"], label=flow["dataType"])

    # Add trust boundaries as subgraphs
    for boundary in st.session_state.trust_boundaries:
        with dot.subgraph(name=f"cluster_{boundary['name']}") as c:
            c.attr(label=boundary["name"], style="dashed")
            # Assume components mentioned in boundary description are nodes
            components = re.findall(r"\b\w+\b", boundary["description"].lower())
            for node in nodes:
                if node.lower() in components:
                    c.node(node)

    # Render diagram to file and encode as base64
    diagram_path = dot.render("diagram", format="png", cleanup=True)
    with open(diagram_path, "rb") as f:
        st.session_state.generated_diagram = base64.b64encode(f.read()).decode("utf-8")
    return st.session_state.generated_diagram

def analyze_threats():
    """Perform comprehensive STRIDE-based threat analysis with security controls."""
    threats = []

    # Helper function to add threats
    def add_threat(threat_type, description, stride, mitigation, asvs, samm, controls=None):
        threat = {
            "type": threat_type,
            "description": description,
            "stride": stride,
            "mitigation": mitigation,
            "asvs": asvs,
            "samm": samm
        }
        if controls:
            threat["controls"] = controls
        threats.append(threat)

    # Analyze system description for components and design characteristics
    text_input = st.session_state.text_input.lower()
    components = {
        "web": "web application" in text_input or "website" in text_input or "public facing" in text_input,
        "api": "api" in text_input or "endpoint" in text_input,
        "database": "database" in text_input or "db" in text_input,
        "cloud": "cloud" in text_input or "aws" in text_input or "azure" in text_input,
        "authentication": "login" in text_input or "password" in text_input or "credential" in text_input,
        "third_party": "third party" in text_input or "external" in text_input,
        "public_facing": "public facing" in text_input or "external facing" in text_input
    }

    # Security controls for public-facing applications
    if components["public_facing"] or components["web"]:
        add_threat(
            "Spoofing",
            "Public-facing application vulnerable to impersonation attacks.",
            "Spoofing",
            "Implement strong authentication mechanisms such as multi-factor authentication (MFA) and OAuth 2.0 with short-lived tokens.",
            "V2.1.1 - Verify strong authentication controls; V2.7.1 - Verify session management.",
            "Threat Assessment Level 1 - Identify authentication risks; Governance Level 2 - Define authentication policies.",
            controls="Use MFA (e.g., TOTP, biometrics), OAuth 2.0 with PKCE, and secure session cookies with HttpOnly and Secure flags."
        )
        add_threat(
            "Denial of Service",
            "Public-facing application susceptible to DoS attacks due to high exposure.",
            "Denial of Service",
            "Deploy Web Application Firewall (WAF), enable rate limiting, and use CDN with DDoS protection (e.g., AWS CloudFront, Shield).",
            "V1.10.1 - Verify anti-DoS controls; V13.1.1 - Verify API security.",
            "Incident Management Level 2 - Implement proactive monitoring; Operations Level 2 - Ensure availability.",
            controls="Configure WAF rules for common attack patterns, set rate limits (e.g., 100 requests/min per IP), and enable auto-scaling."
        )

    # STRIDE: Spoofing
    if components["authentication"] or components["api"]:
        add_threat(
            "Spoofing",
            "Attackers may impersonate legitimate users or services.",
            "Spoofing",
            "Use strong session management, validate API tokens, and implement mutual TLS for APIs.",
            "V2.1.2 - Verify identity validation; V13.2.1 - Verify API authentication.",
            "Threat Assessment Level 1 - Identify authentication risks; Governance Level 2 - Enforce identity policies.",
            controls="Implement JWT validation with HMAC-SHA256 and enforce mutual TLS for API endpoints."
        )

    # STRIDE: Tampering
    if components["database"] or components["web"]:
        add_threat(
            "Tampering",
            "Data integrity may be compromised due to insufficient validation.",
            "Tampering",
            "Use parameterized queries, apply cryptographic hashing (e.g., SHA-256), and enforce input sanitization.",
            "V5.1.3 - Verify input validation; V5.3.4 - Verify secure database queries.",
            "Secure Architecture Level 1 - Define security requirements; Design Level 2 - Implement integrity controls.",
            controls="Use prepared statements for SQL queries and validate inputs against a whitelist."
        )

    # STRIDE: Repudiation
    if components["authentication"] or components["web"]:
        add_threat(
            "Repudiation",
            "Actions may not be traceable due to lack of audit trails.",
            "Repudiation",
            "Implement tamper-proof logging, centralize log storage, and enable log monitoring.",
            "V7.1.1 - Verify logging controls; V7.2.1 - Verify log integrity.",
            "Security Operations Level 2 - Enable audit logging; Incident Management Level 2 - Monitor logs.",
            controls="Use a SIEM system (e.g., AWS CloudTrail, Splunk) and ensure logs include timestamps and user IDs."
        )

    # STRIDE: Information Disclosure
    if components["database"] or components["cloud"]:
        add_threat(
            "Information Disclosure",
            "Sensitive data may be exposed due to unencrypted storage or weak access controls.",
            "Information Disclosure",
            "Encrypt data at rest (AES-256) and in transit (TLS 1.3), enforce least privilege, and use secure key management.",
            "V4.1.3 - Verify access controls; V9.1.1 - Verify secure communication.",
            "Secure Architecture Level 2 - Standardize security controls; Implementation Level 2 - Secure data handling.",
            controls="Use AWS KMS for key management and ensure database encryption with transparent data encryption."
        )

    # STRIDE: Denial of Service
    if components["api"] or components["web"] and not components["public_facing"]:
        add_threat(
            "Denial of Service",
            "System availability may be impacted by resource exhaustion.",
            "Denial of Service",
            "Implement rate limiting, use circuit breakers, and deploy auto-scaling groups.",
            "V1.10.2 - Verify rate limiting; V13.1.2 - Verify API resilience.",
            "Incident Management Level 2 - Monitor for DoS; Operations Level 2 - Ensure availability.",
            controls="Set API rate limits (e.g., 1000 requests/hour) and configure auto-scaling triggers based on CPU usage."
        )

    # STRIDE: Elevation of Privilege
    if components["third_party"] or components["cloud"]:
        add_threat(
            "Elevation of Privilege",
            "Privilege escalation due to misconfigured roles or third-party vulnerabilities.",
            "Elevation of Privilege",
            "Enforce RBAC, segregate duties, audit third-party components, and apply patches promptly.",
            "V4.2.1 - Verify RBAC; V14.2.3 - Verify dependency management.",
            "Secure Architecture Level 2 - Implement RBAC; Implementation Level 2 - Manage dependencies.",
            controls="Use IAM roles with least privilege and scan dependencies with tools like Dependabot."
        )

    # Analyze data flows
    for flow in st.session_state.data_flows:
        data_type = flow.get('dataType', '').lower()
        source = flow.get('source', '').lower()
        destination = flow.get('destination', '').lower()

        # Spoofing in data flows
        if 'user' in source or 'client' in source:
            add_threat(
                "Spoofing",
                f"Unauthorized access in flow from {source} to {destination}.",
                "Spoofing",
                "Validate source identity with OAuth 2.0 or JWT and enforce secure session handling.",
                "V2.1.2 - Verify identity validation; V2.7.3 - Verify session binding.",
                "Threat Assessment Level 1 - Identify authentication risks; Governance Level 2 - Enforce identity policies.",
                controls="Implement OAuth 2.0 with PKCE and secure JWT signing with RS256."
            )

        # Tampering in data flows
        add_threat(
            "Tampering",
            f"Data integrity risk in flow from {source} to {destination}.",
            "Tampering",
            "Use digital signatures or HMAC for integrity and validate inputs at the destination.",
            "V5.1.4 - Verify data integrity; V5.2.2 - Verify input sanitization.",
            "Design Level 2 - Implement integrity controls; Verification Level 1 - Validate inputs.",
            controls="Apply HMAC-SHA256 for data integrity and use schema-based input validation."
        )

        # Information Disclosure in sensitive data flows
        if 'pii' in data_type or 'sensitive' in data_type or 'confidential' in data_type:
            add_threat(
                "Information Disclosure",
                f"Sensitive data ({data_type}) exposed in flow from {source} to {destination}.",
                "Information Disclosure",
                "Encrypt data with TLS 1.3, mask sensitive data in logs, and restrict access.",
                "V9.1.2 - Verify encryption in transit; V4.1.4 - Verify access restrictions.",
                "Implementation Level 2 - Secure data handling; Operations Level 2 - Protect sensitive data.",
                controls="Use TLS 1.3 with strong ciphers and implement data masking for logs."
            )

        # Denial of Service in data flows
        if 'api' in destination or 'server' in destination:
            add_threat(
                "Denial of Service",
                f"Potential DoS attack targeting {destination} in data flow.",
                "Denial of Service",
                "Implement rate limiting, use circuit breakers, and monitor traffic anomalies.",
                "V1.10.2 - Verify rate limiting; V13.1.2 - Verify API resilience.",
                "Incident Management Level 2 - Monitor for DoS; Operations Level 2 - Ensure availability.",
                controls="Configure circuit breakers with a 5-second timeout and monitor with AWS CloudWatch."
            )

    # Analyze trust boundaries
    for boundary in st.session_state.trust_boundaries:
        name = boundary.get('name', '').lower()
        description = boundary.get('description', '').lower()

        # Spoofing across trust boundaries
        if 'boundary' in name or 'dmz' in name:
            add_threat(
                "Spoofing",
                f"Cross-boundary spoofing in {name}.",
                "Spoofing",
                "Enforce mutual TLS, use API gateway authentication, and validate cross-boundary requests.",
                "V2.1.3 - Verify boundary authentication; V13.2.1 - Verify API security.",
                "Threat Assessment Level 2 - Model boundary risks; Governance Level 2 - Define boundary policies.",
                controls="Implement mutual TLS with client certificates and use AWS API Gateway for authentication."
            )

        # Tampering within trust boundaries
        if 'database' in name or 'server' in name:
            add_threat(
                "Tampering",
                f"Data tampering within {name} due to weak controls.",
                "Tampering",
                "Use integrity checks (e.g., checksums), secure coding, and validate data within the boundary.",
                "V5.1.3 - Verify input validation; V5.3.5 - Verify secure coding.",
                "Design Level 2 - Implement integrity controls; Verification Level 2 - Validate boundary controls.",
                controls="Apply SHA-256 checksums and use OWASP secure coding guidelines."
            )

        # Elevation of Privilege within trust boundaries
        add_threat(
            "Elevation of Privilege",
            f"Privilege escalation within {name} due to misconfigured access controls.",
            "Elevation of Privilege",
            "Implement RBAC, segregate duties, and audit permissions regularly.",
            "V4.2.2 - Verify segregation of duties; V4.2.1 - Verify RBAC.",
            "Secure Architecture Level 2 - Implement RBAC; Governance Level 2 - Audit permissions.",
            controls="Define granular IAM roles and audit with AWS Config."
        )

    # Analyze diagram (simulate component detection)
    if st.session_state.diagram:
        diagram_components = []
        if components["web"]:
            diagram_components.append("Web Application")
        if components["database"]:
            diagram_components.append("Database")
        if components["api"]:
            diagram_components.append("API")
        if components["cloud"]:
            diagram_components.append("Cloud Service")

        for component in diagram_components:
            add_threat(
                "Spoofing",
                f"Impersonation of {component} in diagram.",
                "Spoofing",
                f"Secure {component} with strong authentication (e.g., OAuth, certificates).",
                "V2.1.1 - Verify authentication controls; V13.2.2 - Verify API authentication.",
                "Threat Assessment Level 1 - Identify component risks; Governance Level 2 - Enforce authentication.",
                controls=f"Use OAuth 2.0 for {component} authentication and validate certificates."
            )
            add_threat(
                "Information Disclosure",
                f"Data exposure in {component} due to unencrypted channels.",
                "Information Disclosure",
                f"Encrypt data flows to/from {component} and restrict access.",
                "V9.1.1 - Verify secure communication; V4.1.3 - Verify access controls.",
                "Implementation Level 2 - Secure data flows; Operations Level 2 - Protect components.",
                controls=f"Enable TLS 1.3 for {component} and restrict access with IAM policies."
            )
            add_threat(
                "Denial of Service",
                f"Resource exhaustion targeting {component} in diagram.",
                "Denial of Service",
                f"Implement rate limiting and auto-scaling for {component}.",
                "V1.10.1 - Verify anti-DoS controls; V13.1.1 - Verify API resilience.",
                "Incident Management Level 2 - Monitor components; Operations Level 2 - Ensure availability.",
                controls=f"Configure rate limiting and auto-scaling for {component} using AWS services."
            )

    return {"threats": threats}

def step_1():
    st.header("Step 1: Provide System Details")
    st.session_state.text_input = st.text_area(
        "Describe your system architecture (e.g., components, technologies, public-facing, third-party services)",
        st.session_state.text_input,
        height=200
    )
    uploaded_file = st.file_uploader("Upload a Data Flow Diagram (e.g., PNG, JPG)", type=["png", "jpg", "jpeg"])
    if uploaded_file:
        st.session_state.diagram = base64.b64encode(uploaded_file.read()).decode("utf-8")
        st.image(uploaded_file, caption="Uploaded Data Flow Diagram")
    if st.button("Next"):
        if st.session_state.text_input or st.session_state.diagram:
            st.session_state.step = 2
            st.rerun()
        else:
            st.session_state.error = "Please provide a system description or diagram."

def step_2():
    st.header("Step 2: Define Data Flows and Trust Boundaries")
    
    st.subheader("Data Flows")
    with st.container():
        source = st.text_input("Data Flow Source (e.g., User, API)", key="data_flow_source")
        destination = st.text_input("Data Flow Destination (e.g., Database, Service)", key="data_flow_destination")
        data_type = st.text_input("Data Type (e.g., PII, Public, Confidential)", key="data_flow_type")
        if st.button("Add Data Flow"):
            if source and destination and data_type:
                st.session_state.data_flows.append({"source": source, "destination": destination, "dataType": data_type})
                st.success("Data Flow added!")
                st.rerun()
            else:
                st.session_state.error = "Please fill in all data flow fields."
    
    if st.session_state.data_flows:
        st.write("**Current Data Flows:**")
        for flow in st.session_state.data_flows:
            st.write(f"{flow['source']} → {flow['destination']} ({flow['dataType']})")

    st.subheader("Trust Boundaries")
    with st.container():
        trust_boundary_options = [
            "Web Server Boundary",
            "Database Boundary",
            "API Boundary",
            "DMZ",
            "Cloud Service Boundary",
            "Custom"
        ]
        selected_boundary = st.selectbox("Select Trust Boundary", trust_boundary_options, key="trust_boundary_select")
        name = selected_boundary
        if selected_boundary == "Custom":
            name = st.text_input("Custom Trust Boundary Name", key="custom_boundary_name")
        description = st.text_input("Trust Boundary Description", key="boundary_description")
        if st.button("Add Trust Boundary"):
            if name and description and name != "Custom":
                st.session_state.trust_boundaries.append({"name": name, "description": description})
                st.success("Trust Boundary added!")
                st.rerun()
            else:
                st.session_state.error = "Please provide a valid trust boundary name and description."
    
    if st.session_state.trust_boundaries:
        st.write("**Current Trust Boundaries:**")
        for boundary in st.session_state.trust_boundaries:
            st.write(f"{boundary['name']}: {boundary['description']}")

    if st.session_state.data_flows or st.session_state.trust_boundaries:
        st.subheader("Generated Data Flow Diagram")
        diagram = generate_diagram()
        st.image(f"data:image/png;base64,{diagram}", caption="Generated Data Flow Diagram with Trust Boundaries")

    if st.button("Analyze Threats"):
        if st.session_state.data_flows or st.session_state.trust_boundaries:
            with st.spinner("Analyzing threats..."):
                st.session_state.threat_model = analyze_threats()
                st.session_state.step = 3
                st.rerun()
        else:
            st.session_state.error = "Please add at least one data flow or trust boundary."

def step_3():
    st.header("Step 3: Threat Model Results")
    if st.session_state.threat_model:
        st.subheader("Identified Threats")
        for threat in st.session_state.threat_model["threats"]:
            st.markdown(f"**{threat['type']}** (STRIDE: {threat['stride']})")
            st.markdown(f"- **Description**: {threat['description']}")
            st.markdown(f"- **Mitigation**: {threat['mitigation']}")
            if "controls" in threat:
                st.markdown(f"- **Security Controls**: {threat['controls']}")
            st.markdown(f"- **OWASP ASVS**: {threat['asvs']}")
            st.markdown(f"- **OWASP SAMM**: {threat['samm']}")
            st.markdown("---")
    if st.session_state.generated_diagram:
        st.subheader("Generated Data Flow Diagram")
        st.image(f"data:image/png;base64,{st.session_state.generated_diagram}", caption="Data Flow Diagram with Trust Boundaries")
    if st.button("Start Over"):
        st.session_state.step = 1
        st.session_state.text_input = ""
        st.session_state.diagram = None
        st.session_state.data_flows = []
        st.session_state.trust_boundaries = []
        st.session_state.threat_model = None
        st.session_state.error = ""
        st.session_state.generated_diagram = None
        st.rerun()
    if st.session_state.error:
        st.error(st.session_state.error)

# Render the current step
if st.session_state.step == 1:
    step_1()
elif st.session_state.step == 2:
    step_2()
elif st.session_state.step == 3:
    step_3()
