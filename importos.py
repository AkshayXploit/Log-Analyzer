import os
import pandas as pd
import base64
import io
import re
import requests
import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, Input, Output, State, ctx, dash_table

# --- API KEYS ---
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") or "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY") or "YOUR_ABUSEIPDB_API_KEY"

# --- App Setup ---
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.SOLAR])
app.title = "Cracken Log Analyzer PRO - Advanced v2"
server = app.server

# --- Global Variables ---
global_df = pd.DataFrame()
ioc_df = pd.DataFrame()
osint_results_df = pd.DataFrame()
attack_results_df = pd.DataFrame()

# --- Helper Functions ---
def parse_contents(contents):
    _, content_string = contents.split(',')
    decoded = base64.b64decode(content_string)
    try:
        data = io.StringIO(decoded.decode('utf-8'))
        lines = [l for l in data if not l.startswith("#") and l.strip()]
        records = [l.split()[:10] for l in lines if len(l.split()) >= 10]
        columns = ['date', 'time', 's-ip', 'cs-method', 'cs-uri-stem', 'cs-uri-query', 's-port', 'cs-username', 'c-ip', 'user-agent']
        return pd.DataFrame(records, columns=columns)
    except Exception as e:
        print(e)
        return pd.DataFrame()

def extract_indicators(texts):
    ips, domains, hashes = [], [], []
    for text in texts:
        ips += re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        domains += re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}\b', text)
        hashes += re.findall(r'\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b', text)
    return list(set(ips)), list(set(domains)), list(set(hashes))

def detect_web_attacks(texts):
    patterns = {
        "LFI": r"(\.\./)+",
        "RFI": r"(https?:\/\/\S+\.php)",
        "XSS": r"(<script>|javascript:|onerror=|onload=)",
        "RCE": r"(;|\|\||&&|\$\(.*\)|`.*`)",
        "SQL Injection": r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|--|#)\b)",
        "Command Injection": r"(\b(cat|ls|whoami|pwd|id)\b)",
        "Open Redirect": r"(=\s*https?:\/\/)",
        "Sensitive Files": r"(\.env|/etc/passwd|/etc/shadow)",
        "Path Traversal": r"(\.\./|\.\.\\)",
        "PHP Injection": r"(\.php\?)"
    }
    results = []
    for idx, text in enumerate(texts):
        for attack, pattern in patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                results.append({"Row": idx, "Attack Type": attack, "Snippet": text})
    return pd.DataFrame(results)

def vt_lookup_ip(ip):
    if not VT_API_KEY:
        return "No API Key"
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    if r.ok:
        j = r.json()
        return j.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
    return "Error"

def abuseip_lookup(ip):
    if not ABUSEIPDB_API_KEY:
        return "No API Key"
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    r = requests.get(url, headers=headers)
    if r.ok:
        j = r.json()
        return j.get('data', {}).get('abuseConfidenceScore', 0)
    return "Error"

def batch_osint(ips):
    results = []
    for ip in ips:
        vt_score = vt_lookup_ip(ip)
        abuse_score = abuseip_lookup(ip)
        results.append({"IP": ip, "VT Malicious Score": vt_score, "AbuseIPDB Score": abuse_score})
    return pd.DataFrame(results)

# --- Layout ---
app.layout = dbc.Container([
    html.H1("Cracken Log Analyzer PRO - Advanced v2", className="text-center text-warning display-4 mb-4"),

    dbc.Row([
        dbc.Col([
            dcc.Upload(
                id='upload-data',
                children=html.Div('📂 Drag & Drop or Click to Upload Log File', className='text-center text-white'),
                style={'height': '150px', 'border': '2px dashed white', 'borderRadius': '10px', 'textAlign': 'center', 'lineHeight': '150px', "background": "rgba(255,255,255,0.1)"},
                multiple=False
            ),
            html.Br(),
            dbc.Button("🔍 Extract IOCs", id="extract-iocs", color="info", className="w-100 my-2"),
            dbc.Button("🛡️ Detect Web Attacks", id="detect-attacks", color="danger", className="w-100 my-2"),
            dbc.Button("🌐 Run OSINT Scan", id="run-osint", color="primary", className="w-100 my-2"),
            html.Hr(),
            html.H5("🧹 Advanced Log Filtering", className="text-white text-center"),
            dbc.Input(id="filter-ip", placeholder="Filter by IP Address...", type="text", className="my-1"),
            dbc.Input(id="filter-method", placeholder="Filter by HTTP Method...", type="text", className="my-1"),
            dbc.Input(id="filter-uri", placeholder="Filter by URI Contains...", type="text", className="my-1"),
            dbc.Input(id="filter-date", placeholder="Filter by Date (YYYY-MM-DD)...", type="text", className="my-1"),
            dbc.Button("🔎 Apply Filters", id="apply-filters", color="success", className="w-100 my-2"),
            html.Hr(),
            dbc.Button("⬇️ Export Raw Logs", id="export-logs", color="secondary", className="w-100 my-2"),
            dbc.Button("⬇️ Export IOCs", id="export-iocs", color="secondary", className="w-100 my-2"),
            dbc.Button("⬇️ Export OSINT Results", id="export-osint", color="secondary", className="w-100 my-2"),
            dbc.Button("⬇️ Export Web Attacks", id="export-attacks", color="secondary", className="w-100 my-2"),
            html.Div(id="action-status", className="text-center text-success font-weight-bold mt-3"),
            dcc.Download(id="download-data")
        ], width=4),

        dbc.Col([
            dcc.Loading(
                id="loading-tables",
                type="cube",
                children=dash_table.DataTable(
                    id="result-table",
                    style_table={'overflowX': 'auto'},
                    style_header={'backgroundColor': '#17a2b8', 'color': 'white', 'fontWeight': 'bold'},
                    style_cell={'backgroundColor': 'black', 'color': 'white', 'textAlign': 'center'},
                    page_size=10
                )
            )
        ], width=8)
    ])
], fluid=True)

# --- Main Controller Callback ---
@app.callback(
    Output("result-table", "data"),
    Output("result-table", "columns"),
    Output("action-status", "children"),
    Input("upload-data", "contents"),
    Input("extract-iocs", "n_clicks"),
    Input("detect-attacks", "n_clicks"),
    Input("run-osint", "n_clicks"),
    Input("apply-filters", "n_clicks"),
    State("upload-data", "filename"),
    State("filter-ip", "value"),
    State("filter-method", "value"),
    State("filter-uri", "value"),
    State("filter-date", "value"),
    prevent_initial_call=True
)
def main_controller(contents, extract_click, attack_click, osint_click, filter_click,
                    filename, ip_value, method_value, uri_value, date_value):
    global global_df, ioc_df, osint_results_df, attack_results_df
    triggered = ctx.triggered_id

    if triggered == "upload-data" and contents:
        global_df = parse_contents(contents)
        if global_df.empty:
            return [], [], "⚠️ Failed to parse file."
        columns = [{"name": i, "id": i} for i in global_df.columns]
        return global_df.to_dict('records'), columns, f"✅ Uploaded {filename} with {len(global_df)} rows."

    elif triggered == "extract-iocs" and not global_df.empty:
        combined_text = global_df.astype(str).apply(lambda x: ' '.join(x), axis=1)
        ips, domains, hashes = extract_indicators(combined_text)
        ioc_df = pd.DataFrame({"Indicator": ips + domains + hashes, "Type": ["IP"]*len(ips) + ["Domain"]*len(domains) + ["Hash"]*len(hashes)})
        columns = [{"name": i, "id": i} for i in ioc_df.columns]
        return ioc_df.to_dict('records'), columns, f"✅ Extracted {len(ioc_df)} IOCs."

    elif triggered == "detect-attacks" and not global_df.empty:
        combined_text = global_df.astype(str).apply(lambda x: ' '.join(x), axis=1)
        attack_results_df = detect_web_attacks(combined_text)
        columns = [{"name": i, "id": i} for i in attack_results_df.columns]
        return attack_results_df.to_dict('records'), columns, f"⚔️ Detected {len(attack_results_df)} Web Attacks."

    elif triggered == "run-osint" and not ioc_df.empty:
        ips = ioc_df[ioc_df['Type'] == "IP"]['Indicator'].tolist()
        osint_results_df = batch_osint(ips)
        columns = [{"name": i, "id": i} for i in osint_results_df.columns]
        return osint_results_df.to_dict('records'), columns, f"🌐 OSINT Scan Complete for {len(ips)} IPs."

    elif triggered == "apply-filters" and not global_df.empty:
        filtered_df = global_df.copy()
        if ip_value:
            filtered_df = filtered_df[filtered_df['c-ip'].str.contains(ip_value, case=False, na=False)]
        if method_value:
            filtered_df = filtered_df[filtered_df['cs-method'].str.contains(method_value, case=False, na=False)]
        if uri_value:
            filtered_df = filtered_df[filtered_df['cs-uri-stem'].str.contains(uri_value, case=False, na=False)]
        if date_value:
            filtered_df = filtered_df[filtered_df['date'].str.contains(date_value, na=False)]
        columns = [{"name": i, "id": i} for i in filtered_df.columns]
        return filtered_df.to_dict('records'), columns, f"✅ Showing {len(filtered_df)} filtered logs."

    return [], [], "⚠️ Nothing to process."

# --- Export Data ---
@app.callback(
    Output("download-data", "data"),
    Input("export-logs", "n_clicks"),
    Input("export-iocs", "n_clicks"),
    Input("export-osint", "n_clicks"),
    Input("export-attacks", "n_clicks"),
    prevent_initial_call=True
)
def export_data(log_click, ioc_click, osint_click, attack_click):
    triggered = ctx.triggered_id
    if triggered == "export-logs" and not global_df.empty:
        return dcc.send_data_frame(global_df.to_csv, "raw_logs.csv", index=False)
    if triggered == "export-iocs" and not ioc_df.empty:
        return dcc.send_data_frame(ioc_df.to_csv, "iocs.csv", index=False)
    if triggered == "export-osint" and not osint_results_df.empty:
        return dcc.send_data_frame(osint_results_df.to_csv, "osint_results.csv", index=False)
    if triggered == "export-attacks" and not attack_results_df.empty:
        return dcc.send_data_frame(attack_results_df.to_csv, "web_attacks.csv", index=False)

# --- Run ---
if __name__ == "__main__":
    app.run(debug=True)
