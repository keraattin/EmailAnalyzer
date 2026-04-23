import json
from html import escape


def _render_inv_value(k, v):
    """Render one investigation key/value. Handles URL strings and nested dicts (e.g. Received IPs)."""
    if isinstance(v, dict):
        links_html = "".join(
            f'<a href="{escape(url)}" class="badge bg-secondary text-decoration-none me-1" target="_blank">{escape(tool)}</a>'
            for tool, url in v.items()
        )
        return f'<div class="mb-1"><span class="fw-bold">{escape(str(k))}</span>: {links_html}</div>'
    elif isinstance(v, str) and v.startswith("http"):
        return f'<div class="mb-1"><span class="fw-bold">{escape(k)}</span>: <a href="{escape(v)}" target="_blank">{escape(v)}</a></div>'
    else:
        return f'<div class="mb-1"><span class="fw-bold">{escape(str(k))}</span>: {escape(str(v))}</div>'


def generate_headers_section(headers):
    html = """
        <h2 id="headers-section" class="text-center mt-4"><i class="fa-solid fa-code"></i> Headers</h2>
        <hr>
        <h5 id="headers-data-section" class="text-muted"><i class="fa-solid fa-chart-column"></i> Data</h5>
        <table class="table table-bordered table-striped table-sm">
            <thead class="table-dark">
                <tr><th>Key</th><th>Value</th></tr>
            </thead>
            <tbody>
    """
    for key, value in headers["Data"].items():
        html += f'<tr><td class="fw-bold text-nowrap">{escape(str(key))}</td><td><code class="text-break">{escape(str(value))}</code></td></tr>'
    html += "</tbody></table>"

    html += """
        <h5 id="headers-investigation-section" class="text-muted mt-3"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h5>
        <div class="row g-3">
    """
    for index, values in headers["Investigation"].items():
        html += f"""
        <div class="col-md-4">
            <div class="card h-100 shadow-sm">
                <div class="card-header fw-bold">{escape(str(index))}</div>
                <div class="card-body small">
        """
        for k, v in values.items():
            html += _render_inv_value(k, v)
        html += "</div></div></div>"
    html += "</div><hr>"
    return html


def generate_links_section(links):
    """Single merged table: URL + scan links in one row."""
    html = """
        <h2 id="links-section" class="text-center mt-4"><i class="fa-solid fa-link"></i> Links</h2>
        <hr>
        <table class="table table-bordered table-striped table-sm" id="links-data-section">
            <thead class="table-dark">
                <tr>
                    <th style="width:3%">#</th>
                    <th>URL</th>
                    <th style="width:18%">Scan</th>
                </tr>
            </thead>
            <tbody>
    """
    for key, value in links["Data"].items():
        inv = links["Investigation"].get(str(key), {})
        js_val = escape(json.dumps(str(value)))
        copy_btn = f'<button class="btn btn-sm btn-outline-secondary ms-1" onclick="copyToClipboard({js_val})" title="Copy URL"><i class="fa-regular fa-copy"></i></button>'
        scan_links = "".join(
            f'<a href="{escape(url)}" class="badge bg-secondary text-decoration-none me-1" target="_blank">{escape(tool)} Scan</a>'
            for tool, url in inv.items()
        )
        html += f"""
        <tr>
            <td>{escape(str(key))}</td>
            <td><span class="text-break">{escape(str(value))}</span>{copy_btn}</td>
            <td>{scan_links}</td>
        </tr>"""
    html += "</tbody></table><hr>"
    return html


def generate_attachment_section(attachments):
    """Merged table: filename + MIME type + scan links in one row."""
    html = """
        <h2 id="attachments-section" class="text-center mt-4"><i class="fa-solid fa-paperclip"></i> Attachments</h2>
        <hr>
        <table class="table table-bordered table-striped table-sm">
            <thead class="table-dark">
                <tr><th style="width:3%">#</th><th>Filename</th><th style="width:20%">MIME Type</th><th style="width:20%">Scan</th></tr>
            </thead>
            <tbody>
    """
    for key, value in attachments["Data"].items():
        filename  = str(value["filename"])
        mime_type = str(value["mime_type"])
        inv_entry = attachments["Investigation"].get(filename, {})
        scan_links = "".join(
            f'<a href="{escape(y)}" class="badge bg-secondary text-decoration-none me-1 mb-1" target="_blank">{escape(x)} ({escape(k)})</a>'
            for k, v in inv_entry.items()
            for x, y in v.items()
        )
        html += "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            escape(str(key)), escape(filename), escape(mime_type), scan_links
        )

    dup = attachments["Investigation"].get("Duplicate Warning")
    if dup:
        dup_rows = "".join(
            f'<div><code>{escape(sha)}</code>: {", ".join(escape(n) for n in names)}</div>'
            for sha, names in dup.items()
        )
        html += f'<tr><td colspan="4"><div class="alert alert-warning mb-0 py-2"><b>Duplicate Warning</b><br>{dup_rows}</div></td></tr>'

    html += "</tbody></table><hr>"
    return html


def generate_auth_section(authentication):
    html = """
        <h2 id="authentication-section" class="text-center mt-4"><i class="fa-solid fa-shield-halved"></i> Authentication</h2>
        <hr>
        <table class="table table-bordered table-sm w-auto" id="authentication-data-section">
            <thead class="table-dark">
                <tr><th>Protocol</th><th>Result</th></tr>
            </thead>
            <tbody>
    """
    STATUS_CLASSES = {
        "pass":     "bg-success",
        "fail":     "bg-danger",
        "softfail": "bg-warning text-dark",
    }
    for key, value in authentication["Data"].items():
        badge_cls = STATUS_CLASSES.get(value, "bg-secondary")
        html += f'<tr><td class="fw-bold">{escape(str(key)).upper()}</td><td><span class="badge {badge_cls}">{escape(str(value))}</span></td></tr>'
    html += "</tbody></table><hr>"
    return html


def generate_digest_section(digests):
    """Merged table: hash value + scan link in one row."""
    html = """
        <h2 id="digests-section" class="text-center mt-4"><i class="fa-solid fa-hashtag"></i> Digests</h2>
        <hr>
        <table class="table table-bordered table-striped table-sm">
            <thead class="table-dark">
                <tr><th style="width:18%">Key</th><th>Hash</th><th style="width:12%">Scan</th></tr>
            </thead>
            <tbody>
    """
    for key, value in digests["Data"].items():
        js_val = escape(json.dumps(str(value)))
        copy_btn = f'<button class="btn btn-sm btn-outline-secondary ms-2" onclick="copyToClipboard({js_val})" title="Copy hash"><i class="fa-regular fa-copy"></i></button>'
        inv_entry = digests["Investigation"].get(str(key), {})
        scan_links = "".join(
            f'<a href="{escape(url)}" class="badge bg-secondary text-decoration-none me-1" target="_blank">{escape(tool)}</a>'
            for tool, url in inv_entry.items()
        )
        html += f'<tr><td class="fw-bold text-nowrap">{escape(str(key))}</td><td><code class="text-break">{escape(str(value))}</code>{copy_btn}</td><td>{scan_links}</td></tr>'
    html += "</tbody></table><hr>"
    return html


def generate_summary_section(data):
    headers_data = data.get("Headers", {}).get("Data", {})
    headers_inv  = data.get("Headers", {}).get("Investigation", {})
    auth_data    = data.get("Authentication", {}).get("Data", {})
    links_cnt    = len(data.get("Links", {}).get("Data", {}))
    attach_cnt   = len(data.get("Attachments", {}).get("Data", {}))

    threat_flags = []

    spoof = headers_inv.get("Spoof Check", {})
    if "SPOOFED" in spoof.get("Conclusion", ""):
        threat_flags.append(("danger", "Spoof Check", spoof["Conclusion"]))

    dn = headers_inv.get("Display Name Check", {})
    if "impersonation" in dn.get("Conclusion", "").lower():
        threat_flags.append(("warning", "Display Name Check", dn["Conclusion"]))

    rt = headers_inv.get("Reply-To Domain Check", {})
    if "differ" in rt.get("Conclusion", "").lower():
        threat_flags.append(("warning", "Reply-To Domain Check", rt["Conclusion"]))

    for flag_name, flag_detail in headers_inv.get("Suspicious Headers", {}).items():
        threat_flags.append(("warning", f"Suspicious Header: {flag_name}", flag_detail))

    for proto, result in auth_data.items():
        if result in ("fail", "softfail"):
            threat_flags.append(("danger", f"Auth Failure: {proto.upper()}", f"{proto.upper()} result is '{result}'"))

    dup = headers_inv.get("Duplicate Warning") or data.get("Attachments", {}).get("Investigation", {}).get("Duplicate Warning")
    if dup:
        threat_flags.append(("warning", "Duplicate Attachments", "One or more attachments share the same SHA256 hash."))

    if any(color == "danger" for color, _, _ in threat_flags):
        level, badge_cls = "HIGH", "badge bg-danger"
    elif threat_flags:
        level, badge_cls = "MEDIUM", "badge bg-warning text-dark"
    else:
        level, badge_cls = "LOW", "badge bg-success"

    html = """
        <h2 id="summary-section" class="text-center mt-4"><i class="fa-solid fa-shield-halved"></i> Threat Summary</h2>
        <hr>
        <div class="row g-4">
            <div class="col-md-6">
                <div class="card shadow-sm h-100">
                    <div class="card-header fw-bold"><i class="fa-solid fa-envelope-open-text"></i> Email Overview</div>
                    <div class="card-body p-0">
                        <table class="table table-sm mb-0">
                            <tbody>
    """
    for field in ("from", "to", "subject", "date"):
        value = headers_data.get(field, "—")
        html += f'<tr><td class="fw-bold ps-3" style="width:30%">{escape(field.capitalize())}</td><td class="text-break">{escape(str(value))}</td></tr>'
    html += f"""
                                <tr><td class="fw-bold ps-3">Links</td><td>{links_cnt}</td></tr>
                                <tr><td class="fw-bold ps-3">Attachments</td><td>{attach_cnt}</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card shadow-sm h-100">
                    <div class="card-header fw-bold">
                        <i class="fa-solid fa-triangle-exclamation"></i> Threat Level &nbsp;
                        <span class="{badge_cls}">{escape(level)}</span>
                    </div>
                    <div class="card-body">
    """

    if threat_flags:
        for color, name, detail in threat_flags:
            html += f'<div class="alert alert-{color} py-2 mb-2" role="alert"><b>{escape(name)}</b><br><small>{escape(str(detail))}</small></div>'
    else:
        html += '<div class="alert alert-success" role="alert">No threat indicators detected.</div>'

    html += """
                    </div>
                </div>
            </div>
        </div>
        <hr>
    """
    return html


def generate_table_from_json(json_obj):
    data      = json_obj["Analysis"]
    info_data = json_obj["Information"]

    headers_cnt     = len(data["Headers"]["Data"])          if data.get("Headers")        else 0
    headers_inv_cnt = len(data["Headers"]["Investigation"]) if data.get("Headers")        else 0
    links_cnt       = len(data["Links"]["Data"])             if data.get("Links")          else 0
    attach_cnt      = len(data["Attachments"]["Data"])       if data.get("Attachments")    else 0
    digest_cnt      = len(data["Digests"]["Data"])           if data.get("Digests")        else 0
    auth_cnt        = len(data["Authentication"]["Data"])    if data.get("Authentication") else 0

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Analyzer Report — { escape(info_data["Scan"]["Filename"]) }</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.3/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <script async defer src="https://buttons.github.io/buttons.js"></script>
    <script>
    function copyToClipboard(text) {{
        if (navigator.clipboard) {{
            navigator.clipboard.writeText(text);
        }} else {{
            var el = document.createElement('textarea');
            el.value = text;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
        }}
    }}
    </script>
</head>
<body class="bg-light">

    <nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top shadow">
        <div class="container">
            <a class="navbar-brand" href="#"><i class="fa fa-envelope me-2"></i>Email Analyzer</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarSupportedContent">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="#summary-section"><i class="fa-solid fa-shield-halved me-1"></i>Summary</a>
                    </li>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="headersDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">Headers</a>
                        <ul class="dropdown-menu dropdown-menu-dark" aria-labelledby="headersDropdown">
                            <li><a class="dropdown-item" href="#headers-data-section">Data <span class="badge bg-secondary rounded-pill">{ headers_cnt }</span></a></li>
                            <li><a class="dropdown-item" href="#headers-investigation-section">Investigation <span class="badge bg-secondary rounded-pill">{ headers_inv_cnt }</span></a></li>
                        </ul>
                    </li>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="authenticationDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">Authentication</a>
                        <ul class="dropdown-menu dropdown-menu-dark" aria-labelledby="authenticationDropdown">
                            <li><a class="dropdown-item" href="#authentication-section">Data <span class="badge bg-secondary rounded-pill">{ auth_cnt }</span></a></li>
                        </ul>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#links-section"><i class="fa-solid fa-link me-1"></i>Links <span class="badge bg-secondary rounded-pill">{ links_cnt }</span></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#attachments-section"><i class="fa-solid fa-paperclip me-1"></i>Attachments <span class="badge bg-secondary rounded-pill">{ attach_cnt }</span></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#digests-section"><i class="fa-solid fa-hashtag me-1"></i>Digests <span class="badge bg-secondary rounded-pill">{ digest_cnt }</span></a>
                    </li>
                </ul>
                <div class="d-flex gap-2 align-items-center">
                    <a class="github-button" href="https://github.com/keraattin/EmailAnalyzer" data-icon="octicon-star" data-size="large" data-show-count="true" aria-label="Star keraattin/EmailAnalyzer on GitHub">Star</a>
                    <a class="github-button" href="https://github.com/keraattin/EmailAnalyzer/fork" data-icon="octicon-repo-forked" data-size="large" data-show-count="true" aria-label="Fork keraattin/EmailAnalyzer on GitHub">Fork</a>
                    <a class="github-button" href="https://github.com/keraattin" data-size="large" data-show-count="true" aria-label="Follow @keraattin on GitHub">Follow @keraattin</a>
                </div>
            </div>
        </div>
    </nav>

    <div class="container py-4">

        <h2 class="text-center"><i class="fa-solid fa-circle-info"></i> Information</h2>
        <hr>
        <div class="row g-4 mb-4">
            <div class="col-md-6">
                <div class="card shadow-sm h-100">
                    <div class="card-header fw-bold"><i class="fa-solid fa-diagram-project"></i> Project</div>
                    <div class="card-body p-0">
                        <table class="table table-sm mb-0">
                            <tbody>
                                <tr><td class="fw-bold ps-3">Name</td><td>{ escape(info_data["Project"]["Name"]) }</td></tr>
                                <tr><td class="fw-bold ps-3">URL</td><td><a href="{ escape(info_data["Project"]["Url"]) }" target="_blank">{ escape(info_data["Project"]["Url"]) }</a></td></tr>
                                <tr><td class="fw-bold ps-3">Version</td><td>{ escape(str(info_data["Project"]["Version"])) }</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card shadow-sm h-100">
                    <div class="card-header fw-bold"><i class="fa-solid fa-satellite-dish"></i> Scan</div>
                    <div class="card-body p-0">
                        <table class="table table-sm mb-0">
                            <tbody>
                                <tr><td class="fw-bold ps-3">File</td><td>{ escape(info_data["Scan"]["Filename"]) }</td></tr>
                                <tr><td class="fw-bold ps-3">Generated</td><td>{ escape(info_data["Scan"]["Generated"]) }</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
"""

    html += generate_summary_section(data)

    if data.get("Headers"):
        html += generate_headers_section(data["Headers"])

    if data.get("Authentication"):
        html += generate_auth_section(data["Authentication"])

    if data.get("Links"):
        html += generate_links_section(data["Links"])

    if data.get("Attachments"):
        html += generate_attachment_section(data["Attachments"])

    if data.get("Digests"):
        html += generate_digest_section(data["Digests"])

    html += """
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.3/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""

    return html
