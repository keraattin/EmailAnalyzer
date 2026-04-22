import json
from html import escape

def generate_headers_section(headers):
    # Data
    ######################################################################
    html = """
        <h2 id="headers-section" style="text-align: center;"><i class="fa-solid fa-code"></i> Headers</h2>
        <hr>
        <h3 id="headers-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in headers["Data"].items():
        # Populate table rows
        html += f"<tr><td>{ escape(str(key)) }</td><td>{ escape(str(value)) }</td></tr>"
        
    html += """
        </tbody>
    </table>
    """
    ######################################################################
    
    # Investigation
    ######################################################################
    html += """
        <h3 id="headers-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <div class="row">
    """
    for index,values in headers["Investigation"].items():
        # Populate table rows
        html += """
        <div class="col-md-4">
            <div class="jumbotron">
                <h3>{}</h3><hr>
        """.format(escape(str(index)))
        for k,v in values.items():
            html += f"<br><b>{escape(str(k))}:<br></b>{escape(str(v))}"
        
        html += """
            </div>
        </div>
        """

    html += "</div><hr>"
    return html
    ######################################################################

def generate_links_section(links):
    # Data
    ######################################################################
    html = """
        <h2 id="links-section" style="text-align: center;"><i class="fa-solid fa-link"></i> Links</h2>
        <hr>
        <h3 id="links-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in links["Data"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>{}</td>".format(escape(str(key)), escape(str(value)))
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="links-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for index,values in links["Investigation"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>".format(escape(str(index)))
        for k,v in values.items():
            html += f"<b><a href='{escape(v)}' target='_blank'>{escape(k)} Scan</a></b>&nbsp;&nbsp;"
        html += "</td></tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_attachment_section(attachments):
    # Data
    ######################################################################
    html = """
        <h2 id="attachments-section" style="text-align: center;"><i class="fa-solid fa-paperclip"></i> Attachments</h2>
        <hr>
        <h3 id="attachments-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Filename</th>
                    <th>MIME Type</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in attachments["Data"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>{}</td><td>{}</td>".format(
            escape(str(key)),
            escape(str(value["filename"])),
            escape(str(value["mime_type"]))
        )
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="attachments-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for index,values in attachments["Investigation"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>".format(escape(str(index)))
        if index == "Duplicate Warning":
            for sha,names in values.items():
                joined = ", ".join(escape(n) for n in names)
                html += f"<b>{escape(sha)}</b>: {joined}<br>"
        else:
            for k,v in values.items():
                for x,y in v.items():
                    html += f"<b><a href='{escape(y)}' target='_blank'>{escape(x)} Scan({escape(k)})</a></b><br>"
        html += "</td></tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_auth_section(authentication):
    html = """
        <h2 id="authentication-section" style="text-align: center;"><i class="fa-solid fa-shield-halved"></i> Authentication</h2>
        <hr>
        <h3 id="authentication-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Result</th>
                </tr>
            </thead>
        <tbody>
    """
    STATUS_CLASSES = {"pass": "success", "fail": "danger", "softfail": "warning"}
    for key, value in authentication["Data"].items():
        badge_class = STATUS_CLASSES.get(value, "secondary")
        html += f"<tr><td>{escape(str(key))}</td><td><span class='badge badge-{badge_class}'>{escape(str(value))}</span></td></tr>"

    html += """
        </tbody>
    </table>
    <hr>"""
    return html

def generate_digest_section(digests):
    # Data
    ######################################################################
    html = """
        <h2 id="digests-section" style="text-align: center;"><i class="fa-solid fa-hashtag"></i> Digests</h2>
        <hr>
        <h3 id="digests-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in digests["Data"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>{}</td>".format(escape(str(key)), escape(str(value)))
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="digests-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for index,values in digests["Investigation"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>".format(escape(str(index)))
        for k,v in values.items():
            html += f"<b><a href='{escape(v)}' target='_blank'>{escape(k)} scan</a></b><br>"
        html += "</td></tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_summary_section(data):
    headers_data = data.get("Headers", {}).get("Data", {})
    headers_inv  = data.get("Headers", {}).get("Investigation", {})
    auth_data    = data.get("Authentication", {}).get("Data", {})
    links_cnt    = len(data.get("Links", {}).get("Data", {}))
    attach_cnt   = len(data.get("Attachments", {}).get("Data", {}))

    # Collect triggered threat flags
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

    # Threat level
    if any(color == "danger" for color, _, _ in threat_flags):
        level, level_class = "HIGH", "danger"
    elif threat_flags:
        level, level_class = "MEDIUM", "warning"
    else:
        level, level_class = "LOW", "success"

    html = """
        <h2 id="summary-section" style="text-align: center;"><i class="fa-solid fa-shield-halved"></i> Threat Summary</h2>
        <hr>
        <div class="row">
            <div class="col-md-6">
                <h3><i class="fa-solid fa-envelope-open-text"></i> Email Overview</h3>
                <table class="table table-bordered table-striped">
                    <tbody>
    """
    for field in ("from", "to", "subject", "date"):
        value = headers_data.get(field, "—")
        html += f"<tr><td><b>{escape(field.capitalize())}</b></td><td>{escape(str(value))}</td></tr>"
    html += f"""
                        <tr><td><b>Links Found</b></td><td>{links_cnt}</td></tr>
                        <tr><td><b>Attachments Found</b></td><td>{attach_cnt}</td></tr>
                    </tbody>
                </table>
            </div>
            <div class="col-md-6">
                <h3><i class="fa-solid fa-triangle-exclamation"></i> Threat Level &nbsp;
                    <span class="badge badge-{level_class}">{escape(level)}</span>
                </h3>
                <hr>
    """

    if threat_flags:
        for color, name, detail in threat_flags:
            html += f"""
                <div class="alert alert-{color}" role="alert">
                    <b>{escape(name)}</b><br>{escape(str(detail))}
                </div>
            """
    else:
        html += '<div class="alert alert-success" role="alert">No threat indicators detected.</div>'

    html += """
            </div>
        </div>
        <hr>
    """
    return html


def generate_table_from_json(json_obj):
    # Parse JSON object
    data = json_obj["Analysis"]
    info_data = json_obj["Information"]

    # Object Counts
    if data.get("Headers"):
        headers_cnt = len(data["Headers"]["Data"])
        headers_inv_cnt = len(data["Headers"]["Investigation"])
    else:
        headers_cnt = 0
        headers_inv_cnt = 0

    if data.get("Links"):
        links_cnt = len(data["Links"]["Data"])
        links_inv_cnt = len(data["Links"]["Investigation"])
    else:
        links_cnt = 0
        links_inv_cnt = 0

    if data.get("Attachments"):
        attach_cnt = len(data["Attachments"]["Data"])
        attach_inv_cnt = len(data["Attachments"]["Investigation"])
    else:
        attach_cnt = 0
        attach_inv_cnt = 0

    if data.get("Digests"):
        digest_cnt = len(data["Digests"]["Data"])
        digest_inv_cnt = len(data["Digests"]["Investigation"])
    else:
        digest_cnt = 0
        digest_inv_cnt = 0

    if data.get("Authentication"):
        auth_cnt = len(data["Authentication"]["Data"])
    else:
        auth_cnt = 0

    # Generate HTML table with Bootstrap classes
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Analyzer Report — { escape(info_data["Scan"]["Filename"]) }</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script async defer src="https://buttons.github.io/buttons.js"></script>
</head>
<body>

        <nav class="navbar navbar-expand-lg navbar-light bg-light">
            <a class="navbar-brand" href="#"><i class="fa fa-envelope"></i> Email Analyzer</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarSupportedContent">
                <ul class="navbar-nav mr-auto">
                <li class="nav-item">
                    <a class="nav-link" href="#summary-section"><i class="fa-solid fa-shield-halved"></i> Summary</a>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="headersDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Headers
                    </a>
                    <div class="dropdown-menu" aria-labelledby="headersDropdown">
                    <a class="dropdown-item" href="#headers-data-section">Data <span class="badge badge-pill badge-dark">{ headers_cnt }</span></a>
                    <a class="dropdown-item" href="#headers-investigation-section">Investigation <span class="badge badge-pill badge-dark">{ headers_inv_cnt }</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="authenticationDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Authentication
                    </a>
                    <div class="dropdown-menu" aria-labelledby="authenticationDropdown">
                    <a class="dropdown-item" href="#authentication-data-section">Data <span class="badge badge-pill badge-dark">{ auth_cnt }</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="linksDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Links
                    </a>
                    <div class="dropdown-menu" aria-labelledby="linksDropdown">
                    <a class="dropdown-item" href="#links-data-section">Data <span class="badge badge-pill badge-dark">{ links_cnt }</span></a>
                    <a class="dropdown-item" href="#links-investigation-section">Investigation <span class="badge badge-pill badge-dark">{ links_inv_cnt }</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="attachmentsDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Attachments
                    </a>
                    <div class="dropdown-menu" aria-labelledby="attachmentsDropdown">
                    <a class="dropdown-item" href="#attachments-data-section">Data <span class="badge badge-pill badge-dark">{ attach_cnt }</span></a>
                    <a class="dropdown-item" href="#attachments-investigation-section">Investigation <span class="badge badge-pill badge-dark">{ attach_inv_cnt }</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="digestsDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Digests
                    </a>
                    <div class="dropdown-menu" aria-labelledby="digestsDropdown">
                    <a class="dropdown-item" href="#digests-data-section">Data <span class="badge badge-pill badge-dark">{ digest_cnt }</span></a>
                    <a class="dropdown-item" href="#digests-investigation-section">Investigation <span class="badge badge-pill badge-dark">{ digest_inv_cnt }</span></a>
                    </div>
                </li>
                </ul>
            </div>

            <div class="d-flex">
                <!-- Star -->
                <a class="github-button" href="https://github.com/keraattin/EmailAnalyzer" data-icon="octicon-star" data-size="large" data-show-count="true" aria-label="Star keraattin/EmailAnalyzer on GitHub">Star</a>
                &nbsp;
                <!-- Fork -->
                <a class="github-button" href="https://github.com/keraattin/EmailAnalyzer/fork" data-icon="octicon-repo-forked" data-size="large" data-show-count="true" aria-label="Fork keraattin/EmailAnalyzer on GitHub">Fork</a>
                &nbsp;
                <!-- Follow -->
                <a class="github-button" href="https://github.com/keraattin" data-size="large" data-show-count="true" aria-label="Follow @keraattin on GitHub">Follow @keraattin</a>
            </div>
        </nav>

        <div class="container-fluid">
        """
    
    html += f"""
        <h2 style="text-align: center;"><i class="fa-solid fa-circle-info"></i> Information</h2>
        <hr>
        <div class="row">
            <div class="col-md-6">
                <h3 style="text-align: center;"><i class="fa-solid fa-diagram-project"></i> Project</h3>
                <table class="table table-bordered table-striped">
                    <tbody>
                        <tr>
                            <td>Name</td>
                            <td>{ info_data["Project"]["Name"] }</td>
                        </tr>
                        <tr>
                            <td>Url</td>
                            <td><a href="{ info_data["Project"]["Url"] }" target='_blank'>{ info_data["Project"]["Url"] }</a></td>
                        </tr>
                        <tr>
                            <td>Version</td>
                            <td>{ info_data["Project"]["Version"] }</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="col-md-6">
                <h3 style="text-align: center;"><i class="fa-solid fa-satellite-dish"></i> Scan</h3>
                <table class="table table-bordered table-striped">
                    <tbody>
                        <tr>
                            <td>Name</td>
                            <td>{ escape(info_data["Scan"]["Filename"]) }</td>
                        </tr>
                        <tr>
                            <td>Generated</td>
                            <td>{ escape(info_data["Scan"]["Generated"]) }</td>
                        </tr>
                    </tbody>
                </table>
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
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/js/bootstrap.min.js"></script>
</body>
</html>"""

    return html
