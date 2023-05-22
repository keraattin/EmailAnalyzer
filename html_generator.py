import json

def generate_headers_section(headers):
    # Data
    ######################################################################
    html = f"""
        <h2 id="headers-section" style="text-align: center;">Headers</h2>
        <hr>
        <h3 id="headers-data-section">Data</h3>
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
        html += "<tr>"
        html += "<td>{}</td><td>{}</td>".format(key,value)
        html += "</tr>"
        
    html += """
        </tbody>
    </table>
    """
    ######################################################################
    
    # Investigation
    ######################################################################
    html += """
        <h3 id="headers-investigation-section">Investigation</h3>
        <div class="row">
    """
    for index,values in headers["Investigation"].items():
        # Populate table rows
        html += """
        <div class="col-md-4">
            <div class="jumbotron">
                <h3>{}</h3><hr>
        """.format(index)
        for k,v in values.items():
            html += f"<br><b>{k}:<br></b>{v}"
        
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
    html = f"""
        <h2 id="links-section" style="text-align: center;">Links</h2>
        <hr>
        <h3 id="links-data-section">Data</h3>
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
        html += "<td>{}</td><td>{}</td>".format(key,value)
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += f"""
        <h3 id="links-investigation-section">Investigation</h3>
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
        html += "<td>{}</td><td>".format(index)
        for k,v in values.items():
            html += f"<b><a href='{v}'>{k} Scan</a></b>&nbsp;&nbsp;"
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
    html = f"""
        <h2 id="attachments-section" style="text-align: center;">Attachments</h2>
        <hr>
        <h3 id="attachments-data-section">Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in attachments["Data"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>{}</td>".format(key,value)
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += f"""
        <h3 id="attachments-investigation-section">Investigation</h3>
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
        html += "<td>{}</td><td>".format(index)
        for k,v in values.items():
            for x,y in v.items():
                html += f"<b><a href='{y}'>{x} Scan({k})</a></b><br>"
        html += "</td></tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_digest_section(digests):
    # Data
    ######################################################################
    html = f"""
        <h2 id="digests-section" style="text-align: center;">Digests</h2>
        <hr>
        <h3 id="digests-data-section">Data</h3>
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
        html += "<td>{}</td><td>{}</td>".format(key,value)
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += f"""
        <h3 id="digests-investigation-section">Investigation</h3>
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
        html += "<td>{}</td><td>".format(index)
        for k,v in values.items():
            html += f"<b><a href='{v}'>{k} scan</a></b><br>"
        html += "</td></tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_table_from_json(json_obj):
    # Parse JSON object
    data = json_obj["Analysis"]

    # Generate HTML table with Bootstrap classes
    html = f"""
        <head>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/css/bootstrap.min.css">
        </head>

        <nav class="navbar navbar-expand-lg navbar-light bg-light">
            <a class="navbar-brand" href="#">Email Analyzer</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarSupportedContent">
                <ul class="navbar-nav mr-auto">
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Headers
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                    <a class="dropdown-item" href="#headers-data-section">Data <span class="badge badge-pill badge-dark">{len(data["Headers"]["Data"])}</span></a>
                    <a class="dropdown-item" href="#headers-investigation-section">Investigation <span class="badge badge-pill badge-dark">{len(data["Headers"]["Investigation"])}</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Links
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                    <a class="dropdown-item" href="#links-data-section">Data <span class="badge badge-pill badge-dark">{len(data["Links"]["Data"])}</span></a>
                    <a class="dropdown-item" href="#links-investigation-section">Investigation <span class="badge badge-pill badge-dark">{len(data["Links"]["Investigation"])}</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Attachments
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                    <a class="dropdown-item" href="#attachments-data-section">Data <span class="badge badge-pill badge-dark">{len(data["Attachments"]["Data"])}</span></a>
                    <a class="dropdown-item" href="#attachments-investigation-section">Investigation <span class="badge badge-pill badge-dark">{len(data["Attachments"]["Investigation"])}</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Digests
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                    <a class="dropdown-item" href="#digests-data-section">Data <span class="badge badge-pill badge-dark">{len(data["Digests"]["Data"])}</span></a>
                    <a class="dropdown-item" href="#digests-investigation-section">Investigation <span class="badge badge-pill badge-dark">{len(data["Digests"]["Investigation"])}</span></a>
                    </div>
                </li>
                </ul>
            </div>
        </nav>

        <div class="container-fluid">
        """
    

    html += generate_headers_section(data["Headers"])
    html += generate_links_section(data["Links"])
    html += generate_attachment_section(data["Attachments"])
    html += generate_digest_section(data["Digests"])
    
    
    html += """
        </div>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/js/bootstrap.min.js"></script>
    """
    
    return html
