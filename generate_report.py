from datetime import datetime
import os
from jinja2 import Template


def generate_report(lnk_class):
    html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>LNK File Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: auto; }
        .header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }
        .section { background: white; padding: 20px; margin-bottom: 20px; border: 1px solid #ddd; }
        .danger { color: #e74c3c; }
        .warning { color: #f39c12; }
        .success { color: #27ae60; }
        .info { color: #2980b9; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
        th { background: #f5f5f5; }
        .risk-gauge { text-align: center; margin: 20px 0; }
        .extra-block { margin: 10px 0; padding: 10px; background: #f9f9f9; }
        .risk-level {
            text-align: center;
            font-size: 1.2em;
            font-weight: bold;
            margin: 20px 0;
            padding: 10px;
            border-radius: 4px;
        }
        .low-risk {
            color: #27ae60;
            background-color: #eafaf1;
        }
        .suspicious {
            color: #f39c12;
            background-color: #fef9e7;
        }
        .malicious {
            color: #c0392b;
            background-color: #fdedec;
        .item-block {
            margin: 10px 0;
            padding: 10px;
            background: #f8f9fa;
            border-left: 3px solid #3498db;
        }
        }
        .raw-data {
            margin: 15px 0;
        }
        .hex-view {
            margin: 10px 0;
        }
        .hex-data {
            font-family: monospace;
            font-size: 14px;
            background: #f8f9fa;
            padding: 10px;
            border: 1px solid #ddd;
            white-space: pre-wrap;
            word-break: break-all;
            max-width: 1000px;
            max-height: 200px;
            overflow-x: auto;
            overflow-y: scroll;
        }
        .parsed-data {
            background: #f8f9fa;
            padding: 10px;
            border: 1px solid #ddd;
            white-space: pre-wrap;
            word-break: break-all;
            max-width: 1000px;
            max-height: 200px;
            overflow-x: auto;
            overflow-y: scroll;
        }


    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>LNK File Analysis Report</h1>
            <p>Analysis Date: {{ datetime.now().strftime('%Y-%m-%d %H:%M:%S') }}, Made by TeamJowonReady</p>
        </div>

        <div class="section">
            <h2>File Information</h2>
            <table>
                <tr><th>File Path</th><td>{{ lnk_path }}</td></tr>
                <tr><th>File Size</th><td>{{ structure_info['ShellLinkInfo']['FileSize'] }} bytes</td></tr>
                <tr><th>MD5</th><td>{{ file_hashes['md5'] }}</td></tr>
                <tr><th>SHA1</th><td>{{ file_hashes['sha1'] }}</td></tr>
                <tr><th>SHA256</th><td>{{ file_hashes['sha256'] }}</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Risk Assessment</h2>
            <div class="risk-gauge">
                <img src="data:image/png;base64,{{ risk_gauge }}" alt="Risk Gauge">
            </div>
            <div class="risk-level {% if risk_score <= 3 %}low-risk{% elif risk_score <= 7 %}suspicious{% else %}malicious{% endif %}">
                Risk Level: 
                {% if risk_score <= 3 %}
                    <span class="low-risk">Low Risk ({{ risk_score }}/10)</span>
                {% elif risk_score <= 7 %}
                    <span class="suspicious">Suspicious ({{ risk_score }}/10)</span>
                {% else %}
                    <span class="malicious">Malicious ({{ risk_score }}/10)</span>
                {% endif %}
            </div>

            {% if malicious %}
            <div class="malicious">
                <h3>Malicious Indicators</h3>
                <ul>
                {% for item in malicious %}
                    <li class="danger">{{ item }}</li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}
            {% if suspicious %}
            <div class="suspicious">
                <h3>Suspicious Patterns</h3>
                <ul>
                {% for item in suspicious %}
                    <li class="warning">{{ item }}</li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}
        </div>

        <div class="section">
            <h2>Shell Link Header</h2>
            <div class="description">{{ structure_info['Header']['Description'] }}</div>
            <div class="size">Size: {{ structure_info['Header']['Size'] }} bytes</div>
            <table>
            {% for key, value in structure_info['Header']['Data'].items() %}
                <tr><th>{{ key }}</th><td>{{ value }}</td></tr>
            {% endfor %}
            </table>
        </div>

        <div class="section">
            <h2>Link Flags</h2>
            <table>
                <tr><th>Flag Name</th><th>Status</th><th>Description</th></tr>
                {% for name, (value, desc) in structure_info['Header']['Flags'].items() %}
                <tr>
                    <td>{{ name }}</td>
                    <td>{{ "Enabled" if value else "Disabled" }}</td>
                    <td>{{ desc }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <div class="section">
            <h2>Link Target ID List</h2>
            <div class="description">{{ structure_info['LinkTargetIDList']['Description'] }}</div>
            <div class="size">Size: {{ structure_info['LinkTargetIDList']['Size'] }} bytes</div>
            {% if structure_info['LinkTargetIDList']['ParsedData'] %}
            <div class="extra-block">
                <h3>Parsed ItemID List</h3>
                {% for item in structure_info['LinkTargetIDList']['ParsedData']['ItemIDList'] %}
                <div class="item-block">
                    <table>
                        <tr><th>Size</th><td>{{ item['Size'] }}</td></tr>
                        <tr><th>Type</th><td>{{ item['Parsed'] }}</td></tr>
                        <tr>
                            <th>Raw Data</th>
                            <td><pre class="hex-data">{{ item['Data'] }}</pre></td>
                        </tr>
                    </table>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            <div class="raw-data">
                <h3>Raw Data</h3>
                <pre class="hex-data">{{ structure_info['LinkTargetIDList']['Data'] }}</pre>
            </div>
        </div>

        <div class="section">
            <h2>Link Info</h2>
            <div class="description">{{ structure_info['LinkInfo']['Description'] }}</div>
            <div class="size">Size: {{ structure_info['LinkInfo']['Size'] }} bytes</div>
            {% if structure_info['LinkInfo']['ParsedData'] %}
            <div class="extra-block">
                <h3>Parsed Link Info</h3>
                <table>
                    {% for key, value in structure_info['LinkInfo']['ParsedData'].items() %}
                    <tr>
                        <th>{{ key }}</th>
                        <td>{{ value }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            {% endif %}
            <div class="raw-data">
                <h3>Raw Data</h3>
                <pre class="hex-data">{{ structure_info['LinkInfo']['Data'] }}</pre>
            </div>
        </div>

        <div class="section">
            <h2>String Data</h2>
            <div class="description">{{ structure_info['StringData']['Description'] }}</div>
            <div class="size">Size: {{ structure_info['StringData']['Size'] }} bytes</div>
            {% if structure_info['StringData']['Data'] %}
            {% for string_type, data in structure_info['StringData']['Data'].items() %}
            <div class="extra-block">
                <h3>{{ string_type }}</h3>
                <table>
                    <tr>
                        <th>Offset</th>
                        <td>{{ data.offset }}</td>
                    </tr>
                    <tr>
                        <th>Size Information</th>
                        <td>{{ data.size_hex }}</td>
                    </tr>
                    <tr>
                        <th>String Value</th>
                        <td>
                            <div class="hex-view">
                                <div class="parsed-data">{{data.value}}</div>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <th>Raw Hex</th>
                        <td>
                            <div class="hex-view">
                                <div class="hex-data">{{ data.raw_hex }}</div>
                            </div>
                        </td>
                    </tr>
                </table>
            </div>
            {% endfor %}
            {% else %}
            <p>No String Data found</p>
            {% endif %}
        </div>

        <div class="section">
            <h2>Extra Data Blocks</h2>
            <div class="description">{{ structure_info['ExtraData']['Description'] }}</div>
            <div class="size">Size: {{ structure_info['ExtraData']['Size'] }} bytes</div>
            {% if structure_info['ExtraData']['Data'] %}
            {% for block in structure_info['ExtraData']['Data'] %}
            <div class="extra-block">
                <h3>{{ block['name'] }}</h3>
                <table>
                    <tr>
                        <th>Offset</th>
                        <td>{{ block['offset'] }}</td>
                    </tr>
                    <tr>
                        <th>Size Information</th>
                        <td>{{ block['size_hex'] }}</td>
                    </tr>
                    <tr>
                        <th>Signature</th>
                        <td>{{ block['signature'] }} ({{ block['signature_hex'] }})</td>
                    </tr>
                    {% if block['expected_size'] %}
                    <tr>
                        <th>Expected Size</th>
                        <td>{{ block['expected_size'] }}</td>
                    </tr>
                    {% endif %}
                    {% if block['parsed_data'] %}
                    <tr>
                        <th>Parsed Data</th>
                        <td>
                            <pre class="parsed-data">{{ block['parsed_data'] | pprint }}</pre>
                        </td>
                    </tr>
                    {% endif %}
                    <tr>
                        <th>Raw Hex</th>
                        <td>
                            <div class="hex-view">
                                <div class="hex-data">{{ block['data_hex'] }}</div>
                            </div>
                        </td>
                    </tr>
                </table>
            </div>
            {% endfor %}
            {% else %}
            <p>No Extra Data Blocks found</p>
            {% endif %}
        </div>

        {% if vt_results and vt_results.get('found') %}
        <div class="section">
            <h2>VirusTotal Results</h2>
            <table>
                <tr><th>Detections</th><td>{{ vt_results['positives'] }}/{{ vt_results['total'] }}</td></tr>
                <tr><th>Scan Date</th><td>{{ vt_results['scan_date'] }}</td></tr>
                <tr><th>Report Link</th><td><a href="{{ vt_results['permalink'] }}" target="_blank">View Full Report</a></td></tr>
            </table>
        </div>
        {% endif %}
    </div>
</body>
</html>
        """
        
    template = Template(html_template)
    report_html = template.render(
        datetime=datetime,
        lnk_path=lnk_class.lnk_path,
        structure_info=lnk_class.structure_info,
        file_hashes=lnk_class.file_hashes,
        malicious=lnk_class.malicious,
        suspicious=lnk_class.suspicious,
        risk_gauge=lnk_class.generate_risk_gauge(),
        risk_score=lnk_class.risk_score,
        vt_results=lnk_class.vt_results
    )

    report_path = f"{os.path.splitext(lnk_class.lnk_path)[0]}_analysis_report.html"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_html)
        
    print(f"Analysis report saved to: {report_path}")