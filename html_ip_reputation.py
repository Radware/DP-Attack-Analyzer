import ip_lookup
import json
from common import *



def flatten_dict(d, parent_key="", sep="_"):
    """Recursively flattens a nested dictionary."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            items.append((new_key, ", ".join(map(str, v))))  # Convert list to string
        else:
            items.append((new_key, v))
    return dict(items)

def generate_html_table(ip_data, table_id="reputation_all"):
    # Extract column headers and their categories
    headers = set()
    flattened_data = {}
    column_categories = {"IP Address": "General"}
    
    use_abuseipdb = config.get("Reputation", "use_abuseipdb", False)
    use_ipqualityscore = config.get("Reputation", "use_ipqualityscore", False)
    
    for ip, details in ip_data.items():
        flattened_details = flatten_dict(details)
        flattened_data[ip] = flattened_details
        for key in flattened_details.keys():
            if key in reputation_included_columns:
                if (key.startswith("AbuseIPDB") and not use_abuseipdb) or (key.startswith("IPQualityScore") and not use_ipqualityscore):
                    continue
                headers.add(key)
                if key.startswith("AbuseIPDB"):
                    column_categories[key] = "AbuseIPDB"
                elif key.startswith("IPQualityScore"):
                    column_categories[key] = "IPQualityScore"
                else:
                    column_categories[key] = "Other"
    
    headers = sorted(headers)

    # Group headers
    header_groups = []
    last_category = None
    for header in ["IP Address"] + headers:
        category = column_categories.get(header, "Other")
        if header_groups and last_category == category:
            header_groups[-1]["count"] += 1
        else:
            header_groups.append({"category": category, "count": 1})
        last_category = category

    # Unique element IDs
    overlay_id = f"{table_id}_overlay"
    popup_id = f"{table_id}_popup"
    table_container_id = f"{table_id}_table_container"

    html = f"""
    <div id="{overlay_id}" onclick="document.getElementById('{popup_id}').style.display='none';this.style.display='none';"
        style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 999;"></div>
    <div id="{popup_id}" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
    background: white; width: 90%; max-height: 90%; padding: 20px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.5);
    z-index: 1000; border-radius: 10px; overflow: auto; flex-direction: column;">
        <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 10px; border-bottom: 1px solid #ccc;">
            <h3>IP Data Table</h3>
            <button onclick="document.getElementById('{popup_id}').style.display='none';document.getElementById('{overlay_id}').style.display='none';"
                style="cursor: pointer; font-size: 20px; font-weight: bold; background: none; border: none;">&times;</button>
        </div>
        <div id="{table_container_id}" style="max-width: 100%; flex-grow: 1; overflow-x: auto; overflow-y: auto;">
            <table style="border-collapse: collapse; width: 100%;">
                <tr>
    """

    for group in header_groups:
        html += f"<th colspan='{group['count']}' style='border: 1px solid black; padding: 5px; text-align: left;'>{group['category']}</th>"
    html += "</tr><tr>"

    html += "<th style='border: 1px solid black; padding: 5px; text-align: left;'>IP Address</th>"
    for header in headers:
        clean_header = header.replace("AbuseIPDB_", "").replace("IPQualityScore_", "")
        html += f"<th style='border: 1px solid black; padding: 5px; text-align: left;'>{clean_header}</th>"
    html += "</tr>"

    for ip, details in flattened_data.items():
        html += f"<tr><td style='border: 1px solid black; padding: 5px; text-align: left;'>{ip}</td>"
        for header in headers:
            html += f"<td style='border: 1px solid black; padding: 5px; text-align: left;'>{details.get(header, 'N/A')}</td>"
        html += "</tr>"

    html += """
            </table>
        </div>
    </div>
    """

    return html

def getIpReputationHTML(ip_sample_data):
    ip_data = {}
    for entry in ip_sample_data:
        result = ip_lookup.get_ip_abuse_data(entry['sourceAddress'], suppressErrors=True)
        ip_data[entry['sourceAddress']] = result

    #html_content = f"""<button onclick="document.getElementById('reputation_all_popup').style.display = 'flex';document.getElementById('reputation_all_overlay').style.display = 'block';">
    #    Show Aggregated Sample Data IP Abuse Database info
    #</button>"""
    html_content = generate_html_table(ip_data)

    #Create country attacker count pie chart
    countries = {}
    for ip, data in ip_data.items():
        country_code = data.get('AbuseIPDB', {}).get('countryCode') or \
            data.get('IPQualityScore', {}).get('country_code') or \
            "Unknown"
        countries[country_code] = countries.get(country_code, 0) + 1
    
    country_data = sorted(countries.items(), key=lambda x: x[1], reverse=True)
    chart_rows = ",\n                ".join([f"['{country}', {count}]" for country, count in country_data])
    chart_name = "reputationCountryChart"
    chart_title = "Attacker Country Distribution"

    html_content += f"""
        <script>
        google.charts.setOnLoadCallback(drawReputationPieChart);
        function drawReputationPieChart() {{
            var {chart_name}Data = google.visualization.arrayToDataTable([
                ['Country', 'Attack Count'],
                {chart_rows}
            ]);

            var options = {{
                title: '{chart_title}',
                is3D: true,
                pieSliceText: 'percentage',
                legend: 'right',
                slices: {{
                    0: {{offset: 0.1}},
                    1: {{offset: 0.05}},
                    2: {{offset: 0.05}}
                }}
            }};
            document.getElementById('{chart_name}').style="width: 40%; height: 500px; margin: 0; padding: 0;"
            var {chart_name} = new google.visualization.PieChart(document.getElementById('{chart_name}'));
            {chart_name}.draw({chart_name}Data, options);
            document.getElementById('{chart_name}').parentElement.style.height = '400px'
        }}
        </script>
        """
    html_content += generate_leaflet_map_html(ip_data)
    return html_content



def generate_leaflet_map_html(ip_data, map_div_id="attackerMap", map_height="500px"):
    if config.get('Reputation', 'use_ipqualityscore', False):
        coords = []
        for ip, data in ip_data.items():
            try:
                lat = float(data.get("IPQualityScore", {}).get("latitude"))
                lng = float(data.get("IPQualityScore", {}).get("longitude"))
                if -90 <= lat <= 90 and -180 <= lng <= 180:
                    coords.append({"lat": lat, "lng": lng, "label": ip})
            except (TypeError, ValueError):
                continue

        coords_json = json.dumps(coords)

        return f"""
    <h2>Attacker locations</h2>
    <div id="{map_div_id}" style="height: {map_height}; width: 100%; max-width: 800px; margin: auto; width: min(800px, 80%); border: 1px solid #ccc; position: relative; z-index: 0;"></div>

    <!-- Leaflet Dependencies -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

    <script>
    document.addEventListener("DOMContentLoaded", function() {{
        const map = L.map('{map_div_id}', {{
        zoomControl: false,  // Disable visible zoom buttons
        }}).setView([20, 0], 2);

        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
        attribution: '© OpenStreetMap contributors',
        maxZoom: 18
        }}).addTo(map);

        const attackerLocations = {coords_json};

        attackerLocations.forEach(({{
        lat, lng, label
        }}) => {{
        L.circleMarker([lat, lng], {{
            radius: 6,
            color: 'red',
            fillColor: 'red',
            fillOpacity: 0.8
        }}).addTo(map)
            .bindPopup(`<strong>${{label}}</strong>`);
        }});
    }});
    </script>
    """
    else:
        return f"""<h2>Attacker Location Map</h2>
        <div style="text-align: center;">ipqualityscore required.</div>
    """