import html_ip_reputation
from common import *

def generate_sample_data_section(title, sample_data):
    # Generate a sample data table (used for both BPS and PPS)
    html_content = f"<h2>{title}</h2><table border='1' cellpadding='5' cellspacing='0'>"
    html_content += """
        <tr>
            <th>Attack ID</th>
            <th>Source Address</th>
            <th>Source Port</th>
            <th>Destination Address</th>
            <th>Destination Port</th>
        </tr>
    """
    if sample_data:
        for entry in sample_data:
            for attack_id, samples in entry.items():
                for sample in samples:
                    html_content += f"""
                    <tr>
                        <td>{attack_id}</td>
                        <td>{sample.get('sourceAddress', 'N/A')}</td>
                        <td>{sample.get('sourcePort', 'N/A')}</td>
                        <td>{sample.get('destAddress', 'N/A')}</td>
                        <td>{sample.get('destPort', 'N/A')}</td>
                    </tr>
                    """
    else:
        html_content += """
        <tr>
            <td colspan="5">No sample data available</td>
        </tr>
        """

    html_content += "</table>"
    return html_content

def generate_html_report(top_by_bps, top_by_pps, unique_protocols, count_above_threshold, bps_data, pps_data, unique_ips_bps, unique_ips_pps, deduplicated_sample_data, top_n=10, threshold_gbps=0.02):
    # Generate HTML content for the report
    reputation_html_content = ""
    html_content = f"""
        <script>
            function toggleContent(id) {{
                var content = document.getElementById(id);
                if (content.style.display === "table-row") {{
                    content.style.display = "none";
                }} else {{
                    content.style.display = "table-row";
                }}
            }}

            function copyColumnData(className) {{
                var text = "";
                var elements = document.getElementsByClassName(className);
                for (var i = 0; i < elements.length; i++) {{
                    text += elements[i].innerText + "\\n";
                }}
                navigator.clipboard.writeText(text).then(function() {{
                    alert("Copied to clipboard");
                }}, function(err) {{
                    alert("Failed to copy");
                }});
            }}
        </script>
        <h2>Attack Report - Top {top_n} Sorted by Max Attack Rate (BPS)</h2>
        <p>Attack Vectors for the top {top_n} attacks: {', '.join(unique_protocols)}</p>
        <p>Out of the top {top_n} attacks, {count_above_threshold} attacks were greater than {threshold_gbps} Gbps.</p>
        <table>
            <tr>
                <th>Start Time</th>
                <th>End Time</th>
                <th>Attack ID</th>
                <th>Device Info</th>
                <th>Policy</th>
                <th>Attack Category</th>
                <th>Attack Name</th>
                <th>Graph</th>
                <th>Protocol</th>
                <th>Action</th>
                <th>Attack Status</th>
                <th>Max Attack Rate (Gbps)</th>
                <th>Max Attack Rate (PPS)</th>
                <th>Resources</th>
            </tr>
    """

    # Add top_by_bps data
    for syslog_id, details in top_by_bps:
        bdos_lifecycle_log_id = syslog_id
        final_fp = details.get('Final Footprint', 'N/A')
        metrics_summary = details.get('metrics_summary', 'N/A')
        metrics_summary = f"BDOS Lifecycle Log ID: {bdos_lifecycle_log_id}\n\n{metrics_summary}\n\n Final Attack Footprint: {final_fp}"
        state_6_footprints = details.get('state_6_footprints', 'N/A')
        formatted_state_6_footprints = "<br>".join(state_6_footprints.split('\n'))
        formatted_metrics_summary_bps = "<br>".join(metrics_summary.split('\n'))

        # Safely convert Max_Attack_Rate_BPS to float
        max_attack_rate_bps_str = details.get('Max_Attack_Rate_BPS', '0')
        try:
            max_attack_rate_bps = float(max_attack_rate_bps_str)
        except (ValueError, TypeError):
            max_attack_rate_bps = 0.0

        row_class = ''

        graph_name = f"graph_{(details.get('Attack Name', 'N/A') + '_' + details.get('Attack ID', 'N/A')).replace(' ','_').replace('-','_')}"
        # Main row
        if config.get("Reputation", "use_abuseipdb", False) or config.get("Reputation", "use_ipqualityscore", False):
            reputation_button_html = f"""<button type="button" class="collapsible" onclick="document.getElementById('reputation_{details.get('Attack ID', 'N/A')}_popup').style.display = 'flex';document.getElementById('reputation_{details.get('Attack ID', 'N/A')}_overlay').style.display = 'block';"" style="flex: 1;">Reputation</button>"""
        else:
            reputation_button_html = ''
        html_content += f"""
            <tr>
                <td>{details.get('Start Time', 'N/A')}</td>
                <td>{details.get('End Time', 'N/A')}</td>
                <td>{details.get('Attack ID', 'N/A')}</td>
                <!-- <td>{syslog_id}</td> -->
                <td>{details.get('Device IP', 'N/A')}<br>{details.get('Device Name', 'N/A')}</td>
                <td>{details.get('Policy', 'N/A')}</td>
                <td>{details.get('Attack Category', 'N/A')}</td>
                <td>{details.get('Attack Name', 'N/A')}</td>
                <!-- <td>{details.get('Threat Group', 'N/A')}</td> -->
                <td><div id="{graph_name}-bpsmini" style="width: 100%; height: 100%;"></div></td>
                <td>{details.get('Protocol', 'N/A')}</td>
                <td>{details.get('Action', 'N/A')}</td>
                <td>{details.get('Attack Status', 'N/A')}</td>
                <td>{details.get('Max_Attack_Rate_Gbps', 'N/A')}</td>
                <td>{details.get('Max_Attack_Rate_PPS_formatted', 'N/A')}</td>
                <!-- <td>{details.get('Final Footprint', 'N/A')}</td> -->
                <td>
                    <button type="button" class="collapsible" onclick="toggleContent('bdos_lifecycle_pps_{syslog_id}')" style="white-space: nowrap;">BDOS Life Cycle</button>
                    <button type="button" class="collapsible" onclick="toggleContent('tr_bps_{graph_name}');drawChart_{graph_name}();">Graph</button>
                    <div style="display: flex; gap: 4px;">
                        <button type="button" class="collapsible" onclick="toggleContent('bps_{details.get('Attack ID', 'N/A')}')" style="flex: 1;">Sample Data</button>
                        {reputation_button_html}
                    </div>
                </td>
            </tr>
        """
        # Collapsible row for graph (initially hidden)
        html_content += f"""
        <tr id="bdos_lifecycle_bps_{syslog_id}" style="display:none;">
            <td colspan="17">
                <table>
                    <tr>
                        <th>BDOS Metric Summary {syslog_id}</th>
                    </tr>
                    <tr>
                        <td>{formatted_metrics_summary_bps if metrics_summary != 'N/A' else 'No BDOS lifecycle data available'}</td>
                    </tr>
                    <tr>
                        <th>State 6 Footprints {syslog_id}</th>
                    </tr>                    
                    <tr>
                        <td>{formatted_state_6_footprints if metrics_summary != 'N/A' else 'No BDOS lifecycle data available'}</td>
                    </tr>
                </table>
            </td>
        </tr>
        """
        html_content += f"""
            <tr id="tr_bps_{graph_name}" style="display:none;">
                <td colspan="17">
                    <div id="{graph_name}-top_n_bps" style="width: 100%; height: 500px;"></div>
                </td>
            </tr>
        """
        # Collapsible row for sample data (initially hidden)
        html_content += f"""
            <tr id="bps_{details.get('Attack ID', 'N/A')}" style="display:none;">
                <td colspan="17">
                    <table>
                        <tr>
                            <th>Source Address <button class="copy-button" onclick="copyColumnData('bps-source-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Source Port <button class="copy-button" onclick="copyColumnData('bps-source-port-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Destination Address <button class="copy-button" onclick="copyColumnData('bps-dest-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Destination Port <button class="copy-button" onclick="copyColumnData('bps-dest-port-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                        </tr>
        """
        # Check if there are sample data
        sample_found = False
        for entry in bps_data:
            for attack_id, samples in entry.items():
                if attack_id == details.get('Attack ID', 'N/A'):
                    if samples:  # If samples exist
                        sample_found = True
                        for sample in samples:
                            html_content += f"""
                            <tr>
                                <td class="bps-source-{details.get('Attack ID', 'N/A')}">{sample.get('sourceAddress', 'N/A')}</td>
                                <td class="bps-source-port-{details.get('Attack ID', 'N/A')}">{sample.get('sourcePort', 'N/A')}</td>
                                <td class="bps-dest-{details.get('Attack ID', 'N/A')}">{sample.get('destAddress', 'N/A')}</td>
                                <td class="bps-dest-port-{details.get('Attack ID', 'N/A')}">{sample.get('destPort', 'N/A')}</td>
                            </tr>
                            """
                        #IP Reputation Popup
                        #if config.get("Reputation", "use_abuseipdb", False) or config.get("Reputation", "use_ipqualityscore", False):
                        if not f"reputation_{details.get('Attack ID', 'N/A')}_" in reputation_html_content:
                            ip_data = {}
                            for sample in samples:
                                result = html_ip_reputation.ip_lookup.get_ip_abuse_data(sample['sourceAddress'])
                                ip_data[sample['sourceAddress']] = result
                            reputation_html_content += html_ip_reputation.generate_html_table(ip_data, f"reputation_{details.get('Attack ID', 'N/A')}")

        if not sample_found:
            html_content += """
                            <tr>
                                <td colspan="4">No sample data available</td>
                            </tr>
            """
        html_content += "</table></td></tr>"

    # Close the attack report table for BPS
    html_content += "</table>"

    # Add PPS report header (similar structure with copy functionality)
    html_content += f"<h2>Attack Report - Top {top_n} Sorted by Max Attack Rate (PPS)</h2>"
    html_content += "<table>"
    html_content += """
            <tr>
                <th>Start Time</th>
                <th>End Time</th>
                <th>Attack ID</th>
                <th>Device Info</th>
                <th>Policy</th>
                <th>Attack Category</th>
                <th>Attack Name</th>
                <th>Graph</th>
                <th>Protocol</th>
                <th>Action</th>
                <th>Attack Status</th>
                <th>Max Attack Rate (Gbps)</th>
                <th>Max Attack Rate (PPS)</th>
                <th>Resources</th>
            </tr>
    """

    # Add top_by_pps data
    for syslog_id, details in top_by_pps:
        bdos_lifecycle_log_id = syslog_id
        final_fp = details.get('Final Footprint', 'N/A')
        metrics_summary = details.get('metrics_summary', 'N/A')
        if isinstance(metrics_summary, str) and f"BDOS Lifecycle Log ID: {bdos_lifecycle_log_id}" not in metrics_summary:
            metrics_summary = f"BDOS Lifecycle Log ID: {bdos_lifecycle_log_id}\n\n{metrics_summary}"
        metrics_summary = f"{metrics_summary}\n\n Final Attack Footprint: {final_fp}"
        formatted_metrics_summary_pps = "<br>".join(metrics_summary.split('\n'))
        state_6_footprints = details.get('state_6_footprints', 'N/A')
        formatted_state_6_footprints = "<br>".join(state_6_footprints.split('\n'))



        # Safely convert Max_Attack_Rate_PPS to float
        max_attack_rate_pps_str = details.get('Max_Attack_Rate_PPS', '0')
        try:
            max_attack_rate_pps = float(max_attack_rate_pps_str)
        except (ValueError, TypeError):
            max_attack_rate_pps = 0.0

        row_class = ''
        graph_name = f"graph_{(details.get('Attack Name', 'N/A') + '_' + details.get('Attack ID', 'N/A')).replace(' ','_').replace('-','_')}"
        
        if config.get("Reputation", "use_abuseipdb", False) or config.get("Reputation", "use_ipqualityscore", False):
            reputation_button_html = f"""<button type="button" class="collapsible" onclick="document.getElementById('reputation_{details.get('Attack ID', 'N/A')}_popup').style.display = 'flex';document.getElementById('reputation_{details.get('Attack ID', 'N/A')}_overlay').style.display = 'block';"" style="flex: 1;">Reputation</button>"""
        else:
            reputation_button_html = ''
        # Main row
        html_content += f"""
            <tr class="{row_class}">
                <td>{details.get('Start Time', 'N/A')}</td>
                <td>{details.get('End Time', 'N/A')}</td>
                <td>{details.get('Attack ID', 'N/A')}</td>
                <!-- <td>{syslog_id}</td> -->
                <td>{details.get('Device IP', 'N/A')}<br>{details.get('Device Name', 'N/A')}</td>
                <td>{details.get('Policy', 'N/A')}</td>
                <td>{details.get('Attack Category', 'N/A')}</td>
                <td>{details.get('Attack Name', 'N/A')}</td>
                <!-- <td>{details.get('Threat Group', 'N/A')}</td> -->
                <td><div id="{graph_name}-ppsmini"></div></td>
                <td>{details.get('Protocol', 'N/A')}</td>
                <td>{details.get('Action', 'N/A')}</td>
                <td>{details.get('Attack Status', 'N/A')}</td>
                <td>{details.get('Max_Attack_Rate_Gbps', 'N/A')}</td>
                <td>{details.get('Max_Attack_Rate_PPS_formatted', 'N/A')}</td>
                <!-- <td>{details.get('Final Footprint', 'N/A')}</td> -->
                <td>
                    <button type="button" class="collapsible" onclick="toggleContent('bdos_lifecycle_pps_{syslog_id}')" style="white-space: nowrap;">BDOS Life Cycle</button>
                    <button type="button" class="collapsible" onclick="toggleContent('tr_pps_{graph_name}');drawChart_{graph_name}();">Graph</button>
                    <div style="display: flex; gap: 4px;">
                        <button type="button" class="collapsible" onclick="toggleContent('pps_{details.get('Attack ID', 'N/A')}')" style="flex: 1;">Sample Data</button>
                        {reputation_button_html}
                    </div>
                    
                </td>
            </tr>
        """
        html_content += f"""
        <tr id="bdos_lifecycle_pps_{syslog_id}" style="display:none;">
            <td colspan="17">
                <table>
                    <tr>
                        <th>BDOS Metric Summary {syslog_id}</th>
                    </tr>
                    <tr>
                        <td>{formatted_metrics_summary_pps if metrics_summary != 'N/A' else 'No BDOS lifecycle data available'}</td>
                    </tr>
                    <tr>
                        <th>State 6 Footprints {syslog_id}</th>
                    </tr>
                    <tr>
                        <td>{formatted_state_6_footprints if metrics_summary != 'N/A' else 'No Footprints available'}</td>
                    </tr>
                </table>
            </td>
        </tr>
        """
        # Collapsible row for graph
        html_content += f"""
            <tr id="tr_pps_{graph_name}" style="display:none;">
                <td></td>
                <td colspan="17">
                    <div id="{graph_name}-top_n_pps" style="width: 100%; height: 500px;"></div>
                </td>
            </tr>
        """
        # Collapsible row for sample data (initially hidden)
        html_content += f"""
            <tr id="pps_{details.get('Attack ID', 'N/A')}" style="display:none;">
                <td colspan="17">
                    <table>
                        <tr>
                            <th>Source Address <button class="copy-button" onclick="copyColumnData('pps-source-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Source Port <button class="copy-button" onclick="copyColumnData('pps-source-port-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Destination Address <button class="copy-button" onclick="copyColumnData('pps-dest-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Destination Port <button class="copy-button" onclick="copyColumnData('pps-dest-port-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                        </tr>
        """
        # Check if there are sample data
        sample_found = False
        for entry in pps_data:
            for attack_id, samples in entry.items():
                if attack_id == details.get('Attack ID', 'N/A'):
                    if samples:  # If samples exist
                        sample_found = True
                        for sample in samples:
                            html_content += f"""
                            <tr>
                                <td class="pps-source-{details.get('Attack ID', 'N/A')}">{sample.get('sourceAddress', 'N/A')}</td>
                                <td class="pps-source-port-{details.get('Attack ID', 'N/A')}">{sample.get('sourcePort', 'N/A')}</td>
                                <td class="pps-dest-{details.get('Attack ID', 'N/A')}">{sample.get('destAddress', 'N/A')}</td>
                                <td class="pps-dest-port-{details.get('Attack ID', 'N/A')}">{sample.get('destPort', 'N/A')}</td>
                            </tr>
                            """
                        #IP Reputation Popup
                        if config.get("Reputation", "use_abuseipdb", False) or config.get("Reputation", "use_ipqualityscore", False):
                            if not f"reputation_{details.get('Attack ID', 'N/A')}_" in reputation_html_content:
                                ip_data = {}
                                for sample in samples:
                                    result = html_ip_reputation.ip_lookup.get_ip_abuse_data(sample['sourceAddress'])
                                    ip_data[sample['sourceAddress']] = result
                                reputation_html_content += html_ip_reputation.generate_html_table(ip_data, f"reputation_{details.get('Attack ID', 'N/A')}")

        if not sample_found:
            html_content += """
                            <tr>
                                <td colspan="4">No sample data available</td>
                            </tr>
            """

        html_content += "</table></td></tr>"

    # Close the attack report table for PPS
    html_content += "</table>"
    
    unique_ips_bps = [ip.strip() for ip in unique_ips_bps]
    unique_ips_pps = [ip.strip() for ip in unique_ips_pps]
    combined_unique_ips = list(set(unique_ips_bps + unique_ips_pps))

    # Generate HTML content for combined unique IPs as a table
    html_content += """
    Unique Sample data and Source IP functions: 
    <button id="toggleButton1" onclick="toggleTable()">Show Source IP Table</button>
    <button id="toggleButton2" onclick="toggleCombinedSamples()">Show Aggregated Sample Data</button>
    <button onclick="document.getElementById('reputation_all_popup').style.display = 'flex';document.getElementById('reputation_all_overlay').style.display = 'block';">
        Show Aggregated Sample Data IP Abuse Database info
    </button>
    <!-- Parent container for the two tables -->
    <div style="display: flex; gap: 20px;">
        <!-- Source IP Table -->
        <div id="ipTableContainer" style="display: none;">
            <table id="sourceIpTable" border="1" style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr>
                        <th style="height: 30px;">Unique Source IPs
                            <button onclick="copyColumn('sourceIpTable', 0)">Copy</button>
                        </th>
                    </tr>
                </thead>
                <tbody>
    """

    # Populate the table with the combined unique IPs
    for ip in combined_unique_ips:
        html_content += f"""
        <tr style="height: 30px;">
            <td>{ip}</td>
        </tr>
        """

    html_content += """
                </tbody>
            </table>
        </div>

        <!-- Combined Unique Samples Table -->
        <div id="combinedSampleContainer" style="display: none;">
            <table id="combinedSampleTable" border="1" style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr>
                        <th style="height: 30px;">Source Address
                            <button onclick="copyColumn('combinedSampleTable', 0)">Copy</button>
                        </th>
                        <th style="height: 30px;">Source Port
                            <button onclick="copyColumn('combinedSampleTable', 1)">Copy</button>
                        </th>
                        <th style="height: 30px;">Destination Address
                            <button onclick="copyColumn('combinedSampleTable', 2)">Copy</button>
                        </th>
                        <th style="height: 30px;">Destination Port
                            <button onclick="copyColumn('combinedSampleTable', 3)">Copy</button>
                        </th>
                    </tr>
                </thead>
                <tbody>
    """

    # Populate the combined unique samples table
    for sample in deduplicated_sample_data:
        html_content += f"""
        <tr style="height: 30px;">
            <td>{sample['sourceAddress']}</td>
            <td>{sample['sourcePort']}</td>
            <td>{sample['destAddress']}</td>
            <td>{sample['destPort']}</td>
        </tr>
        """

    html_content += """
                </tbody>
            </table>
        </div>
    </div>

    <script>
    function copyColumn(tableId, columnIndex) {
        var columnData = "";
        var table = document.getElementById(tableId);
        for (var i = 1; i < table.rows.length; i++) { // Start from 1 to skip header row
            columnData += table.rows[i].cells[columnIndex].innerText + '\\n';
        }
        // Ensure there is column data before copying
        if (columnData.trim() === "") {
            alert("No data to copy in this column.");
            return;
        }
        
        navigator.clipboard.writeText(columnData).then(function() {
            alert('Column data copied to clipboard!');
        }, function(err) {
            alert('Failed to copy: ', err);
        });
    }

    function toggleTable() {
        var tableContainer = document.getElementById("ipTableContainer");
        var toggleButton = document.getElementById("toggleButton1");
        
        if (tableContainer.style.display === "block") {
            tableContainer.style.display = "none";
            toggleButton.innerText = "Show Source IP Table";
        } else {
            tableContainer.style.display = "block";
            toggleButton.innerText = "Hide Source IP Table";
        }
    }

    function toggleCombinedSamples() {
        var combinedSampleContainer = document.getElementById("combinedSampleContainer");
        var toggleButton = document.getElementById("toggleButton2");

        if (combinedSampleContainer.style.display === "block") {
            combinedSampleContainer.style.display = "none";
            toggleButton.innerText = "Show Aggregated Sample Data";
        } else {
            combinedSampleContainer.style.display = "block";
            toggleButton.innerText = "Hide Aggregated Sample Data";
        }
    }
    </script>
    """

    return html_content + reputation_html_content



def get_top_n(syslog_details, top_n=10, threshold_gbps=0.02):
    threshold_bps = threshold_gbps * 1e9

    # Sort by Max_Attack_Rate_BPS and Max_Attack_Rate_PPS
    sorted_by_bps = sorted(
        syslog_details.items(),
        key=lambda item: float(item[1].get('Max_Attack_Rate_BPS', '0').replace(' ', '')),
        reverse=True
    )

    sorted_by_pps = sorted(
        syslog_details.items(),
        key=lambda item: float(item[1].get('Max_Attack_Rate_PPS', '0').replace(' ', '')),
        reverse=True
    )

    # Get top N from both sorted lists
    top_by_bps = sorted_by_bps[:top_n]
    top_by_pps = sorted_by_pps[:top_n]

    # Count how many top BPS exceed the threshold
    count_above_threshold = sum(
        1 for syslog_id, details in top_by_bps
        if float(details.get('Max_Attack_Rate_BPS', '0').replace(' ', '')) > threshold_bps
    )

    # Collect unique protocols from top_by_bps
    unique_protocols = list({details.get('Protocol', 'N/A') for syslog_id, details in top_by_bps})

    return top_by_bps, top_by_pps, unique_protocols, count_above_threshold
