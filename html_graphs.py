import json
import random
from datetime import datetime
import time
import math


def graphPrerequisites():
    #Workaround function to prevent google charts from auto-converting timezones to local time.
    outStr = """
<script type="text/javascript">
    function correctedDate(inputTime) {
    var date = new Date(inputTime);
    var timezoneOffset = date.getTimezoneOffset();
    var adjustedTime = new Date(inputTime + timezoneOffset * 60 * 1000);
    return adjustedTime;
    }
</script>
"""
    return outStr


def createTopGraphsHTML(BPSjson,PPSjson):
    
    def OptionsHTML(Title):
        output =  """
            var options = {
                title: '"""
        output += Title
        output +="""',
                curveType: 'function',
                width: '100%',
                legend: {
                    position: 'top',
                    textStyle: { fontSize: 12 },
                    maxLines: 6
                },
                annotations: { style: 'line'},
                displayAnnotations: true,
                focusTarget: 'category',
                vAxis: {
                    viewWindow: {min:0}
                },
                hAxis: {format: 'HH:mm:ss', slantedText:true, slantedTextAngle:45, title: 'Time (UTC)',},
                series: {
                    0: { labelInLegend: 'Challenged', color: "#ff8f00"},
                    1: { labelInLegend: 'Excluded', color: "#807be0"},
                    2: { labelInLegend: 'Received', color: "#088eb1"},
                    3: { labelInLegend: 'Dropped', color: "#f41414"},
                },
                tooltip: {
                    isHtml: true,
                    format: 'MMM d, y, HH:mm:ss'  // Ensure full date and time are shown in the tooltip
                },
                explorer: {
                    actions: ['dragToZoom', 'rightClickToReset'],
                    axis: 'horizontal',
                    keepInBounds: true,
                    maxZoomIn: 40.0
                }
            };"""
        return output
    outStr = """
    <script type="text/javascript">
      google.charts.load('current', {'packages':['corechart']});
      google.charts.setOnLoadCallback(drawBPSChart);
      function drawBPSChart() {
        var data = google.visualization.arrayToDataTable([
        [ { label: 'Time', type: 'datetime'}, { label: 'Challenged', type: 'number'}, { label: 'Excluded', type: 'number'}, { label: 'Received', type: 'number'}, { label: 'Dropped', type: 'number'}]"""
    for row in BPSjson['data']:
        #%d-%m-%Y 
        if row['row']['challengeIng'] and row['row']['excluded'] and row['row']['trafficValue'] and {row['row']['discards']}:
            outStr += f",\n        [correctedDate({row['row']['timeStamp']}), {row['row']['challengeIng']}, {row['row']['excluded']}, {row['row']['trafficValue']}, {row['row']['discards']}]"

    outStr += "]);"
    outStr += OptionsHTML("Full Time Range Max KBPS")
    outStr += """
        var chart = new google.visualization.AreaChart(document.getElementById('bpsChart'));

        chart.draw(data, options);
      }
      google.charts.setOnLoadCallback(drawPPSChart);
      function drawPPSChart() {
        var data = google.visualization.arrayToDataTable([
        [ { label: 'Time', type: 'datetime'}, { label: 'Challenged', type: 'number'}, { label: 'Excluded', type: 'number'}, { label: 'Received', type: 'number'}, { label: 'Dropped', type: 'number'}]"""
    for row in PPSjson['data']:
        #%d-%m-%Y 
        if row['row']['challengeIng'] and row['row']['excluded'] and row['row']['trafficValue'] and {row['row']['discards']}:
            outStr += f",\n        [correctedDate({row['row']['timeStamp']}), {row['row']['challengeIng']}, {row['row']['excluded']}, {row['row']['trafficValue']}, {row['row']['discards']}]"

    outStr += "]);"
    outStr += OptionsHTML("Full Time Range Max PPS (UTC)")
    outStr += """
        var chart = new google.visualization.AreaChart(document.getElementById('ppsChart'));

        chart.draw(data, options);
      }
    </script>

    <div id="bpsChart" style="width: 90%; height: 500px"></div>
    <div id="ppsChart" style="width: 90%; height: 500px"></div>
"""
    return outStr

#def createChart(Title, myData, epoch_from, epoch_to):
def createChart(Title, myData):
    """Creates a graph for an individual attack """
    name = f'graph_{Title.replace(" ","_").replace("-","_")}'

    # Sort the data by the timestamp
    sorted_data = sorted(myData["data"], key=lambda item: item["row"]["timeStamp"])

    # Extracting timestamps and formatting them as new Date objects in GMT
    timestamps = [int(item["row"]["timeStamp"]) for item in sorted_data]
    #labels = [f"new Date({ts} + (new Date().getTimezoneOffset() * 60000))" for ts in timestamps]
    labels = [f"correctedDate({ts})" for ts in timestamps]

    # Prepare the data for Google Charts
    data_table = [["Timestamp"] + [key for key in sorted_data[0]["row"].keys() if key != "timeStamp" and key != "footprint"]]
    for i, item in enumerate(sorted_data):
        row = [labels[i]]
        for key in data_table[0][1:]:
            value = item["row"].get(key)
            row.append(float(value) if value is not None else None)
        data_table.append(row)

    # Annotations for footprints
    annotations = []
    for idx, item in enumerate(sorted_data):
        if "footprint" in item["row"] and item["row"]["footprint"] is not None:
            annotations.append(f"{{x: {idx + 1}, shortText: 'F', text: 'Footprint detected', color: 'red'}}")

    # Convert data_table to JSON and replace the quotes around Date objects
    json_data = json.dumps(data_table)
    #json_data = json_data.replace('"new Date(', 'new Date(').replace(')"', ')')
    json_data = json_data.replace('"correctedDate(', 'correctedDate(').replace(')"', ')')

    # Generate HTML content dynamically
    html_content = f"""
    <script type="text/javascript">
        //google.charts.load('current', {{'packages':['corechart', 'annotationchart']}});
        google.charts.setOnLoadCallback(drawChart_{name});
        function drawChart_{name}() {{
            var data = google.visualization.arrayToDataTable({json_data});
            //var epoch_from = correctedDate({{epoch_from}});
            //var epoch_to = correctedDate({{epoch_to}});
            var options = {{
                title: '{Title}',
                curveType: 'function',
                legend: {{
                    position: 'top',
                    textStyle: {{ fontSize: 12 }},
                    maxLines: 6
                }},
                annotations: {{
                    style: 'line',
                    textStyle: {{
                        fontSize: 12,
                        bold: true,
                        color: 'red'
                    }},
                    stem: {{
                        color: 'red',
                        length: 8
                    }}
                }},
                alwaysOutside: true,
                displayAnnotations: true,
                focusTarget: 'category',
                vAxis: {{viewWindow: {{min:0}} }},
                hAxis: {{format: 'HH:mm:ss', slantedText:true, slantedTextAngle:45, title: 'Time (UTC)'}},
                series: {{
                    0: {{ color: '#ff8f00' }},
                    1: {{ color: '#807be0' }},
                    2: {{ color: '#088eb1' }},
                    3: {{ color: '#f41414' }},
                    4: {{ color: '#1c91c0' }},
                    5: {{ color: '#43459d' }},
                }}
            }};
            var miniOptions = {{
                title: null,
                width: 100,  
                height: 50, 
                chartArea: {{
                    left: 0,
                    top: 0,
                    width: '100%',
                    height: '100%'
                }},
                legend: {{ position: 'none' }}, // Hide the legend for the mini chart
                focusTarget: null,
                hAxis: {{ 
                    textPosition: 'none', 
                    gridlines: {{ count: 0 }}, 
                    ticks: []
                    //minValue: correctedDate({{epoch_from}}),
                    //maxValue: correctedDate({{epoch_to}})
                }}, // Hide x-axis text for compactness
                vAxis: {{ 
                    textPosition: 'none', 
                    gridlines: {{ count: 0 }}, 
                    ticks: [], 
                    viewWindow: {{min:0}} }}, // Hide y-axis text for compactness
            }};
            
            function drawChart(containerId, data, options) {{
                var container = document.getElementById(containerId);
                if (container !== null) {{
                    var chart = new google.visualization.LineChart(container);
                    chart.draw(data, options);
                }}
            }}

            // Draw the main chart
            drawChart('{name}-bottom', data, options);

            // Draw the top charts
            drawChart('{name}-top_n_pps', data, options);
            drawChart('{name}-top_n_bps', data, options);

            drawChart('{name}-bpsmini', data, {{ ...options, ...miniOptions }});
            drawChart('{name}-ppsmini', data, {{ ...options, ...miniOptions }});

            var chart_annotations = {json.dumps(annotations)};
            chart_annotations.forEach(function(annotation) {{
                chart.setAnnotation(annotation);
            }});
        }}
    </script>
    <div id="{name}-bottom" style="width: 100%; height: 500px; display: none;"></div>
    """
    return html_content


def createCombinedChart(Title, myData):
    """
    Build HTML+JS to create a Google Chart with PPS/BPS lines
    Combines multiple attacks into one.
    
    myData structure example:
      {
        "dataset1": {
          "data": [
            {"row": {"timeStamp": 1731526443458, "Bps": 4, "Pps": 0}},
            {"row": {"timeStamp": 1731526458458, "Bps": 10, "Pps": 2}},
            ...
          ],
          "metadata": {"dp_name": "DataPoint1", "other_info": "..." }
        },
        "dataset2": {
          "data": [...],
          "metadata": {...}
        },
        ...
      }
    """
    out_datasets = {}
    metadata_map = {}

    def pad_with_zeros(myData):
        """Make sure each line to be graphed starts and ends with 0.
        Adds 0s where necessary"""
        for key, dataset in myData.items():
            data = dataset.get("data", [])
            
            if len(data) > 1:  # Only process if more than one row exists
                # Ensure sorting by timestamp before processing
                sorted_data = sorted(data, key=lambda x: x["row"]["timeStamp"])
                
                # Check if the first row has Bps: 0 and Pps: 0 or time difference is too small
                first_row = sorted_data[0]["row"]
                second_row_time = sorted_data[1]["row"]["timeStamp"] if len(sorted_data) > 1 else None
                if first_row["Bps"] != 0 or first_row["Pps"] != 0 or (second_row_time and (second_row_time - first_row["timeStamp"] < 7500)):
                    # Create a new row with timestamp 15 seconds earlier
                    new_row = {
                        "row": {
                            "timeStamp": first_row["timeStamp"] - 15000,
                            "Bps": 0,
                            "Pps": 0
                        }
                    }
                    
                    # Insert at the beginning
                    sorted_data.insert(0, new_row)

                # Check if the last row has Bps: 0 and Pps: 0 or time difference is too small
                last_row = sorted_data[-1]["row"]
                second_to_last_time = sorted_data[-2]["row"]["timeStamp"] if len(sorted_data) > 1 else None
                if last_row["Bps"] != 0 or last_row["Pps"] != 0 or (second_to_last_time and (last_row["timeStamp"] - second_to_last_time < 7500)):
                    # Create a new row with timestamp 15 seconds later
                    new_row = {
                        "row": {
                            "timeStamp": last_row["timeStamp"] + 15000,
                            "Bps": 0,
                            "Pps": 0
                        }
                    }
                    
                    # Append at the end
                    sorted_data.append(new_row)
                
                # Update the dataset with sorted and modified data
                dataset["data"] = sorted_data
        
        return myData
    pad_with_zeros(myData)

    for dataset_name, dataset_data in myData.items():
        cur_dataset_pps = {}
        cur_dataset_bps = {}
        rows = dataset_data['data']
        metadata_map[dataset_name] = dataset_data.get('metadata', {})

        for row in rows:
            cur_row = row['row']
            timestamp = round(cur_row['timeStamp'] / 15000) * 15000  # Round to the nearest 15 seconds
            pps_value = cur_row['Pps']
            bps_value = cur_row['Bps']

            # Keep the higher value for duplicate timestamps
            if timestamp in cur_dataset_pps:
                cur_dataset_pps[timestamp] = max(cur_dataset_pps[timestamp], pps_value)
                cur_dataset_bps[timestamp] = max(cur_dataset_bps[timestamp], bps_value)
            else:
                cur_dataset_pps[timestamp] = pps_value
                cur_dataset_bps[timestamp] = bps_value

        # Convert the dictionaries to sorted lists
        sorted_dataset_pps = sorted(cur_dataset_pps.items())
        sorted_dataset_bps = sorted(cur_dataset_bps.items())
        
        out_datasets[f'{dataset_name}_pps'] = sorted_dataset_pps
        out_datasets[f'{dataset_name}_bps'] = sorted_dataset_bps
    
    metadata_map['Aggregate'] = {}

    sorted_keys = sorted(
        out_datasets.keys(),
        key=lambda k: out_datasets[k][0][0] if out_datasets[k] else float('inf')
    )

    out_datasets = {key: out_datasets[key] for key in sorted_keys}

    out_html = f"""
    <div id="checkboxes_{Title}"></div>
    <div id="chart_div_bps_{Title}" style="width: 100%; height: 500px;"></div>
    <div id="chart_div_pps_{Title}" style="width: 100%; height: 500px;"></div>

    <script type="text/javascript">
        (function() {{
            const datasets_{Title} = {json.dumps(out_datasets)};
            const metadataMap_{Title} = {json.dumps(metadata_map)};
            const checkboxContainer_{Title} = document.getElementById('checkboxes_{Title}');
            const filteredDataset_pps_{Title} = {{}};
            const filteredDataset_bps_{Title} = {{}};

            // Create checkboxes dynamically for each dataset pair (_pps and _bps)
            Object.keys(datasets_{Title}).forEach(function(datasetName) {{
                if (datasetName.endsWith('_pps')) {{
                    const baseName = datasetName.replace('_pps', ''); // Get the base dataset name
                    const label = document.createElement('label');
                    label.innerHTML = 
                        `<input type="checkbox" value="${{baseName}}" class="dataset-checkbox-{Title}"> ${{baseName}}`;
                    checkboxContainer_{Title}.appendChild(label);
                    checkboxContainer_{Title}.appendChild(document.createElement('br'));
                }}
            }});

            // Prepare data for Google Charts
            function prepareDataForGoogleCharts_{Title}(filteredDataset) {{
                const allTimestamps = new Set();
                console.log("3.1.1");
                Object.values(filteredDataset).forEach(dataset => {{
                    dataset.forEach(dataPoint => {{
                        allTimestamps.add(dataPoint[0]);
                    }});
                }});
                console.log("3.1.2");
                const sortedTimestamps = Array.from(allTimestamps).sort((a, b) => a - b);
                console.log("3.1.3");
                const dataArray = [];
                const datasetNames = Object.keys(filteredDataset);
                console.log("3.1.4");
                // Add headers, including a tooltip column for each dataset
                const headerRow = ['Timestamp'];
                datasetNames.forEach(name => {{
                    headerRow.push(name); // Data column
                    headerRow.push({{
                        type: 'string',
                        role: 'tooltip',
                        p: {{ html: true }}
                    }}); // Tooltip column
                }});
                dataArray.push(headerRow);
                console.log("3.1.5");
                // Populate rows with data and tooltips
                sortedTimestamps.forEach(timestamp => {{
                    const row = [new correctedDate(timestamp)];
                    datasetNames.forEach(datasetName => {{
                        const dataPoint = filteredDataset[datasetName].find(dp => dp[0] === timestamp);
                        const value = dataPoint ? dataPoint[1] : null;
                        row.push(value); // Data value
                        if (value !== null) {{
                            const metadata = metadataMap_{Title}[datasetName.replace('_pps', '').replace('_bps', '')];
                            row.push(`<div style="margin-left: 20px;"><strong>Value:</strong> ${{value.toLocaleString?.() || value}} <br>${{Object.entries(metadata).map(([key, value]) => `${{key}}: ${{value}}`).join('<br>')}}</div>`); // Tooltip
                            
                        }} else {{
                            row.push(null)
                        }}
                    }});
                    dataArray.push(row);
                }});
                return dataArray;
            }}


            // Update the Google Charts
            function updateChart_{Title}(type) {{
                let chartData, chart, chartDiv, legendTitle;
                if (type === 'pps') {{
                    legendTitle = "PPS";
                    console.log("3.1");
                    console.log(prepareDataForGoogleCharts_{Title});
                    console.log(filteredDataset_pps_{Title});
                    chartData = prepareDataForGoogleCharts_{Title}(filteredDataset_pps_{Title});
                    console.log("3.2");
                    chartDiv = document.getElementById('chart_div_pps_{Title}');
                    console.log("3.3");
                    chart = new google.visualization.LineChart(chartDiv);
                    console.log("3.4");
                }} else if (type === 'bps') {{
                    legendTitle = "KBPS";
                    chartData = prepareDataForGoogleCharts_{Title}(filteredDataset_bps_{Title});
                    chartDiv = document.getElementById('chart_div_bps_{Title}');
                    chart = new google.visualization.LineChart(chartDiv);
                }}
                const data = google.visualization.arrayToDataTable(chartData);
                const options = {{
                    title: legendTitle,
                    curveType: 'function',
                    legend: {{
                        position: 'top',
                        textStyle: {{ fontSize: 12 }},
                        maxLines: 6
                    }},
                    hAxis: {{
                        title: 'Time (UTC)',
                        format: 'HH:mm:ss',
                        slantedText: true,
                        slantedTextAngle: 45
                    }},
                    vAxis: {{
                        viewWindow: {{ min: 0 }}
                    }},
                    tooltip: {{
                        isHtml: true
                    }},
                    focusTarget: 'category',
                    interpolateNulls: true,
                    explorer: {{
                        actions: ['dragToZoom', 'rightClickToReset'],
                        axis: 'horizontal',
                        keepInBounds: true,
                        maxZoomIn: 40.0
                    }}
                }};
                chart.draw(data, options);
            }}

            function update_aggregate_data_{Title}(data) {{
                console.log("aggregating");
                if ("Aggregate" in data) {{
                    delete data["Aggregate"];
                    console.log("Existing Aggregate data removed.");
                }}
                let aggregated = {{}};

                for (let key in data) {{
                    data[key].forEach(entry => {{
                        let timestamp = entry[0];
                        let value = entry[1];

                        if (!aggregated[timestamp]) {{
                            aggregated[timestamp] = 0;
                        }}
                        
                        aggregated[timestamp] += value;
                    }});
                }}
                // Convert aggregated object to array format
                let aggregatedArray = Object.entries(aggregated).map(([timestamp, value]) => [Number(timestamp), value]);

                // Convert `data` into an array of entries and rebuild in order
                let entries = Object.entries(data);
                entries.unshift(["Aggregate", aggregatedArray]); // Append Aggregate last

                Object.keys(data).forEach(key => delete data[key]); // Clear the original object
                Object.assign(data, Object.fromEntries(entries)); // Rebuild with correct order
            }}

            // Load Google Charts and set up event listeners
            google.charts.load('current', {{ packages: ['corechart'] }});
            google.charts.setOnLoadCallback(() => {{
                document.querySelectorAll('.dataset-checkbox-{Title}').forEach(function(checkbox) {{
                    checkbox.addEventListener('change', function() {{
                        const baseName = checkbox.value;
                        if (checkbox.checked) {{
                            console.log("1");
                            filteredDataset_pps_{Title}[baseName + '_pps'] = datasets_{Title}[baseName + '_pps'];
                            update_aggregate_data_{Title}(filteredDataset_pps_{Title});
                            filteredDataset_bps_{Title}[baseName + '_bps'] = datasets_{Title}[baseName + '_bps'];
                            update_aggregate_data_{Title}(filteredDataset_bps_{Title});
                            console.log("2");
                        }} else {{
                            delete filteredDataset_pps_{Title}[baseName + '_pps'];
                            update_aggregate_data_{Title}(filteredDataset_pps_{Title});
                            delete filteredDataset_bps_{Title}[baseName + '_bps'];
                            update_aggregate_data_{Title}(filteredDataset_bps_{Title});
                        }}
                        console.log("3")
                        updateChart_{Title}('pps'); // Update PPS chart
                        console.log("4")
                        updateChart_{Title}('bps'); // Update BPS chart
                        console.log("5")
                    }});
                    checkbox.checked = true;
                    checkbox.dispatchEvent(new Event('change'));
                    console.log("6")
                }});
            }});
        }})();
    </script>
    """
    return out_html

def createPieCharts(attack_data, top_n_attack_ids):
    """Creates two 3D pie charts for total bandwidth and total packets, showing percentages on the chart and including a legend."""
    # Aggregate the totals from all attacks
    aggregate_data = {}
    for dp, data in attack_data.items():
        for attack in data['data']:
            if attack['row']['attackIpsId'] in top_n_attack_ids:
                name = attack['row']['name']
                total_bandwidth = attack['row'].get('packetBandwidth', 0)
                total_packets = attack['row'].get('packetCount', 0)
                existing_data = aggregate_data.get(name, {'total_bandwidth': 0, 'total_packets': 0})
                aggregate_data[name] = {
                    'total_bandwidth': int(existing_data['total_bandwidth']) + int(total_bandwidth),
                    'total_packets': int(existing_data['total_packets']) + int(total_packets)
                }

    # Prepare and sort the data for the charts
    sorted_items = sorted(aggregate_data.items(), key=lambda x: x[1]['total_bandwidth'], reverse=True)

    attack_names = [item[0] for item in sorted_items]
    total_bandwidth_values = [item[1]['total_bandwidth'] for item in sorted_items]
    total_packets_values = [item[1]['total_packets'] for item in sorted_items]

    # Calculate the sums for total bandwidth and total packets
    total_bandwidth_sum = sum(total_bandwidth_values)
    total_packets_sum = sum(total_packets_values)

    # Generate the JavaScript for drawing a 3D pie chart
    def create_pie_chart_js(chart_name, chart_data, title):
        return f"""
            var {chart_name}Data = google.visualization.arrayToDataTable([
                ['Attack Name', 'Value'],
                {', '.join([f"['{attack}', {chart_data[i]}]" for i, attack in enumerate(attack_names)])}
            ]);

            var {chart_name}Options = {{
                title: '{title}',
                is3D: true,  // Enable 3D chart
                pieSliceText: 'percentage',  // Show percentages on the chart
                legend: 'right',  // Include legend (key) on the right
                slices: {{
                    0: {{offset: 0}},  // Optional slight offset for callout effect
                    1: {{offset: 0}},
                    2: {{offset: 0}}
                }},
            }};

            var {chart_name} = new google.visualization.PieChart(document.getElementById('{chart_name}'));
            {chart_name}.draw({chart_name}Data, {chart_name}Options);
            document.getElementById('{chart_name}').style="width: 40%; height: 400px; margin: 0; padding: 0;"
        """

    # Titles with sums
    bandwidth_title = f"Cumulative Attack Bandwidth: {total_bandwidth_sum:,} kb"
    packets_title = f"Total Attack Packets: {total_packets_sum:,}"

    # Output HTML for Google Charts and the two pie charts side by side
    html_output = f"""
    <script>
        google.charts.setOnLoadCallback(drawPieCharts);
        function drawPieCharts() {{
            {create_pie_chart_js('bandwidthChart', total_bandwidth_values, bandwidth_title)}
            {create_pie_chart_js('packetsChart', total_packets_values, packets_title)}
        }}
    </script>

    <div style="display: flex; justify-content: center; mgap: 20px; margin: 0; padding: 0; height: 400px; overflow: hidden;">
        <div id="bandwidthChart" style="width: 40%; height: 500px; margin: 0; padding: 0;"></div>
        <div id="packetsChart" style="width: 40%; height: 500px; margin: 0; padding: 0;"></div>
    </div>
    <div style="display: flex; justify-content: center; margin: 0; padding: 0; overflow: hidden;">
        <div id="reputationCountryChart" style="margin: 0; padding: 0;"></div>
    </div>
    """
    
    return html_output

