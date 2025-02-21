from common import *


def getSummary(top_metrics, graph_data, combined_graph_data, sample_data, attack_data, top_n_attack_ids):
    """Takes raw data and outputs an english description of what occurred"""
    #Incident description
    #   Multiple attacks were detected on site _____
    #   Attack IP destinations:
    #       <date1> - <targeted ips>
    #       <date2> - <targeted ips>
    #   Attack timeframe: 
    #       <date1> between <Start Time> and <End Time>
    #       <date1> between <Start Time2> and <End Time2>
    #       <date2> between <Start Time> and <End Time>
    #   Attack Volume: Gbps/PPS/CPS
    #       Max attack rate:
    #           ~<Total Bandwidth>/<rate per second> started at <start time>, ended at <end time> on <Date> - <Attack type>
    #           ~<Total Bandwidth>/<rate per second> started at <start time>, ended at <end time> on <Date> - <Attack type>
    #   Attack Vectors:
    #       <date> - <List of Attack Names>
    #   Impact?:
    #
    #Summary
    #   Radware CyberController Plus has detected and successfully/partially mitigated the multi-vector attack 
    #   Radware successfully mitigated x out y of the total attack volume or 60% of the attack volume(be careful with this)
    #   There was/was not impact during the incident
    #   The impact happened due to…

    first_attack_start = None
    last_attack_end = None
    vectors = {}
    for topkey in ['top_by_bps', 'top_by_pps']:
        for attack in top_metrics[topkey]:
            if attack[1]['Policy'] != 'Packet Anomalies':
                start_time = datetime.datetime.strptime(attack[1]["Start Time"], '%d-%m-%Y %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
                end_time = datetime.datetime.strptime(attack[1]["End Time"], '%d-%m-%Y %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
                first_attack_start = min(first_attack_start, start_time) if first_attack_start else start_time
                last_attack_end = max(last_attack_end, end_time) if last_attack_end else end_time
            attack_name = attack[1]["Attack Name"]
            if vectors.get(attack_name, None) is None:
                vectors[attack_name] = {}
            vectors[attack_name]['gbps'] = vectors[attack_name].get('gbps',0) + attack[1]['Max_Attack_Rate_Gbps']
            vectors[attack_name]['highest_gbps'] = max(vectors[attack_name].get('highest_gbps',0), attack[1]['Max_Attack_Rate_Gbps'])
            
    sorted_vectors = sorted(vectors.items(), key=lambda x: x[1]['highest_gbps'], reverse=True)

    if first_attack_start is not None and last_attack_end is not None:
        elapsed_time = last_attack_end - first_attack_start
        elapsed_days = elapsed_time.days
        elapsed_hours = elapsed_time.seconds // 3600
        elapsed_minutes = (elapsed_time.seconds % 3600) // 60
        elapsed_seconds = elapsed_time.seconds % 60
        elapsed_parts = []
        if elapsed_days > 0:
            elapsed_parts.append(f"{elapsed_days} day{'s' if elapsed_days > 1 else ''}")
        if elapsed_hours > 0:
            elapsed_parts.append(f"{elapsed_hours} hour{'s' if elapsed_hours > 1 else ''}")
        if elapsed_minutes > 0:
            elapsed_parts.append(f"{elapsed_minutes} minute{'s' if elapsed_minutes > 1 else ''}")
        if elapsed_seconds > 0:
            elapsed_parts.append(f"{elapsed_seconds} second{'s' if elapsed_seconds > 1 else ''}")
        elapsed_time = ", ".join(elapsed_parts)

        #Identify attack segments with a minimum gap of x minutes
        waves = []
        for topkey in ['top_by_bps', 'top_by_pps']:
            for attack in top_metrics[topkey]:
                if attack[1]['Policy'] != 'Packet Anomalies':
                    start_time = datetime.datetime.strptime(attack[1]["Start Time"], '%d-%m-%Y %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
                    end_time = datetime.datetime.strptime(attack[1]["End Time"], '%d-%m-%Y %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
                    for wave in waves:
                        if start_time <= wave['end'] and end_time >= wave['start']:
                            # Merge overlapping event into the wave segment
                            wave['start'] = min(wave['start'], start_time)
                            wave['end'] = max(wave['end'], end_time)
                            if not attack in wave['attacks']:
                                wave['attacks'].append(attack)
                            break
                    else:
                        waves.append({'start': start_time, 'end': end_time, 'attacks': [attack]})
        #Merge overlapping waves
        minimum_minutes_between_waves = int(config.get("General","minimum_minutes_between_waves","5")) # Max allowed gap in minutes between waves to merge
        merged_waves = []
        for wave in sorted(waves, key=lambda x: x['start']):  # Sort by start time
            if not merged_waves:
                merged_waves.append(wave)
            else:
                last_wave = merged_waves[-1]
                # Check if the gap between waves is less than max_segment_gap_minutes
                gap = (wave['start'] - last_wave['end']).total_seconds() / 60 
                if gap <= minimum_minutes_between_waves:
                    last_wave['start'] = min(last_wave['start'], wave['start'])
                    last_wave['end'] = max(last_wave['end'], wave['end'])
                    last_wave['attacks'].extend(wave['attacks'])
                else:
                    merged_waves.append(wave)
        waves = merged_waves

        peak_traffic = highest_aggregate_15_seconds(combined_graph_data)
        if graph_data['bps']['dataMap']['maxValue']:
            peak_traffic['bps_time'] = int(graph_data['bps']['dataMap']['maxValue']['timeStamp'])
            peak_traffic['pps_time'] = int(graph_data['pps']['dataMap']['maxValue']['timeStamp'])
            peak_traffic['bps'] = "{:,}".format(int(float(graph_data['bps']['dataMap']['maxValue']['trafficValue'])))
            peak_traffic['pps'] = "{:,}".format(int(float(graph_data['pps']['dataMap']['maxValue']['trafficValue'])))
        else:
            peak_traffic['bps_time'] = 0
            peak_traffic['pps_time'] = 0
            peak_traffic['bps'] = 0
            peak_traffic['pps'] = 0
        
        #peak_traffic = {
        #    'bps': "{:,}".format(int(float(graph_data['bps']['dataMap']['maxValue']['trafficValue']))),
        #    'bps_time': int(graph_data['bps']['dataMap']['maxValue']['timeStamp']),
        #    'pps': "{:,}".format(int(float(graph_data['pps']['dataMap']['maxValue']['trafficValue']))),
        #    'pps_time': int(graph_data['pps']['dataMap']['maxValue']['timeStamp']),
        #    }
        
        attacked_destinations = set()
        attack_sources = set()
        destination_ports = set()
        for sample in sample_data:
            attack_sources.add(sample['sourceAddress'])
            attacked_destinations.add(sample['destAddress'])
            destination_ports.add(sample['destPort'])
        
        attack_sources = list(attack_sources)
        attacked_destinations = list(attacked_destinations)
        destination_ports = list(destination_ports)

        attack_sources.sort(key=lambda ip: tuple(map(int, ip.split('.'))))
        attacked_destinations.sort(key=lambda ip: tuple(map(int, ip.split('.'))))
        destination_ports.sort(key=int)

        included_attacks = 0
        total_attacks = 0
        included_bw = 0
        total_bw = 0
        included_packets = 0
        total_packets = 0
        protocols_bw = {}
        protocols_packets = {}
        for dp,data in attack_data.items():
            for attack in data['data']:
                if attack['row']['attackIpsId'] in top_n_attack_ids:
                    included_attacks += 1
                    included_bw += int(attack['row'].get('packetBandwidth', 0))
                    included_packets += int(attack['row'].get('packetCount', 0))
                    protocols_bw[attack['row'].get('protocol',"N/A")] = int(attack['row'].get('packetBandwidth', 0)) + int(protocols_bw.get(attack['row'].get('protocol',"N/A"),0))
                    protocols_packets[attack['row'].get('protocol',"N/A")] = int(attack['row'].get('packetCount', 0)) + int(protocols_packets.get(attack['row'].get('protocol',"N/A"),0))
                    #protocols_packets[attack['row'].get('protocol',"N/A")] += int(attack['row'].get('packetCount', 0))
                total_attacks += 1
                total_bw += int(attack['row'].get('packetBandwidth', 0))
                total_packets += int(attack['row'].get('packetCount', 0))

        output = f"""
    <div style="line-height: 1.5; text-align: center;">
        <table style="width: 80%; margin: 0 auto; border-collapse: collapse; padding: 8px;">
            <!-- Attack timeframe -->
            <tr style="border: none;">
                <td style="border: none; text-align: right;"><strong>Attack Timeframe:</strong></td>
                <td style="border: none; text-align: left;">Top {topN} attacks were observed over a <strong>{elapsed_time}</strong> time period from <strong>{first_attack_start.strftime('%d-%m-%Y %H:%M:%S %Z')}</strong> to <strong>{last_attack_end.strftime('%d-%m-%Y %H:%M:%S %Z')}</strong></td>
            </tr>"""

        if len(waves) > 1:
            output += f"""
            <tr style="border: none;">
                <td style="border: none; text-align: right;"><strong>Attack Waves:</strong></td>
                <td style="border: none; text-align: left;">The attacks can be broken into <strong>{len(waves)} non-overlapping attack waves</strong> separated by at least <strong>{minimum_minutes_between_waves} minutes</strong>.
            """
            
            for wave in waves:
                output += f"""<br><strong>{wave['start'].strftime('%d-%m-%Y %H:%M:%S %Z')}</strong> to <strong>{wave['end'].strftime('%d-%m-%Y %H:%M:%S %Z')}</strong> - <strong>{len(wave['attacks'])} attacks</strong>"""
            output += """
                </td>
            </tr>"""

        output += f"""

            <!-- Attack Vectors -->
            <tr style="border: none;">
                <td style="border: none; text-align: right;"><strong>Attack Vectors:</strong></td>
                <td style="border: none; text-align: left;">
                    The following attack vectors were observed, ranked by the peak bandwidth of the largest attack for each type:<br>
                    {", ".join(
                        f"<strong>{attack[0]}</strong> ({round(attack[1]['highest_gbps'], 2):g} Gbps)"
                        for attack in sorted_vectors
                    )}
                </td>
            </tr>

            <!-- Peak Attack Rate -->
            <tr style="border: none;">
                <td style="border: none; text-align: right;"><strong>Peak Attack Rate:</strong></td>
                <td style="border: none; text-align: left;">
                    <strong>Throughput</strong> peaked at <strong>{peak_traffic['bps']} kbps</strong> at <strong>{datetime.datetime.fromtimestamp(peak_traffic['bps_time']/1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S %Z')}</strong><br>
                    <strong>Packets per second (PPS)</strong> peaked at <strong>{peak_traffic['pps']} pps</strong> at <strong>{datetime.datetime.fromtimestamp(peak_traffic['pps_time']/1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S %Z')}</strong>
                </td>
            </tr>

            <!-- Attacked Destinations -->
            <tr style="border: none;">
                <td style="border: none; text-align: right;"><strong>Attacked Destinations:</strong></td>
                <td style="border: none; text-align: left;">
                    Attacks were identified against <strong>{len(attacked_destinations)} destination IP address{'es' if len(attacked_destinations) != 1 else ''}</strong> and <strong>{len(destination_ports)} destination port{'s' if len(destination_ports) != 1 else ''}.</strong><br>
                    Target IPs: {", ".join(attacked_destinations)}<br>
                    Target Ports: {", ".join(destination_ports)}
                </td>
            </tr>

            <!-- Attack Sources -->
            <tr style="border: none;">
                <td style="border: none; text-align: right;"><strong>Attack Sources:</strong></td>
                <td style="border: none; text-align: left;">
                    Sampled data includes attacks from <strong>at least {len(attack_sources)} unique source IP addresses</strong><br>
                    <!--{", ".join(attack_sources)}-->
                </td>
            </tr>"""
        try:
            output += f"""

            <!-- Attack Protocols -->
            <tr style="border: none;">
                <td style="border: none; text-align: right;"><strong>Attack Protocols:</strong></td>
                <td style="border: none; text-align: left;">
                    By bandwidth: {", ".join([f"{key}({value / included_bw * 100:.2f}%)" for key, value in protocols_bw.items()])} <br>
                    By packet count: {", ".join([f"{key}({value / included_packets * 100:.2f}%)" for key, value in protocols_packets.items()])} <br>
                </td>
            </tr>

            <!-- TopN Analysis -->
            <tr style="border: none;">
                <td style="border: none; text-align: right;"><strong>TopN Coverage:</strong></td>
                <td style="border: none; text-align: left;">
                This report focuses on the largest attacks observed within the specified time period, filtered by the Top {topN} BPS and PPS tables.<br>
            """
            if (total_attacks - included_attacks) > 0:
                output += f"""
                        It includes the <strong>{included_attacks} largest attack{'s' if total_attacks > 1 else ''}</strong> out of the <strong>{total_attacks} observed attack{'s' if total_attacks > 1 else ''}</strong>, based on the Top {topN} BPS and Top {topN} PPS rankings.<br>
                        The{'se' if included_attacks > 1 else ''} <strong>{included_attacks} attack{'s' if included_attacks != 1 else ''}</strong> represent{'s' if included_attacks == 1 else ''} <strong>{included_bw / total_bw:.2%}</strong> of the total attack bandwidth and <strong>{included_packets / total_packets:.2%}</strong> of the total attack packet count.<br>
                        The remaining <strong>{total_attacks - included_attacks} excluded attack{'s' if (total_attacks - included_attacks) != 1 else ''}</strong> represent{'s' if (total_attacks - included_attacks) == 1 else ''} <strong>{(total_bw - included_bw) / total_bw:.2%}</strong> of the observed attack bandwidth and <strong>{(total_packets - included_packets) / total_packets:.2%}</strong> of the observed attack packets.
                        """
            else:
                output += f"All observed attacks are included in this report. <strong>No attacks were excluded.</strong>"
            output += f"""
                </td>
            </tr>"""
        except:
            update_log(f"Divide by zero condition avoided. Presenting alternate date in report. total_bw: {total_bw} total_packets: {total_packets} included_bw: {included_bw} included_packets: {included_packets}")
            output += f"""
            <!-- Very low traffic alternate data -->
            <tr style="border: none;">
                <td style="border: none; text-align: right;"><strong>Statistics:</strong></td>
                <td style="border: none; text-align: left;">
                    Total bandwidth: {total_bw}<br>
                    Total packets: {total_packets}<br>
                    Included bandwidth: {included_bw}<br>
                    Included packets: {included_packets}
                </td>
            </tr>"""

        output += f"""
        </table>
    </div>
    """
    else:
        #First_Attack_Start is none, no attacks identified
        output = f"""
    <div style="line-height: 1.5; text-align: center;">
        <table style="width: 80%; margin: 0 auto; border-collapse: collapse;">
            <!-- No Attacks Identified -->
            <tr style="border: none;">
                <td style="border: none; text-align: right;"><strong>Attacks Identified:</strong></td>
                <td style="border: none; text-align: left;"><strong>No</strong> attacks were identified over the specified time period.</td>
            </tr>
        </table>
    </div>
    """
    return output



def highest_aggregate_15_seconds(myData):
    """This function finds the peak 15-second pps and bps time periods in 'combined graphs' data.
    It is currently unused."""
    # Function to round timestamp to the nearest 15 seconds
    def round_to_nearest_15_seconds(timestamp):
        return round(timestamp / 15000) * 15000

    # Dictionary to store aggregated values for each 15-second window
    aggregated_data = {}
    max_pps = 0
    max_bps = 0
    max_pps_time = None
    max_bps_time = None

    for dataset in myData.values():
        for item in dataset["data"]:
            timestamp = item["row"]["timeStamp"]
            rounded_time = round_to_nearest_15_seconds(timestamp)

            # Initialize the aggregated values for this time period if not already present
            if rounded_time not in aggregated_data:
                aggregated_data[rounded_time] = {'Pps': 0, 'Bps': 0}

            # Aggregate "Pps" and "Bps" values for each rounded timestamp
            if "Pps" in item["row"]:
                aggregated_data[rounded_time]['Pps'] += float(item["row"]["Pps"])
            if "Bps" in item["row"]:
                aggregated_data[rounded_time]['Bps'] += float(item["row"]["Bps"])

    # Find the highest aggregate for both "Pps" and "Bps" and track their timestamps
    for timestamp, values in aggregated_data.items():
        if values['Pps'] > max_pps:
            max_pps = values['Pps']
            max_pps_time = timestamp
        if values['Bps'] > max_bps:
            max_bps = values['Bps']
            max_bps_time = timestamp

    return {
        "pps": "{:,}".format(int(max_pps)),
        "bps": "{:,}".format(int(max_bps)),
        "pps_time": max_pps_time,
        "bps_time": max_bps_time
    }