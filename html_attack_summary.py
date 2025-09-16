from common import *

def timeline(waves: List[Dict[str, Any]], start_epoch: Optional[float] = None,  end_epoch: Optional[float] = None) -> str:
    # Tuning
    CONDENSE_THRESHOLD_FRAC = 0.12      # condense outer gap if ≥ 12% of window
    CONDENSE_ABS_SECONDS    = 8 * 3600 # ...or if ≥ 8 hours
    CONDENSE_WIDTH_PCT      = 8.0       # visual width (%) of each condensed edge
    MIN_WAVE_HIT_WIDTH_PX   = 2         # min wave width (px) for hover targeting

    TRACK_GRAY = "#e5e7eb"
    WAVE_RED   = "#ef4444"

    def _to_naive_utc(d: datetime.datetime) -> datetime.datetime:
        return d.astimezone(datetime.timezone.utc).replace(tzinfo=None) if d.tzinfo else d

    def _esc(s: str) -> str:
        return (s.replace("&", "&amp;")
                 .replace('"', "&quot;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;"))

    # Normalize waves -> naive UTC
    usable = []
    for w in (waves or []):
        s, e = w.get("start"), w.get("end")
        if not isinstance(s, datetime.datetime) or not isinstance(e, datetime.datetime):
            continue
        s = _to_naive_utc(s); e = _to_naive_utc(e)
        if e < s: s, e = e, s
        attack_count = len(w.get("attacks") or [])
        usable.append((s, e, attack_count))

    style = f"""
<style>
.attack-timeline{{position:relative; --tl-surface:#fff;}}
.attack-timeline .track{{position:relative;height:20px;background:{TRACK_GRAY};border-radius:10px;overflow:visible}}
.attack-timeline .seg{{position:absolute;height:100%}}

/* tooltips */
.attack-timeline .seg.wave::after{{
  content:attr(data-l1) '\\A' attr(data-l2);
  white-space:pre; position:absolute; left:50%; bottom:calc(100% + 6px); transform:translateX(-50%);
  font-size:12px; font-weight:600; padding:4px 8px; border-radius:6px; background:rgba(0,0,0,.75);
  color:#fff; pointer-events:none; opacity:0; transition:opacity .12s;
}}
.attack-timeline .seg.gap::after,
.attack-timeline .seg.compress::after{{
  content:attr(data-l1);
  white-space:pre; position:absolute; left:50%; bottom:calc(100% + 6px); transform:translateX(-50%);
  font-size:12px; font-weight:600; padding:4px 8px; border-radius:6px; background:rgba(0,0,0,.75);
  color:#fff; pointer-events:none; opacity:0; transition:opacity .12s;
}}
.attack-timeline .seg:hover::after{{opacity:1}}

/* waves */
.attack-timeline .seg.wave{{
  z-index:2; background:{WAVE_RED}; box-shadow:inset 0 0 0 1px rgba(255,255,255,.35);
  border:none; border-radius:0; min-width:{MIN_WAVE_HIT_WIDTH_PX}px;
}}

/* mid gaps: invisible, hover-only */
.attack-timeline .seg.gap{{z-index:1; background:transparent; border:none; border-radius:0; min-width:2px;}}

/* condensed edge (same gray as track) */
.attack-timeline .seg.compress{{
  z-index:1; background:{TRACK_GRAY}; border:0; border-radius:0; position:absolute;
}}
.attack-timeline .seg.compress.left-edge{{border-top-left-radius:10px; border-bottom-left-radius:10px;}}
.attack-timeline .seg.compress.right-edge{{border-top-right-radius:10px; border-bottom-right-radius:10px;}}

/* centered white PARALLELOGRAM (45° sides) + tight three dots */
.attack-timeline .seg.compress .cutout{{
  position:absolute; top:0px; bottom:0px; left:50%;
  width:clamp(24px, 60%, 36px);
  transform:translateX(-50%) skewX(-45deg); /* 45° parallelogram */
  background:var(--tl-surface);
  border-radius:3px;
  /* box-shadow:0 0 0 1px rgba(0,0,0,0.06) inset, 0 1px 2px rgba(0,0,0,0.08); */
  pointer-events:none;
}}
.attack-timeline .seg.compress .dots{{
  position:absolute; left:50%; top:50%; transform:translate(-50%,-50%);
  font-size:12px; line-height:1; color:#6b7280; letter-spacing:1px; pointer-events:none;
  /* three bullets with no extra spaces between them */
  content:"";
}}
/* use a pseudo-element for the dots' text to keep it tight across browsers */
.attack-timeline .seg.compress .dots::before{{
  content:"\\2022\\2022\\2022"; /* ••• */
}}
</style>
""".strip()

    if not usable:
        return f'{style}<div class="attack-timeline"><div class="track"></div></div>'

    # Overall window (epochs ms → naive UTC)
    start_dt = (datetime.datetime.utcfromtimestamp(start_epoch / 1000.0).replace(tzinfo=None)
                if (start_epoch not in (None, "")) else None)
    end_dt   = (datetime.datetime.utcfromtimestamp(end_epoch / 1000.0).replace(tzinfo=None)
                if (end_epoch   not in (None, "")) else None)
    min_start = min(s for s, _, _ in usable)
    max_end   = max(e for _, e, _ in usable)
    overall_start = start_dt or min_start
    overall_end   = end_dt   or max_end
    if overall_end < overall_start:
        overall_start, overall_end = overall_end, overall_start
    total_seconds = max(1, int((overall_end - overall_start).total_seconds()))

    # Clamp & sort
    clamped = []
    for s, e, cnt in usable:
        ds, de = max(s, overall_start), min(e, overall_end)
        if de <= overall_start or ds >= overall_end:
            continue
        clamped.append((ds, de, cnt))
    clamped.sort(key=lambda x: x[0])

    # No waves in window -> single full condensed
    if not clamped:
        l1 = _esc(f"No Attacks: {friendly_duration(overall_start, overall_end)} (condensed)")
        seg = (
            '<div class="seg compress left-edge right-edge" '
            f'data-l1="{l1}" style="left:0.000000%;width:100.000000%;">'
            '<div class="cutout"></div><div class="dots"></div>'
            '</div>'
        )
        return f'{style}<div class="attack-timeline"><div class="track">{seg}</div></div>'

    # Merge overlaps; sum attack counts
    merged, counts = [], []
    for s, e, cnt in clamped:
        if not merged:
            merged.append([s, e]); counts.append(cnt)
        else:
            ls, le = merged[-1]
            if s <= le:
                if e > le: merged[-1][1] = e
                counts[-1] += cnt
            else:
                merged.append([s, e]); counts.append(cnt)

    first_wave_start = merged[0][0]
    last_wave_end    = merged[-1][1]
    left_gap_sec  = max(0, int((first_wave_start - overall_start).total_seconds()))
    right_gap_sec = max(0, int((overall_end - last_wave_end).total_seconds()))

    def _should_condense(gap_sec: int) -> bool:
        return (gap_sec >= CONDENSE_ABS_SECONDS) or ((gap_sec / total_seconds) >= CONDENSE_THRESHOLD_FRAC if total_seconds else False)

    condense_left  = _should_condense(left_gap_sec)  and left_gap_sec  > 0
    condense_right = _should_condense(right_gap_sec) and right_gap_sec > 0

    left_pad_pct  = CONDENSE_WIDTH_PCT if condense_left  else (100.0 * left_gap_sec  / total_seconds)
    right_pad_pct = CONDENSE_WIDTH_PCT if condense_right else (100.0 * right_gap_sec / total_seconds)
    inner_pct     = max(1e-6, 100.0 - left_pad_pct - right_pad_pct)

    inner_start = first_wave_start if condense_left  else overall_start
    inner_end   = last_wave_end    if condense_right else overall_end
    inner_secs  = max(1, int((inner_end - inner_start).total_seconds()))

    def _map_left(t: datetime.datetime) -> float:
        return left_pad_pct + ((t - inner_start).total_seconds() / inner_secs) * inner_pct

    def _map_width(a: datetime.datetime, b: datetime.datetime) -> float:
        return max(0.0, ((b - a).total_seconds() / inner_secs) * inner_pct)

    parts = []

    # Left condensed edge (with parallelogram + tight dots)
    if condense_left and left_pad_pct > 0:
        l1 = _esc(f"No Attacks: {friendly_duration(overall_start, first_wave_start)} (condensed)")
        parts.append(
            '<div class="seg compress left-edge" '
            f'data-l1="{l1}" style="left:0.000000%;width:{left_pad_pct:.6f}%;">'
            '<div class="cutout"></div><div class="dots"></div>'
            '</div>'
        )

    # Middle gaps + waves
    cursor = inner_start
    for (ws, we), cnt in zip(merged, counts):
        if ws > cursor:
            gap_l = _map_left(cursor)
            gap_w = _map_width(cursor, ws)
            l1 = _esc(f"No Attacks: {friendly_duration(cursor, ws)}")
            parts.append(
                f'<div class="seg gap" data-l1="{l1}" '
                f'style="left:{gap_l:.6f}%;width:{gap_w:.6f}%;"></div>'
            )
        wave_l = _map_left(ws)
        wave_w = _map_width(ws, we)
        l1 = _esc(f"Attack Wave Duration: {friendly_duration(ws, we)}")
        l2 = _esc(f"{cnt} attack{'s' if cnt != 1 else ''}")
        parts.append(
            f'<div class="seg wave" data-l1="{l1}" data-l2="{l2}" '
            f'style="left:{wave_l:.6f}%;width:{wave_w:.6f}%;"></div>'
        )
        cursor = we

    # Right condensed edge (with parallelogram + tight dots) or regular trailing gap
    if condense_right and right_pad_pct > 0:
        l = 100.0 - right_pad_pct
        l1 = _esc(f"No Attacks: {friendly_duration(last_wave_end, overall_end)} (condensed)")
        parts.append(
            f'<div class="seg compress right-edge" data-l1="{l1}" '
            f'style="left:{l:.6f}%;width:{right_pad_pct:.6f}%;"><div class="cutout"></div><div class="dots"></div></div>'
        )
    else:
        if last_wave_end < inner_end:
            gap_l = _map_left(last_wave_end)
            gap_w = _map_width(last_wave_end, inner_end)
            l1 = _esc(f"No Attacks: {friendly_duration(last_wave_end, inner_end)}")
            parts.append(
                f'<div class="seg gap" data-l1="{l1}" '
                f'style="left:{gap_l:.6f}%;width:{gap_w:.6f}%;"></div>'
            )

    return f'{style}<div class="attack-timeline"><div class="track">{"".join(parts)}</div></div>'

def getSummary(top_metrics, graph_data, combined_graph_data, sample_data, attack_data, top_n_attack_ids, csv_data, report_timeframe) -> str:
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
            num = float(attack[1]['Max_Attack_Rate_Gbps']) if attack[1]['Max_Attack_Rate_Gbps'] != "N/A" else 0
            vectors[attack_name]['gbps'] = vectors[attack_name].get('gbps',0) + num
            vectors[attack_name]['highest_gbps'] = max(vectors[attack_name].get('highest_gbps',0), num)
            
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
        if len(graph_data) > 0 and graph_data['bps']['dataMap']['maxValue']:
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
        if sample_data != None:
            for sample in sample_data:
                attack_sources.add(sample['sourceAddress'])
                attacked_destinations.add(sample['destAddress'])
                destination_ports.add(sample['destPort'])
        else:
            attack_sources.add("0.0.0.0")
            attacked_destinations.add("0.0.0.0")
            destination_ports.add("0")

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
                <td style="border: none; text-align: right; vertical-align: top;"><strong>Attack Timeframe:</strong></td>
                <td style="border: none; text-align: left;">Top {topN} attacks were observed over a <strong>{elapsed_time}</strong> time period from <strong>{first_attack_start.strftime(output_time_format)}</strong> to <strong>{last_attack_end.strftime(output_time_format)}</strong></td>
            </tr>"""

        if len(waves) >= 1:
            output += f"""
            <tr style="border: none;">
                <td style="border: none; text-align: right; vertical-align: top;"><strong>Attack Waves:</strong></td>
                <td style="border: none; text-align: left;">The attacks can be broken into <strong>{len(waves)} non-overlapping attack waves</strong> separated by at least <strong>{minimum_minutes_between_waves} minutes</strong>.
            """
            
            for wave in waves:
                output += f"""<br><strong>{wave['start'].strftime(output_time_format)}</strong> to <strong>{wave['end'].strftime(output_time_format)}</strong> - <strong>{len(wave['attacks'])} attack{'s' if len(wave['attacks']) > 1 else ''}</strong> - <strong>Duration: {friendly_duration(wave['start'], wave['end'])}</strong>"""
            output += f"""
                    <!--  <br>The timeline below illustrates the timing of each attack wave relative to the overall attack timeframe. -->
                    <br>{timeline(waves, report_timeframe.get('start_epoch',None ), report_timeframe.get('end_epoch',None ))}
                </td>
            </tr>"""


        output += f"""

            <!-- Attack Vectors -->
            <tr style="border: none;">
                <td style="border: none; text-align: right; vertical-align: top;"><strong>Attack Vectors:</strong></td>
                <td style="border: none; text-align: left;">
                    The following attack vectors were observed, ranked by the peak bandwidth of the largest attack for each type:<br>
                    {", ".join(
                        f"<strong>{attack[0]}</strong> ({round(attack[1]['highest_gbps'], 2):g} Gbps)"
                        for attack in sorted_vectors
                    )}
                </td>
            </tr>
            """

        if int(str(peak_traffic['bps']).replace(',', '')) > 0:
            output += f"""
            <!-- Peak Traffic Rate -->
                <tr style="border: none;">
                    <td style="border: none; text-align: right; vertical-align: top;"><strong>Peak Traffic Rate:</strong></td>
                    <td style="border: none; text-align: left;">
                        <strong>Throughput</strong> peaked at <strong>{peak_traffic['bps']} kbps</strong> at <strong>{datetime.datetime.fromtimestamp(peak_traffic['bps_time']/1000, tz=datetime.timezone.utc).strftime(output_time_format)}</strong><br>
                        <strong>Packets per second (PPS)</strong> peaked at <strong>{peak_traffic['pps']} pps</strong> at <strong>{datetime.datetime.fromtimestamp(peak_traffic['pps_time']/1000, tz=datetime.timezone.utc).strftime(output_time_format)}</strong>
                    </td>
                </tr>
                """
        if not common_globals['Manual Mode']:
            #Not manual mode
            output += f"""
                <!-- Attacked Destinations -->
                <tr style="border: none;">
                    <td style="border: none; text-align: right; vertical-align: top;"><strong>Attacked Destinations:</strong></td>
                    <td style="border: none; text-align: left;">
                        Attacks were identified against <strong>{len(attacked_destinations)} destination IP address{'es' if len(attacked_destinations) != 1 else ''}</strong> and <strong>{len(destination_ports)} destination port{'s' if len(destination_ports) != 1 else ''}.</strong><br>
                        <strong>Target IPs:</strong> {", ".join(attacked_destinations)}<br>
                        <strong>Target Ports:</strong> {", ".join(destination_ports)}
                    </td>
                </tr>
                """
        else:
            #manual mode
            output += f"""
                <!-- Attacked Destinations -->
                <tr style="border: none;">
                    <td style="border: none; text-align: right; vertical-align: top;"><strong>Attacked Destinations:</strong></td>
                    <td style="border: none; text-align: left;">
                        <strong>Combined Top {topN} PPS & BPS attacks</strong><br>
                        <div style="margin-left: 2em;">
                          <strong>Target IPs:</strong> {"; ".join(f"{ip}{' (' + str(count) + ' times)' if int(count) > 1 else ''}" for ip, count in csv_data['topN']["Destination IP Address"].items())}<br>
                          <strong>Target Ports:</strong> {"; ".join(f"{port}{' (' + str(count) + ' times)' if int(count) > 1 else ''}" for port, count in csv_data['topN']["Destination Port"].items())}<br>
                        </div>
                        <details>
                          <summary><strong>All attacks </strong>(not restricted to top {topN}) - <strong>{len(csv_data['Destination IP Address'])} destination IP address{'es' if len(csv_data['Destination IP Address']) != 1 else ''}</strong> and <strong>{len(csv_data['Destination Port'])} destination port{'s' if len(csv_data['Destination Port']) != 1 else ''}</strong></summary>
                          <div style="margin-left: 2em;">
                            <!-- Attacks were identified against <strong>{len(csv_data['Destination IP Address'])} unique target IP address{'es' if len(csv_data['Destination IP Address']) != 1 else ''}</strong> and <strong>{len(csv_data['Destination Port'])} port{'s' if len(csv_data['Destination Port']) != 1 else ''}.</strong><br> -->
                            <div style="margin-left: 2em; max-height: 200px; overflow-y: auto; border: 1px solid #ccc; padding: 4px; display: inline-block;">
                                <table style="border-collapse: separate; border-spacing: 0; width: auto; margin: 0 auto;">
                                    <thead>
                                    <tr>
                                        <th colspan="2" style="text-align: center; padding: 4px 6px; position: sticky; top: -4; background: white; z-index: 3; box-shadow: inset 0 -1px #ccc;">Target IP Addresses</th>
                                    </tr>
                                    <tr>
                                        <th style="text-align: center; padding: 2px 6px; position: sticky; top: 24px; background: white; z-index: 2; box-shadow: inset 0 -1px #ccc;">Target IP</th>
                                        <th style="text-align: center; padding: 2px 6px; position: sticky; top: 24px; background: white; z-index: 2; box-shadow: inset 0 -1px #ccc;">Count</th>
                                    </tr>
                                    </thead>
                                    <tbody>
                                    {''.join(
                                        f"<tr><td style='padding: 2px 6px; text-align: center;'>{ip}</td><td style='padding: 2px 6px; text-align: center;'>{count}</td></tr>"
                                        for ip, count in csv_data["Destination IP Address"].items()
                                    )}
                                    </tbody>
                                </table>
                            </div>
                            <div style="margin-left: 2em; max-height: 200px; overflow-y: auto; border: 1px solid #ccc; padding: 4px; display: inline-block;">
                                <table style="border-collapse: separate; border-spacing: 0; width: auto; margin: 0 auto;">
                                    <thead>
                                    <tr>
                                        <th colspan="2" style="text-align: center; padding: 4px 6px; position: sticky; top: 0; background: white; z-index: 3; box-shadow: inset 0 -1px #ccc;">Target Ports</th>
                                    </tr>
                                    <tr>
                                        <th style="text-align: center; padding: 2px 6px; position: sticky; top: 28px; background: white; z-index: 2; box-shadow: inset 0 -1px #ccc;">Target Port</th>
                                        <th style="text-align: center; padding: 2px 6px; position: sticky; top: 28px; background: white; z-index: 2; box-shadow: inset 0 -1px #ccc;">Count</th>
                                    </tr>
                                    </thead>
                                    <tbody>
                                    {''.join(
                                        f"<tr><td style='padding: 2px 6px; text-align: center;'>{port}</td><td style='padding: 2px 6px; text-align: center;'>{count}</td></tr>"
                                        for port, count in csv_data["Destination Port"].items()
                                    )}
                                    </tbody>
                                </table>
                            </div>

                          </div>
                        </details>
                    </td>
                </tr>
                """
#Include '(1 time) for ips and ports
#                        <strong>Target IPs:</strong> {"; ".join(f"{ip} ({count} time{'s' if int(count) != 1 else ''})" for ip, count in csv_data["Destination IP Address"].items())}<br>
#                        <strong>Target Ports:</strong> {"; ".join(f"{port} ({count} time{'s' if int(count) != 1 else ''})" for port, count in csv_data["Destination Port"].items())}
        if attack_sources != ['0.0.0.0']:
            output += f"""
                <!-- Attack Sources -->
                <tr style="border: none;">
                    <td style="border: none; text-align: right; vertical-align: top;"><strong>Attack Sources:</strong></td>
                    <td style="border: none; text-align: left;">
                        Sampled data includes attacks from <strong>at least {len(attack_sources)} unique source IP addresses</strong><br>
                        <!--{", ".join(attack_sources)}-->
                    </td>
                </tr>
                """
        
        if not common_globals['Manual Mode']:
            output += f"""
            <!-- Attack Protocols -->
            <tr style="border: none;">
                <td style="border: none; text-align: right; vertical-align: top;"><strong>Attack Protocols:</strong></td>
                <td style="border: none; text-align: left;">
                    By bandwidth: {", ".join([f"<strong>{key}</strong> ({format(value / included_bw * 100, '.2f').rstrip('0').rstrip('.')}%, {friendly_bits(value)})" for key, value in protocols_bw.items()])} <br>
                    By packet count: {", ".join([f"<strong>{key}</strong> ({format(value / included_packets * 100, '.2f').rstrip('0').rstrip('.')}%, {value:,} packet{'s' if value >= 2 else ''})" for key, value in protocols_packets.items()])} <br>
                </td>
            </tr>
            """
        else:
            output += f"""
            <!-- Attack Protocols -->
            <tr style="border: none;">
                <td style="border: none; text-align: right; vertical-align: top;"><strong>Attack Protocols:</strong></td>
                <td style="border: none; text-align: left;">
                    <strong>Top {topN} Largest Attacks:</strong><br>
                    &nbsp;&nbsp;&nbsp;&nbsp;By bandwidth: {", ".join([f"<strong>{key}</strong> ({format(value / included_bw * 100, '.2f').rstrip('0').rstrip('.')}%, {friendly_bits(value)})" for key, value in protocols_bw.items()])} <br>
                    &nbsp;&nbsp;&nbsp;&nbsp;By packet count: {", ".join([f"<strong>{key}</strong> ({format(value / included_packets * 100, '.2f').rstrip('0').rstrip('.')}%, {value:,} packet{'s' if value >= 2 else ''})" for key, value in protocols_packets.items()])} <br>
                    <strong>All Attacks (not restricted to top {topN}):</strong><br>
                    &nbsp;&nbsp;&nbsp;&nbsp;By attack count:  {"; ".join(f"<strong>{protocol}</strong> ({format(value / total_attacks * 100, '.2f').rstrip('0').rstrip('.')}%, {format(value, ',')} attack{'s' if value >= 2 else ''})" for protocol, value in csv_data["Protocol"].items())}<br>
                    &nbsp;&nbsp;&nbsp;&nbsp;By bandwidth:  {"; ".join(f"<strong>{protocol}</strong> ({format(value / total_bw * 100, '.2f').rstrip('0').rstrip('.')}%, {friendly_bits(value)})" for protocol, value in csv_data["Protocol Kbits"].items())}<br>
                    &nbsp;&nbsp;&nbsp;&nbsp;By packet count:  {"; ".join(f"<strong>{protocol}</strong> ({format(value / total_packets * 100, '.2f').rstrip('0').rstrip('.')}%, {format(value, ',')} packet{'s' if value >= 2 else ''})" for protocol, value in csv_data["Protocol Packets"].items())}<br>
                </td>
            </tr>
            """
        try:
            output += f"""
            <!-- TopN Analysis -->
            <tr style="border: none;">
                <td style="border: none; text-align: right; vertical-align: top;"><strong>TopN Coverage:</strong></td>
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
                <td style="border: none; text-align: right; vertical-align: top;"><strong>Statistics:</strong></td>
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
                <td style="border: none; text-align: right; vertical-align: top;"><strong>Attacks Identified:</strong></td>
                <td style="border: none; text-align: left;"><strong>No attacks were identified</strong> over the specified time period.</td>
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