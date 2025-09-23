#from datetime import datetime, timezone
import csv
import heapq
from itertools import tee, islice

#from common import temp_folder
#from common import topN
from common import *


#################### Helper functions ####################

MDY_FMT = "%m.%d.%Y %H:%M:%S"
DMY_FMT = "%d.%m.%Y %H:%M:%S"
def cache_and_identify_date_format(csv_text_stream, date_cols, default_fmt=MDY_FMT):
    """
    Cache a non-seekable CSV to a local temp file in temp_folder and detect date format
    Returns (fmt, cached_path).
    """
    delimiter=","

    def _decide_from_str(s: str):
        s = (s or "").strip()
        if not s:
            return None
        date_part = s.split(" ", 1)[0]
        parts = date_part.split(".")
        if len(parts) != 3:
            return None
        try:
            a, b, _ = (int(p) for p in parts)  # a=first, b=second
        except ValueError:
            return None
        if a > 12 and 1 <= b <= 12:
            return DMY_FMT
        if b > 12 and 1 <= a <= 12:
            return MDY_FMT
        return None  # ambiguous

    def _row_from_line(header, line, delimiter=","):
        """Parse a single CSV data line into a dict using the given header."""
        sio = io.StringIO("\n".join([delimiter.join(header), line]))
        r = csv.DictReader(sio, delimiter=delimiter)
        return next(r, None)

    def _decide_from_row_dict(row, date_cols):
        if not row:
            return None
        for c in date_cols:
            fmt = _decide_from_str(row.get(c))
            if fmt:
                return fmt
        return None

    cached_path = os.path.join(temp_folder, csv_text_stream.name)

    # Write stream to local temp file
    with open(cached_path, "w", encoding="utf-8", newline="") as tmp:
        first_line = csv_text_stream.readline()
        if not first_line:
            return default_fmt, cached_path
        tmp.write(first_line)
        header = next(csv.reader([first_line], delimiter=delimiter))

        first_data_line = None
        for line in csv_text_stream:
            tmp.write(line)
            if first_data_line is None and line.strip():
                first_data_line = line

    # --- Check FIRST row
    fmt = None
    if first_data_line:
        row = _row_from_line(header, first_data_line, delimiter)
        fmt = _decide_from_row_dict(row, date_cols)
        if fmt:
            return fmt, cached_path

    # --- Check LAST row
    with open(cached_path, "r", encoding="utf-8", newline="") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        back = min(65536, end)
        f.seek(end - back)
        tail = f.read()
    lines = [ln for ln in tail.splitlines() if ln.strip()]
    if lines:
        last_line = lines[-1]
        row = _row_from_line(header, last_line, delimiter)
        fmt = _decide_from_row_dict(row, date_cols)
        if fmt:
            return fmt, cached_path

    # 2) Second pass: scan EVERY row using DictReader until decisive
    with open(cached_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        for row in reader:
            fmt = _decide_from_row_dict(row, date_cols)
            if fmt:
                return fmt, cached_path

    return default_fmt, cached_path


def attackipsid_to_syslog_id(attackid):
    # Split the attackid into two parts
    first_part, second_part = attackid.split('-')
    # Format the second part by padding with zeros to make it 12 characters long
    second_part_formatted = second_part.zfill(12)
    # Reverse the first part to make it easier to split into chunks of 4 from the end
    first_part_reversed = first_part[::-1]
    chunks = [first_part_reversed[i:i+4][::-1] for i in range(0, len(first_part_reversed), 4)]
    # Combine chunks in the correct order with '-' separator
    first_part_formatted = '-'.join(chunks[::-1])
    # first part is 12 characters long (prepend zeros if necessary)
    first_part_formatted = first_part_formatted.zfill(12)
    # Construct the syslog_id by appending the formatted parts
    syslog_id = f"FFFFFFFF-{first_part_formatted}-{second_part_formatted}"
    
    return syslog_id


def attackipsid_to_syslog_id_hex(attackid):
    """ This function converts AttackIpsID to Syslog ID"""
    id_first_part_dec = int(attackid.split('-')[0])
    id_second_part_dec = int(attackid.split('-')[1])

    # Convert decimal to hex and remove the '0x' prefix
    id_first_part_hex = hex(id_first_part_dec)[2:]
    id_second_part_hex = hex(id_second_part_dec)[2:]

    # Pad the second part to ensure it is at least 8 characters
    if id_second_part_dec >= 16777216 and id_second_part_dec <= 268435455:
        id_second_part_hex = '0' + id_second_part_hex
    elif id_second_part_dec >= 1048576 and id_second_part_dec <= 16777215:
        id_second_part_hex = '00' + id_second_part_hex
    elif id_second_part_dec >= 65536 and id_second_part_dec <= 1048575:
        id_second_part_hex = '000' + id_second_part_hex
    elif id_second_part_dec >= 4096 and id_second_part_dec <= 65535:
        id_second_part_hex = '0000' + id_second_part_hex
    elif id_second_part_dec >= 256 and id_second_part_dec <= 4095:
        id_second_part_hex = '00000' + id_second_part_hex
    elif id_second_part_dec >= 16 and id_second_part_dec <= 255:
        id_second_part_hex = '000000' + id_second_part_hex
    elif id_second_part_dec >= 0 and id_second_part_dec <= 15:
        id_second_part_hex = '0000000' + id_second_part_hex

    # Adjust first part and construct Syslog ID
    if id_first_part_dec >= 0 and id_first_part_dec <= 15:
        id_first_part_hex = '000' + id_first_part_hex
        id_second_part_hex = '0000' + id_second_part_hex
    elif id_first_part_dec >= 16 and id_first_part_dec <= 255:
        id_first_part_hex = '00' + id_first_part_hex
        id_second_part_hex = '0000' + id_second_part_hex
    elif id_first_part_dec >= 256 and id_first_part_dec <= 4095:
        id_first_part_hex = '0' + id_first_part_hex
        id_second_part_hex = '0000' + id_second_part_hex
    elif id_first_part_dec >= 4096 and id_first_part_dec <= 65535:
        id_second_part_hex = '0000' + id_second_part_hex
    elif id_first_part_dec >= 65536 and id_first_part_dec <= 1048575:
        id_first_part_hex_prefix = id_first_part_hex[:1]
        id_first_part_hex = id_first_part_hex[1:]
        id_second_part_hex = '000' + id_first_part_hex_prefix + id_second_part_hex
    elif id_first_part_dec >= 1048576 and id_first_part_dec <= 16777215:
        id_first_part_hex_prefix = id_first_part_hex[:2]
        id_first_part_hex = id_first_part_hex[2:]
        id_second_part_hex = '00' + id_first_part_hex_prefix + id_second_part_hex
    elif id_first_part_dec >= 16777216 and id_first_part_dec <= 268435455:
        id_first_part_hex_prefix = id_first_part_hex[:3]
        id_first_part_hex = id_first_part_hex[3:]
        id_second_part_hex = '0' + id_first_part_hex_prefix + id_second_part_hex
    elif id_first_part_dec >= 268435456 and id_first_part_dec <= 4294967295:
        id_first_part_hex_prefix = id_first_part_hex[:4]
        id_first_part_hex = id_first_part_hex[4:]
        id_second_part_hex = id_first_part_hex_prefix + id_second_part_hex

    # Final padding to ensure the format is correct: 4 characters for first part, 12 for second
    id_first_part_hex = id_first_part_hex.zfill(4)
    id_second_part_hex = id_second_part_hex.zfill(12)

    # Construct the syslog_id and convert to uppercase
    syslog_id = f'FFFFFFFF-FFFF-FFFF-{id_first_part_hex}-{id_second_part_hex}'.upper()
    return syslog_id


def parse_response_file():
    """
    Opens response.json and parses the contents
    returns syslog_ids, syslog_details
    """
    # Open and read the JSON response file
    with open(temp_folder + 'response.json', 'r') as file:
        data = json.load(file)

    # Initialize lists and headers
    table_data = []
    syslog_ids = []
    headers = ["Device IP", "Policy", "Attack ID", "Radware ID", "Syslog ID", "Attack Category", "Attack Name", "Threat Group", "Protocol", "Source Address", "Source Port", "Destination Address", "Destination Port", "Action", "Attack Status", "Latest Attack State", "Final Attack Footprint", "Average Attack Rate(PPS)", "Average Attack Rate(BPS)", "Max Attack Rate(GBPS)", "Max Attack Rate(PPS)", "Packet Count", "Attack Duration", "Start Time", "End Time", "Direction", "Physical Port"]

    device_version_cache = {}

    for ip_address, ip_data in data.items():
        if ip_address == 'metaData':
            continue
        
        for row_data in ip_data.get('data', []):
            row = row_data.get('row', {})
            
            # Extract all relevant fields
            device_ip = row.get('deviceIp', 'N/A')
            policy_id = row.get('ruleName', 'N/A')
            attackid = row.get('attackIpsId', 'N/A')
            radwareid = row.get('radwareId', 'N/A')
            attack_category = row.get('category', 'N/A')
            attack_name = row.get('name', 'N/A')
            Threat_Group = row.get('threatGroup', 'N/A')
            Protocol = row.get('protocol', 'N/A')
            Source_Address = row.get('sourceAddress', 'N/A')
            Source_Port = row.get('sourcePort', 'N/A')
            Destination_Address = row.get('destAddress', 'N/A')
            Destination_Port = row.get('destPort', 'N/A')
            Action_Type = row.get('actionType', 'N/A')
            Attack_Status = row.get('status', 'N/A')
            Latest_State = row.get('latestBlockingState', 'N/A')
            final_footprint = row.get('latestFootprintText', 'N/A')
            Average_Attack_Rate_PPS = row.get('averageAttackPacketRatePps', 'N/A')
            Average_Attack_Rate_BPS = row.get('averageAttackRateBps', 'N/A')
            Max_Attack_Rate_BPS = row.get('maxAttackRateBps', 'N/A')
            Max_Attack_Rate_PPS = row.get('maxAttackPacketRatePps', 'N/A')         
            Packet_Count = row.get('packetCount', 'N/A')
            start_time_epoch = row.get('startTime', 'N/A')
            end_time_epoch = row.get('endTime', 'N/A')
            Direction = row.get('direction', 'N/A')
            Physical_Port = row.get('physicalPort', 'N/A')

            try:
                Max_Attack_Rate_Gbps = float(Max_Attack_Rate_BPS) / 1_000_000_000
            except:
                Max_Attack_Rate_Gbps = 0
            # Convert epoch times to datetime

            def epoch_to_datetime(epoch_time):
                """Convert epoch time to human-readable datetime format."""
                epoch_time = int(epoch_time)  # Convert epoch_time to integer
                return datetime.datetime.fromtimestamp(epoch_time / 1000.0, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S')
            
            start_time = epoch_to_datetime(start_time_epoch) if start_time_epoch != 'N/A' else 'N/A'
            end_time = epoch_to_datetime(end_time_epoch) if end_time_epoch != 'N/A' else 'N/A'
            
            # Calculate duration
            def calculate_duration(start_time, end_time):
                start_dt = datetime.datetime.strptime(start_time, '%d-%m-%Y %H:%M:%S')
                end_dt = datetime.datetime.strptime(end_time, '%d-%m-%Y %H:%M:%S')
                duration = end_dt - start_dt
                return str(duration)
            
            duration = calculate_duration(start_time, end_time) if start_time != 'N/A' and end_time != 'N/A' else 'N/A'
            # # Get the active version for the device IP
            # if ip_address not in device_version_cache:
            #     active_version = v.getActiveVersion(ip_address)
            #     device_version_cache[ip_address] = active_version
            # else:
            #     active_version = device_version_cache[ip_address]
            # # Determine if the version is 8.32.x
            # is_version_8_32_x = active_version and active_version.startswith("8.32.")

            # Determine syslog_id based on active version
            # if is_version_8_32_x:
            #     syslog_id = attackipsid_to_syslog_id(attackid)
            # else:
            #     #print("not 8.32")
            #     syslog_id = attackipsid_to_syslog_id_hex(attackid)
            
            # Determine syslog_id 
            if config.get('General', 'HexBasedSyslogIDs','true').lower() == 'true':
                syslog_id = attackipsid_to_syslog_id_hex(attackid)
            else:
                syslog_id = attackipsid_to_syslog_id(attackid)
            
            
            # Append data to the table
            table_data.append([device_ip, policy_id, attackid, radwareid, syslog_id, attack_category, attack_name, Threat_Group, Protocol, Source_Address, Source_Port, Destination_Address, Destination_Port, Action_Type, Attack_Status, Latest_State, final_footprint, Average_Attack_Rate_PPS, Average_Attack_Rate_BPS, Max_Attack_Rate_Gbps, Max_Attack_Rate_PPS, Packet_Count, duration, start_time, end_time, Direction, Physical_Port])
            syslog_ids.append(syslog_id)
    
    table_data.sort(key=lambda x: float(x[19]) if x[19] != 'N/A' else 0, reverse=True)

    syslog_details = {
    row[4]: {
        "Device IP": row[0],
        "Policy": row[1],
        "Attack ID": row[2],
        "Attack Category": row[5],
        "Attack Name": row[6],
        "Threat Group": row[7],
        "Protocol": row[8],
        "Action": row[13],
        "Attack Status": row[14],
        "Max_Attack_Rate_Gbps": row[19],
        # Unformatted value for calculations
        "Max_Attack_Rate_PPS": row[20],
        # Formatted value for display
        "Max_Attack_Rate_PPS_formatted": "{:,}".format(int(row[20])) if row[20].isdigit() else 'N/A',
        "Final Footprint": row[16],
        "Start Time": row[23],
        "End Time": row[24]
    }
          for row in table_data    
    } 
    
    #table = tabulate(table_data, headers=headers, tablefmt="pretty")

    sorted_by_pps = sorted(
        syslog_details.items(),
        key=lambda item: float(item[1].get('Max_Attack_Rate_PPS', '0').replace(' ', '')),
        reverse=True
    )

    top_by_bps = list(syslog_details.items())[:topN]
    top_by_pps = sorted_by_pps[:topN]
    for syslog_id, detail in top_by_bps[:topN]:
        syslog_details[syslog_id].update({'graph':True})
    for syslog_id, detail in top_by_pps[:topN]:
        syslog_details[syslog_id].update({'graph':True})

    #with open(outputFolder + 'output_table.txt', 'w') as f:
    #    f.write(table)

    output_csv_file = temp_folder + "output_table.csv"
    with open(output_csv_file, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(headers)  # Write headers to CSV
        for row in table_data:
            writer.writerow(row)

    print(f"Data written to CSV file: {output_csv_file}")
    return syslog_ids, syslog_details

def parse_csv(csvfile):
    """
    Receives a csvfile, creates a copy in temp_folder.
    Populates and\or appends data to .\temp\response.json.
    returns dp_list_ip, epoch_from_time, epoch_to_time, csv_data 
    """
    #reader = csv.DictReader(csvfile)
    update_log("    Detecting date format...", newline=False)
    date_format, cached_path = cache_and_identify_date_format(csvfile, date_cols=["Start Time", "End Time"], default_fmt=MDY_FMT)
    update_log(f"    {color.GREEN}Complete{color.RESET} ({date_format})")

    # Second pass: parse from cached_path
    with open(cached_path, "r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)

        # Count rows
        row_count = sum(1 for _ in reader)
        csvfile.seek(0)
        update_log(f"    Processing CSV ({row_count} rows)")
        json_output_file = temp_folder + "response.json"
        dp_list_ip = {}
        # Mapping of "JSON output field": "input CSV header" (or None for generated/default fields)
        json_field_map = {
            "deviceIp": "Device IP Address",
            "sourcePort": "Source Port",
            "vlanTag": "VLAN Tag",
            "packetCount": "Total Packets",
            "packetRate": None,
            "averageAttackPacketRatePps": None, #Calculated
            "lastPeriodBandwidth": None,
            "poId": "Protected Object",
            "duration": "Duration",
            "protocol": "Protocol",
            "destPort": "Destination Port",
            "detectorName": "Device Name",
            "threatGroup": "Threat Group",
            "destAddress": "Destination IP Address",
            "ruleName": "Policy Name",
            "radwareId": "Radware ID",
            "startTime": "Start Time",
            "trapVersion": None,
            "direction": "Direction",
            "averageAttackRateBps": None,  # Calculated from Total Mbits / Duration
            "activationId": "Activation Id",
            "packetType": "Packet Type",
            "maxAttackRateBps": None, #"Max Attack Rate in Kb" or "Max bps" depending on the CSV version
            "mplsRd": None,
            "attackIpsId": "Attack ID",
            "sourceAddress": "Source IP Address",
            "isFragmented": None,
            "latestFootprintText": "Footprint",
            "enrichmentContainer": None,
            "deviceVersion": None,
            "isProcessByWorkflow": "Workflow Rule Process",
            "physicalPort": "Physical Port",
            "actionType": "Action",
            "lastPeriodPacketRate": None,
            "maxAttackPacketRatePps": "Max pps",
            "tierId": None,
            "packetBandwidth": "Total Mbits", #Calculated
            "name": "Attack Name",
            "risk": "Risk",
            "detectionSource": None,
            "endTime": "End Time",
            "category": "Threat Category",
            "status": None
        }
        reader = csv.DictReader(csvfile, delimiter=',')
        grouped_json = {}
        csv_data = {'Destination IP Address':{}, 'Destination Port':{}, 'Source IP Address':{}, 'Source Port':{}, 'Protocol':{}, 'Protocol Kbits':{}, 'Protocol Packets':{}}
        csv_data['topN'] = {'Destination IP Address':{}, 'Destination Port':{}, 'Source IP Address':{}, 'Source Port':{}, 'Protocol':{}, 'Protocol Kbits':{}, 'Protocol Packets':{}}
        for row in reader:
            json_row = {}

            device_ip = row.get("Device IP Address", "Unknown")
            device_name = row.get("Device Name", "Unknown")
            policy = row.get("Policy Name", "Unknown")

            # Create or update the DP entry
            if device_ip not in dp_list_ip:
                dp_list_ip[device_ip] = {'name': device_name, 'policies': [policy]}
            else:
                dp_list_ip[device_ip]['name'] = device_name  # overwrite is okay
                policies = dp_list_ip[device_ip].setdefault('policies', [])
                if policy not in policies:
                    policies.append(policy)


            for field, csv_col in json_field_map.items():
                value = "N/A"
                if field == "averageAttackRateBps":
                    try:
                        mbits = float(row.get("Total Mbits", "0").replace(",", ""))
                        duration = float(row.get("Duration", "0").replace(",", ""))
                        value = f"{(mbits * 1_000_000 / duration):.2f}" if duration > 0 else "0"
                    except (ValueError, ZeroDivisionError):
                        value = "0"
                elif field == "averageAttackPacketRatePps":
                    try:
                        packets = int(row.get("Total Packets", "0").replace(",", ""))
                        duration = float(row.get("Duration", "0").replace(",", ""))
                        value = f"{(packets / duration):.2f}" if duration > 0 else "0"
                    except (ValueError, ZeroDivisionError):
                        value = "0"
                elif field == "packetBandwidth":
                    value = int(float(row.get("Total Mbits", "0")) * 1000)
                elif field == "maxAttackRateBps":
                    value = row.get("Max Attack Rate in Kb", "N/A")
                    if value == "N/A":
                        value = row.get("Max bps", "N/A")
                elif field in ("startTime", "endTime"):
                    datetime_str = row.get(csv_col, None)
                    if datetime_str:
                        dt = datetime.datetime.strptime(datetime_str, date_format)
                        #dt = dt.replace(tzinfo=timezone.utc)  # Treat the timezone as UTC
                        value = str(int(dt.timestamp() * 1000))
                        if field == "startTime":
                            if 'epoch_from_time' not in locals():
                                epoch_from_time = value
                            else:
                                if value < epoch_from_time:
                                    epoch_from_time = value
                        else:
                            if 'epoch_to_time' not in locals():
                                epoch_to_time = value
                            else:
                                if value < epoch_from_time:
                                    epoch_to_time = value
                    else:
                        value = "N/A"
                elif csv_col in csv_data.keys():
                    value = row.get(csv_col, "N/A")
                    if csv_col == "Protocol":
                        csv_data[csv_col][value] = int(csv_data[csv_col].get(value,0)) + 1
                        csv_data[csv_col + " Kbits"][value] = int(csv_data[csv_col + " Kbits"].get(value,0)) + max(int(float(row.get("Total Mbits", 1))* 1000), 1)
                        csv_data[csv_col + " Packets"][value] = int(csv_data[csv_col + " Packets"].get(value,0)) + max(int(row.get("Total Packets", 1)), 1)
                    else:
                        csv_data[csv_col][value] = int(csv_data[csv_col].get(value,0)) + 1
                        
                elif csv_col:
                    value = row.get(csv_col, "N/A")

                json_row[field] = value

            entry = {"row": json_row}
            grouped_json.setdefault(device_ip, {"data": []})["data"].append(entry)

    
    update_log("    Checking for/opening existing JSON")
    # Merge with existing JSON data if file exists
    if os.path.exists(json_output_file):
        try:
            with open(json_output_file, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
        except json.JSONDecodeError:
            existing_data = {}
    else:
        existing_data = {}

    update_log("    Appending CSV data to JSON")
    for device_ip, new_block in grouped_json.items():
        if device_ip in existing_data:
            existing_data[device_ip]["data"].extend(new_block["data"])
        else:
            existing_data[device_ip] = new_block

    lines_per_row_estimate = 14  # Roughly how many lines each row takes when indented
    header_lines_estimate = 4 * len(existing_data)  # Opening & closing for each device block

    total_json_rows = sum(len(device["data"]) for device in existing_data.values())
    estimated_lines = (total_json_rows * lines_per_row_estimate) + header_lines_estimate + 2  # +2 for the root braces

    update_log(f"    Saving JSON ({total_json_rows} entires producing an estimated {estimated_lines} lines of output)...", newline=False)
    # Write merged JSON back
    with open(json_output_file, 'w', encoding='utf-8') as f:
        json.dump(existing_data, f, indent=4)
    update_log(f"    {color.GREEN}Complete{color.RESET}")


    #Process topN sources/destinations/ports
    update_log(f"    Parsing Top {topN}...", newline=False)
    csvfile.seek(0)
    reader = csv.DictReader(csvfile)  # Each row is a dict
    top_rows_pps = heapq.nlargest(topN, reader, key=lambda row: float(row['Max pps'].replace(",", "") or 0))
    csvfile.seek(0)
    reader = csv.DictReader(csvfile)
    top_rows_bps = heapq.nlargest(topN, reader, key=lambda row: (
        float(row['Total Mbits'].replace(",", "")) / float(row['Duration'].replace(",", "")) 
        if row.get('Duration') and row['Duration'].replace(",", "").strip() not in ("", "0", "0.0") else float('-inf')
    )
)

    # Merge without duplicates
    top_rows = {}
    for row in top_rows_pps + top_rows_bps:
        row_key = json.dumps(row, sort_keys=True)
        top_rows[row_key] = row

    top_rows = list(top_rows.values())  # Unique rows only

    for row in top_rows:
        for key, value in row.items():
            if key in csv_data['topN'].keys():
                value = row.get(key, "N/A")
                if key == "Protocol":
                    csv_data['topN'][key][value] = int(csv_data['topN'][key].get(value,0)) + 1
                    csv_data['topN'][key + " Kbits"][value] = int(csv_data['topN'][key + " Kbits"].get(value,0)) + max(int(float(row.get("Total Mbits", 1))* 1000), 1)
                    csv_data['topN'][key + " Packets"][value] = int(csv_data['topN'][key + " Packets"].get(value,0)) + max(int(row.get("Total Packets", 1)), 1)
                else:
                    csv_data['topN'][key][value] = int(csv_data['topN'][key].get(value,0)) + 1

    update_log(f"    {color.GREEN}Complete{color.RESET}")
    return dp_list_ip, epoch_from_time, epoch_to_time, csv_data

def parse_log_file(file, syslog_ids):
    # Initialize a dictionary to hold the log entries for each attack ID
    attack_logs = {syslog_id: [] for syslog_id in syslog_ids}
    
    with open(file, 'r') as file:
        lines = file.readlines()

        # To store the most recent matching generic syslog_id for each region and attack type
        latest_initial_log = {}

        for line in lines:
            line = line.strip()
            parts = line.split(',')
            
            # Extract timestamp, region, attack type, syslog_id, and data
            timestamp = parts[0].strip()
            region = parts[1].strip()  # Example: 'eu1_34_0-24'
            attack_type = parts[3].strip()  # Example: 'network flood IPv4 UDP'
            syslog_id = parts[4].strip()  # Example: 'FFFFFFFF-FFFF-FFFF-2CB3-040F66846000'
            data = ','.join(parts[5:]).strip()


            # Check if this is a generic syslog_id
            if syslog_id in ['FFFFFFFF-0000-0000-0000-000000000000', 'FFFFFFFF-FFFF-FFFF-0000-000000000000']:
                # Store this line as the most recent generic syslog_id for this region and attack type
                key = (region, attack_type)
                latest_initial_log[key] = (timestamp, data)
            
            # Check if the current line contains a specific syslog_id
            for attack_id in syslog_ids:
                if attack_id in syslog_id:
                    key = (region, attack_type)
                    
                    # If there is a corresponding initial log, add it to the attack log first
                    if key in latest_initial_log:
                        attack_logs[attack_id].append(latest_initial_log[key])
                        del latest_initial_log[key]  # Remove the initial log once used
                    
                    # Add the current log entry to the correct attack log
                    attack_logs[attack_id].append((timestamp, data))
                    break  # Move to the next line after processing the attack_id

    return attack_logs
 # type: ignore


import re

def categorize_logs_by_state(attack_logs):
    state_definitions = {
        '0': "Attack Ended",
        '2': "Attack has been detected, fp characterization started - FORWARDING",
        '4': "Initial fp created - FORWARDING",
        '6': "Final fp created - BLOCKING",
        '9': "Burst attack state (Handling burst attack)"
    }

    categorized_logs = {syslog_id: [] for syslog_id in attack_logs}

    state_pattern = re.compile(r"Entering state (\d+)")
    footprint_pattern = re.compile(r"Footprint \[(.*)\]")

    for syslog_id, logs in attack_logs.items():
        current_state = None
        for timestamp, entry in logs:
            state_match = state_pattern.search(entry)
            footprint_match = footprint_pattern.search(entry)

            if state_match:
                state_code = state_match.group(1)
                if state_code in state_definitions:
                    current_state = state_code
                    state_description = state_definitions[state_code]
                    categorized_logs[syslog_id].append((timestamp, f"State {state_code}: {state_description}", entry))

            elif footprint_match and current_state == '6':
                state_description = state_definitions.get(current_state, "Unknown state")
                categorized_logs[syslog_id].append((timestamp, f"State {current_state}: {state_description}", entry))

    return categorized_logs

from collections import defaultdict

def extract_state_6_footprints(attack_logs):
    state_pattern = re.compile(r"Entering state (\d+)")
    blocks_by_syslog = defaultdict(list)

    for syslog_id, logs in attack_logs.items():
        in_state_6 = False
        current_block = []

        for timestamp, entry in logs:
            state_match = state_pattern.search(entry)
            if state_match:
                state_code = state_match.group(1)

                if in_state_6 and current_block:
                    blocks_by_syslog[syslog_id].append(current_block)
                    current_block = []

                in_state_6 = (state_code == '6')
                if in_state_6:
                    current_block.append((timestamp, entry))
                else:
                    in_state_6 = False
            elif in_state_6:
                current_block.append((timestamp, entry))

        if in_state_6 and current_block:
            blocks_by_syslog[syslog_id].append(current_block)

    # Format the output like metrics_summary
    formatted_results = {}
    for syslog_id, blocks in blocks_by_syslog.items():
        block_texts = []
        for i, block in enumerate(blocks, start=1):
            block_lines = [f"{timestamp} | {entry}" for timestamp, entry in block]
            indented = "\n".join(f"    {line}" for line in block_lines)
            block_texts.append(f"----- State 6 Block {i} -----\n{indented}")
        formatted_results[syslog_id] = {
            "state_6_footprints": "\n\n".join(block_texts)
    }


    return formatted_results





def calculate_attack_metrics(categorized_logs):
    metrics = {}

    def format_timedelta(td):
        if td is None:
            return "N/A"
        total_seconds = int(td.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02}:{minutes:02}:{seconds:02}"

    def format_percentage(value):
        if value is None:
            return 'N/A'
        return f"{value:.2f}%"

    for syslog_id, entries in categorized_logs.items():
        state_2_times = []
        state_4_times = []
        state_6_times = []
        state_6_transition = False

        if not entries:
            continue

        fmt = '%d-%m-%Y %H:%M:%S'

        last_state_6 = None
        next_state_after_6 = None

        for entry in entries:
            timestamp, _, state_description = entry
            log_time = datetime.datetime.strptime(timestamp, fmt)

            if "Entering state 2" in state_description:
                state_2_times.append(log_time)
                if last_state_6 and not next_state_after_6:
                    next_state_after_6 = log_time
            elif "Entering state 4" in state_description:
                state_4_times.append(log_time)
                if last_state_6 and not next_state_after_6:
                    next_state_after_6 = log_time
            elif "Entering state 6" in state_description:
                state_6_times.append(log_time)
                last_state_6 = log_time
                state_6_transition = True
                next_state_after_6 = None
            elif 'FFFFFFFF-0000-0000-0000-000000000000' in state_description or \
                    'FFFFFFFF-FFFF-FFFF-0000-000000000000' in state_description:
                state_6_times.append(log_time)
                last_state_6 = log_time
                state_6_transition = True
                next_state_after_6 = None
            elif "Entering state 0" in state_description:
                if last_state_6 and next_state_after_6:
                    break
        first_state_2 = state_2_times[0] if state_2_times else None
        first_state_4 = state_4_times[0] if state_4_times else None
        last_state_4 = state_4_times[-1] if state_4_times else None
        first_time = datetime.datetime.strptime(entries[0][0], fmt)
        last_time = datetime.datetime.strptime(entries[-1][0], fmt)
        if state_6_times and state_6_times[0] == first_time:
            # Burst attack detected
            attack_time = last_time - first_time
            blocking_time = last_time - state_6_times[0]
            blocking_time_percentage = (blocking_time / attack_time) * 100 if attack_time.total_seconds() > 0 else None

            metrics[syslog_id] = {
                'metrics_summary': (
                    f"Burst Attack Detected, Using previous blocking footprint\n"
                    f"Total Attack Duration: {format_timedelta(attack_time)}\n"
                    f"Blocking Time: {format_timedelta(blocking_time)}\n"
                    f"Blocking Time Percentage: {format_percentage(blocking_time_percentage)}"
                )
            }
        else:
            initial_fp_time = None
            if last_state_4:
                if first_state_2:
                    initial_fp_time = last_state_4 - first_state_2
                else:
                    initial_fp_time = last_state_4 - first_time

            final_fp_time = None
            if last_state_6 and last_state_4:
                final_fp_time = last_state_6 - first_state_4
            elif not state_6_transition:
                final_fp_time = "Final footprint not formed"

            blocking_time = None
            if last_state_6:
                if next_state_after_6:
                    blocking_time = next_state_after_6 - last_state_6
                else:
                    blocking_time = last_time - last_state_6

            total_duration = last_time - first_time
            blocking_time_percentage = None
            if blocking_time and total_duration.total_seconds() > 0:
                blocking_time_percentage = (blocking_time / total_duration) * 100

            formatted_total_duration = format_timedelta(total_duration)
            formatted_initial_fp_time = format_timedelta(initial_fp_time)
            formatted_final_fp_time = final_fp_time if isinstance(final_fp_time, str) else format_timedelta(final_fp_time)
            formatted_blocking_time = format_timedelta(blocking_time)
            formatted_blocking_time_percentage = format_percentage(blocking_time_percentage)

            metrics[syslog_id] = {
                'metrics_summary': (
                    f"Total Attack Duration: {formatted_total_duration}\n"
                    f"Time taken to create initial LOW strictness footprint: {formatted_initial_fp_time}\n"
                    f"Time taken to optimize and create the final footprint: {formatted_final_fp_time}\n"
                    f"Blocking Time: {formatted_blocking_time}\n"
                    f"Blocking Time Percentage: {formatted_blocking_time_percentage}"
                )
            }

    return metrics

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