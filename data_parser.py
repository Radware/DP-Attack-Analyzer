from datetime import datetime, timezone
import json
import csv
import re

from common import temp_folder
from common import topN


#################### Helper functions ####################
def epoch_to_datetime(epoch_time):
    """Convert epoch time to human-readable datetime format."""
    epoch_time = int(epoch_time)  # Convert epoch_time to integer
    return datetime.fromtimestamp(epoch_time / 1000.0, tz=timezone.utc).strftime('%d-%m-%Y %H:%M:%S')
    #return datetime.fromtimestamp(epoch_time / 1000.0).strftime('%Y-%m-%d %H:%M:%S')


def calculate_duration(start_time, end_time):
    start_dt = datetime.strptime(start_time, '%d-%m-%Y %H:%M:%S')
    end_dt = datetime.strptime(end_time, '%d-%m-%Y %H:%M:%S')
    duration = end_dt - start_dt
    return str(duration)

def convert_bps_to_gbps(bps_value):
    """
    Convert a value from bits per second (BPS) to gigabits per second (Gbps).
    """
    if bps_value == 'N/A':
        return 'N/A'
    
    try:
        bps_value = float(bps_value)  # Convert to float for calculation
        gbps_value = bps_value / 1_000_000_000  # Convert to Gbps
        return gbps_value
    except (ValueError, TypeError):
        return 'N/A'  # Return 'N/A' if conversion fails

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
    # This function converts AttackIpsID to Syslog ID

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


def parse_response_file(v):
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
        
        # Get the active version for the device IP
        if ip_address not in device_version_cache:
            active_version = v.getActiveVersion(ip_address)
            device_version_cache[ip_address] = active_version
        else:
            active_version = device_version_cache[ip_address]
        # Determine if the version is 8.32.x
        print(device_version_cache)
        is_version_8_32_x = active_version and active_version.startswith("8.32.")
        
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

            Max_Attack_Rate_Gbps = convert_bps_to_gbps(Max_Attack_Rate_BPS)
            # Convert epoch times to datetime
            start_time = epoch_to_datetime(start_time_epoch) if start_time_epoch != 'N/A' else 'N/A'
            end_time = epoch_to_datetime(end_time_epoch) if end_time_epoch != 'N/A' else 'N/A'
            
            # Calculate duration
            duration = calculate_duration(start_time, end_time) if start_time != 'N/A' and end_time != 'N/A' else 'N/A'
            
            # Determine syslog_id based on active version
            if is_version_8_32_x:
                syslog_id = attackipsid_to_syslog_id(attackid)
            else:
                #print("not 8.32")
                syslog_id = attackipsid_to_syslog_id_hex(attackid)
            
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


def parse_log_file(outputFolder, syslog_ids):
    # Initialize a dictionary to hold the log entries for each attack ID
    attack_logs = {syslog_id: [] for syslog_id in syslog_ids}
    
    with open(outputFolder, 'r') as file:
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
            data = parts[5].strip()
            
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


def categorize_logs_by_state(attack_logs):
    # State definitions
    state_definitions = {
        '0': "Attack Ended",
        '2': "Attack has been detected, fp characterization started - FORWARDING",
        #'3': "Anomaly state (Generated FP not able to mitigate the attack)",
        '4': "Initial fp created - FORWARDING",
        #'5': "Sub-hierarchy state (AND part of the FP is created)",
        '6': "Final fp created - BLOCKING",
        #'7': "Non-strictness footprint state (When generated FP is not meeting strictness level)",
        '9': "Burst attack state (Handling burst attack)"
    }
    
    # Initialize a dictionary to hold categorized logs based on states
    #categorized_logs = {syslog_id: [] for syslog_id in attack_logs}
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
            elif footprint_match and current_state:
                state_description = state_definitions.get(current_state, "Unknown state")
                categorized_logs[syslog_id].append((timestamp, f"State {current_state}: {state_description}", entry))
    
    return categorized_logs


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
            log_time = datetime.strptime(timestamp, fmt)

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
        first_time = datetime.strptime(entries[0][0], fmt)
        last_time = datetime.strptime(entries[-1][0], fmt)
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








