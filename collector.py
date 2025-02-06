import time
import json
import os
import datetime

from clsVision import *
from common import *


#################### Helper functions ####################
# def convert_to_epoch(human_readable_time, time_format='%d-%m-%Y %H:%M:%S'):
#     # Parse the human-readable time to a datetime object
#     dt = datetime.strptime(human_readable_time, time_format)
#     # Convert the datetime object to epoch time
#     epoch_time = int(time.mktime(dt.timetuple()) * 1000)
#     return epoch_time, dt.month


def prompt_user_time_period():
    """ Prompt user for time period, returns a list, [0] epoch start time, [1] epoch end time """
    previousFromTime = config.get('PreviousRun','epoch_from_time')
    previousToTime = config.get('PreviousRun','epoch_to_time')
    arg_choice = False
    if len(args) == 0:
        #Ask user for time period:
        print("Please select a time period:")
        print("1) The past x hours")
        print("2) The past 24 hours")
        print("3) The past 48 hours")
        print("4) Manually enter attack timeframe (Assumes your PC's local time zone unless UTC is specified)")
        print("5) Manually enter timeframe in epoch time")
        if previousFromTime and previousToTime:
            longFromTime = datetime.datetime.fromtimestamp(int(previousFromTime)/1000).strftime('%d-%m-%Y %H:%M:%S')
            longToTime = datetime.datetime.fromtimestamp(int(previousToTime)/1000).astimezone().strftime('%d-%m-%Y %H:%M:%S %Z')
            longFromTimeUTC = datetime.datetime.fromtimestamp(int(previousFromTime)/1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S')
            longToTimeUTC = datetime.datetime.fromtimestamp(int(previousToTime)/1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S %Z')
            print(f"6) Time range from previous run - {longFromTime} to {longToTime} ({longFromTimeUTC} to {longToTimeUTC})")
        else:
            print("6) Time range from previous run (previous run not available)")
        choice = input("Enter selection (1-6) or other to quit: ")
    else:
        #Script is run with arguments.
        arg_choice = args.pop(0)
        if arg_choice == '--hours' or arg_choice == '-h':
            choice = '1'
        elif arg_choice == '--date-range' or arg_choice == '-dr':
            choice = '4'
        elif arg_choice == '--epoch-range' or arg_choice == '-er':
            choice = '5'
        elif arg_choice == '--previous-time-range' or arg_choice == '-p':
            choice = '6'

    if choice == '1':#The past x hours
        hours = int(args.pop(0)) if args else int(input("Enter number of hours: "))
        epoch_from_time = (int(time.time()) - (60 * 60 * hours)) * 1000
        epoch_to_time = int(time.time()) * 1000
        # from_month = datetime.fromtimestamp(epoch_from_time / 1000).month
        # to_month = datetime.fromtimestamp(epoch_to_time / 1000).month
    elif choice == '2':#The past 24 hours
        epoch_from_time = (int(time.time()) - (60 * 60 * 24)) * 1000
        epoch_to_time = int(time.time()) * 1000
        # from_month = datetime.fromtimestamp(epoch_from_time / 1000).month
        # to_month = datetime.fromtimestamp(epoch_to_time / 1000).month
    elif choice == '3':#The past 48 hours
        epoch_from_time = (int(time.time()) - (60 * 60 * 48)) * 1000
        epoch_to_time = int(time.time()) * 1000
        # from_month = datetime.fromtimestamp(epoch_from_time / 1000).month
        # to_month = datetime.fromtimestamp(epoch_to_time / 1000).month
    elif choice == '4':#Manually enter attack timeframe
        success = False
        while not success:
            try:
                from_time = args.pop(0) if args else input("Enter the closest time before the attack START (format: DD-MM-YYYY HH:MM:SS [optional:UTC]) or q to quit: ")
                if from_time == 'q':
                    print("Quit")
                    exit(1)

                utc=False
                if "utc" in from_time.lower():
                    utc=True
                    from_time = from_time.lower().replace("utc", "").strip()

                dt = datetime.datetime.strptime(from_time, '%d-%m-%Y %H:%M:%S')
                if utc: 
                    dt = dt.replace(tzinfo=datetime.timezone.utc)

                #epoch_from_time = int(time.mktime(dt.timetuple()) * 1000)
                epoch_from_time = int(dt.timestamp() * 1000)
                # from_month = dt.month
                success = True
            except ValueError:
                if arg_choice:
                    update_log("Error parsing start time argument. Exiting.")
                    exit(1)
                print("Error parsing start time, please try again!")
            
        success = False
        while not success:
            try:
                to_time = args.pop(0) if args else input("Enter the closest time after the attack END (format: DD-MM-YYYY HH:MM:SS [optional: UTC]) or q to quit: ")
                if from_time == 'q':
                    print("Quit")
                    exit(1)

                utc=False
                if "utc" in from_time.lower():
                    utc=True
                    from_time = from_time.lower().replace("utc", "").strip()

                dt = datetime.datetime.strptime(from_time, '%d-%m-%Y %H:%M:%S')
                if utc: 
                    dt = dt.replace(tzinfo=datetime.timezone.utc)

                #epoch_from_time = int(time.mktime(dt.timetuple()) * 1000)
                epoch_from_time = int(dt.timestamp() * 1000)
                # from_month = dt.month
                success = True
            except ValueError:
                if arg_choice:
                    update_log("Error parsing start time argument. Exiting.")
                    exit(1)
                print("Error parsing end time, please try again.")
    elif choice == '5':
        from_time = args.pop(0) if args else input("Enter epoch from time")
        to_time = args.pop(0) if args else input("Enter epoch to time")
        if from_time.isnumeric() and to_time.isnumeric():
            epoch_from_time = int(from_time)
            epoch_to_time = int(to_time)
        else:
            print("Non-Numeric entry, quit")
            exit(1)
    elif choice == '6':
        if previousFromTime and previousToTime:
            epoch_from_time = int(previousFromTime)
            epoch_to_time = int(previousToTime)
    else:
        update_log("Other input, quit")
        exit(0)
    
    if not arg_choice:
        #Update the config if it was not run with arguments.
        config.set('PreviousRun','epoch_from_time',epoch_from_time)
        config.set('PreviousRun','epoch_to_time',epoch_to_time)
        config.save()


    from_month = datetime.datetime.fromtimestamp(epoch_from_time / 1000).month
    to_month = datetime.datetime.fromtimestamp(epoch_to_time / 1000).month
    start_year = datetime.datetime.fromtimestamp(epoch_from_time / 1000).year
    end_year = datetime.datetime.fromtimestamp(epoch_to_time / 1000).year

    if from_month == to_month and start_year == end_year:
        epoch_time_range = [epoch_from_time, epoch_to_time, from_month, start_year]
        return epoch_time_range
        #return from_month
    else:
        epoch_time_range = [epoch_from_time, epoch_to_time, from_month, start_year, to_month]
        return epoch_time_range
    
    #return epoch_time_range


def user_selects_defensePros(v):
    """
    Fetches the list of available DefensePro devices from Vision instance 'v',
    displays them to the user, and validates user input for device IPs.
    Returns:
    - valid_ips (list): A list of validated DefensePro device IPs entered by the user.
    - dp_list_ip (dict): A dictionary mapping of the DefensePro device IPs to device information, fetched from the Vision instance 'v'.
                         Keys are device IPs and values are the corresponding device information.
    """
    try:
        device_list = v.getDPDeviceList()
        #dp_list_ip = {device['managementIp']: device for device in device_list}
        dp_list_ip = {device['managementIp']: device for device in device_list if device['status'] != 'FAILED'}
        
        # Display list of available DefensePros
        #print("Available Defensepros: " + ', '.join(dp_list_ip.keys()))
        print("Available DefensePros: " + ', '.join(f"{dp_list_ip[key]['name']} ({key})" for key in dp_list_ip))
        
        used_args = False
        while True:
            if args:
                device_entries = args.pop(0).split(',')
                used_args = True
            else:
                if len(sys.argv) == 1:#If script is run with arguments, don't prompt. Length of 1 is 0 user arguments.
                    device_entries = input("Enter DefensePro Names or IPs separated by commas (or leave blank for All available devices): ").split(',')
                else:
                    device_entries = ""
            if len(device_entries[0]) == 0 and len(device_entries) == 1:
                valid_ips = list(dp_list_ip.keys())
                break
            else:
                # Validate all the user's entries are valid.
                valid_ips = []
                invalid_entries = []
                for entry in device_entries:
                    entry = entry.strip()
                    matched_entry = None
                    #Check if the entry matches a valid DP name.
                    for key, value in dp_list_ip.items():
                        if value['name'].lower() == entry.lower():
                            valid_ips.append(key)
                            break
                    else:
                        #No name was matched, check if the entry matches an IP
                        if entry in dp_list_ip:
                            valid_ips.append(entry)
                        else:
                            invalid_entries.append(entry)

                if invalid_entries:
                    if used_args:
                        update_log(f"Error processing argument - <DefensePro list>. Received {device_entries}. \r\n\tThe following entries are invalid or not available: {', '.join(invalid_entries)}. The final report will not include unavailable devices")
                        #exit(1)
                        common_globals['unavailable_devices'] = invalid_entries
                        break
                    else:
                        print(f"The following entries are invalid or not available: {', '.join(invalid_entries)}")
                elif valid_ips:
                    #device_entries = valid_ips
                    break
                else:
                    print("Please enter valid IP addresses or device hostnames.")
        return valid_ips, dp_list_ip

    except Exception as e:
        update_log(f"An error occurred while fetching device list: {e}")
        return [], {}


def get_attack_data(epoch_from_time, epoch_to_time, v, device_ips, policies, dp_list_ip):
    try:
        attack_data = {}
        for device_ip in device_ips:
            device_ip = device_ip.strip()
            if device_ip not in dp_list_ip:
                update_log(f"Device IP {device_ip} is not available or does not exist. Skipping.")
                continue
            device_policies = policies.get(device_ip, [])
            filters = [
                {
                    "type": "termFilter",
                    "inverseFilter": False,
                    "field": "ruleName",
                    "value": policy
                }
                for policy in device_policies
            ]
            
            filter_json = {
                "type": "orFilter",
                "inverseFilter": False,
                "filters": filters
            } if filters else None

            response_data = v.getAttackReports(device_ip, epoch_from_time, epoch_to_time,filter_json)

            print(f"Attack data for {device_ip}:")
            #print(response_data)
            try:
                    total_hits = int(response_data["metaData"]["totalHits"])
                    if total_hits == 0:
                        raise ValueError(f"No data present for the specified time period for {device_ip}")
            except KeyError:
                    update_log(f"No 'metaData' key in response for {device_ip}")
                    continue
            except ValueError as ve:
                    update_log(str(ve))
                    continue   

            attack_data[device_ip] = response_data

        
        return attack_data

    except Exception as e:
        update_log(f"An error occurred: {e}")             
    

def get_all_sample_data(v, top_by_bps, top_by_pps):
    # Initialize lists to store the filtered data and unique source IPs
    all_sample_data_bps = []
    all_sample_data_pps = []
    unique_ips_bps = set()
    unique_ips_pps = set()
    deduplicated_sample_data = []
    combined_unique_samples = set()  # To store unique combined samples

    # Function to extract relevant fields from sample data
    def extract_fields(sample_data, unique_ips):
        extracted_data = []
        for item in sample_data:
            row = item.get('row', {})
            source_ip = row.get('sourceAddress')
            source_port = row.get('sourcePort')
            dest_ip = row.get('destAddress')
            dest_port = row.get('destPort')

            # Collect unique source IPs
            if source_ip:
                unique_ips.add(source_ip)

            # Add the extracted data as a tuple for deduplication
            extracted_data.append({
                'sourceAddress': source_ip,
                'sourcePort': source_port,
                'destAddress': dest_ip,
                'destPort': dest_port
            })
        return extracted_data

    # Collect and filter attack IDs for both BPS and PPS
    for _, details in top_by_bps:
        attack_id = details.get('Attack ID')
        if attack_id:
            try:
                sample_data = v.get_sample_data(attack_id)
                if isinstance(sample_data, dict):
                    filtered_data = extract_fields(sample_data.get('data', []), unique_ips_bps)
                    all_sample_data_bps.append({attack_id: filtered_data})
                else:
                    update_log(f"Unexpected data format for attack id {attack_id}: {sample_data}")
            except Exception as e:
                update_log(f"Failed to get sample data for attack id {attack_id}: {e}")

    for _, details in top_by_pps:
        attack_id = details.get('Attack ID')
        if attack_id:
            try:
                sample_data = v.get_sample_data(attack_id)
                if isinstance(sample_data, dict):
                    filtered_data = extract_fields(sample_data.get('data', []), unique_ips_pps)
                    all_sample_data_pps.append({attack_id: filtered_data})
                else:
                    update_log(f"Unexpected data format for attack id {attack_id}: {sample_data}")
            except Exception as e:
                update_log(f"Failed to get sample data for attack id {attack_id}: {e}")

    # Deduplicate sample data by combining BPS and PPS sample data based on all fields
    def deduplicate_sample_data(sample_data_list):
        seen_samples = set()  # To keep track of unique sample entries
        deduplicated = []
        for sample_data in sample_data_list:
            for attack_id, data in sample_data.items():
                for entry in data:
                    # Create a tuple of all fields for deduplication
                    sample_tuple = (
                        entry['sourceAddress'],
                        entry['sourcePort'],
                        entry['destAddress'],
                        entry['destPort']
                    )
                    # Only add if the tuple is unique
                    if sample_tuple not in seen_samples:
                        seen_samples.add(sample_tuple)
                        deduplicated.append(entry)
                        combined_unique_samples.add(sample_tuple)  # Collect unique samples across BPS and PPS
        return deduplicated

    # Combine BPS and PPS sample data, deduplicating them
    deduplicated_sample_data = deduplicate_sample_data(all_sample_data_bps + all_sample_data_pps)

    # Ensure the output directory exists
    if not os.path.exists(temp_folder):
        os.makedirs(temp_folder)

    # Save results to JSON files
    bps_file_path = os.path.join(temp_folder, 'top_by_bps_sample_data.json')
    pps_file_path = os.path.join(temp_folder, 'top_by_pps_sample_data.json')

    with open(bps_file_path, 'w') as f:
        json.dump(all_sample_data_bps, f, indent=4)
    print(f"Sample data for top_by_bps saved to {bps_file_path}")

    with open(pps_file_path, 'w') as f:
        json.dump(all_sample_data_pps, f, indent=4)
    print(f"Sample data for top_by_pps saved to {pps_file_path}")

    # Return the processed sample data, unique IPs for BPS/PPS, and combined deduplicated sample data
    return all_sample_data_bps, all_sample_data_pps, list(unique_ips_bps), list(unique_ips_pps), deduplicated_sample_data, list(combined_unique_samples)

