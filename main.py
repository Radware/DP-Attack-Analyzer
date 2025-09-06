import traceback
import json
import tarfile
import zipfile
import ipaddress
import html
from collections import defaultdict



#internal modules
import clsVision
import collector
import data_parser
import html_attack_summary
import html_data
import html_graphs
import html_header
import html_ip_reputation
import sftp_module
import send_email



#Default options such as topN and output folder are now stored in common.py. 
from common import *

collect_data=True
parse_data=True
csv_attack_data = {}
if __name__ == '__main__':
    if collect_data and (not args or (args[0].lower() != '--offline' and args[0] != '-o')):
        update_log("Creating/clearing temp folder")
        #Make sure temp_folder exists and that it is empty
        if os.path.exists(temp_folder):
            # Remove all files in the temp folder
            for filename in os.listdir(temp_folder):
                file_path = os.path.join(temp_folder, filename)
                #if log_file not in file_path:#We can exclude the log file from deletion by uncommenting this line.
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                except Exception as e:
                    update_log(f"  Failed to delete {file_path}. Reason: {e}")
            log_state = 1
        else:
            # Create the temp folder if it doesn't exist
            os.makedirs(temp_folder)
            log_state = 1
        device_name = "name_not_found"
        if args and (args[0].lower() == '--manually-collected' or args[0] == '-m'):
            update_log("Running in 'Manually Collected Files' mode")
            common_globals['Manual Mode'] = True
            if os.path.exists(manual_folder):
                found_files = []
                dp_list_ip = {}
                foundtgz = False
                foundzip = False
                for filename in os.listdir(manual_folder):
                    file_path = os.path.join(manual_folder, filename)
                    if filename.endswith(".tar.gz"):
                        update_log(f'Processing {file_path}')
                        #Do tar support file stuff
                        with tarfile.open(file_path,'r:gz') as outer_tgz:
                            for member in outer_tgz.getmembers():
                                if member.isfile() and member.name == './support.txt':
                                    with outer_tgz.extractfile(member) as f:
                                        for line in f:
                                            decoded = line.decode(errors='ignore')
                                            match = re.search(r'^system mib2-name set (\S+)', decoded)
                                            if match:
                                                device_name = match.group(1)
                                                update_log(f"    Device name found: {color.CYAN}{device_name}{color.RESET}")
                                                break
                            for member in outer_tgz.getmembers():
                                #extract attack log
                                if member.isfile() and member.name.startswith('./attack_log/') and member.name.endswith('tar.gz'):
                                    update_log(f'    {member.name} found. Extracting to {temp_folder}...', newline=False)
                                    inner_tgz_file = outer_tgz.extractfile(member)
                                    if inner_tgz_file:
                                        with tarfile.open(fileobj=inner_tgz_file) as inner_tgz:
                                            for inner_member in inner_tgz.getmembers():
                                                if inner_member.isfile():
                                                    base = os.path.basename(inner_member.name)
                                                    extracted_name = os.path.join(temp_folder, f'{base}_{device_name}.txt')
                                                    with open(extracted_name,'wb') as f:
                                                        f.write(inner_tgz.extractfile(inner_member).read())
                                                    found_files.append(extracted_name)
                                                    update_log(f'     {color.GREEN}Complete{color.RESET} ({extracted_name})')
                                                    foundtgz = True
                    elif ".zip" in filename:
                        #BDOS csv file
                        update_log(f"Processing {file_path}")
                        with zipfile.ZipFile(file_path, 'r') as z:
                            for inner_file in z.namelist():
                                if inner_file.lower().endswith('.csv'):
                                    update_log(f'    Opening {inner_file}...', newline=False)
                                    with z.open(inner_file) as csv_file:
                                        text_file = io.TextIOWrapper(csv_file, encoding='utf-8')
                                        update_log(f'     \033[92mComplete\033[0m')
                                        dp_list_temp, this_epoch_from_time, this_epoch_to_time, new_csv_attack_data = data_parser.parse_csv(text_file)
                                        dp_list_ip.update(dp_list_temp)
                                        
                                        #Merge new_csv_attack_data into csv_attack_data
                                        #new_csv_attack_data = {"Destination IP Address": {"1.2.3.4": "15", "Multiple": "25333", "5.6.7.8": "7"},"Other Thing": {"2.3.4.5": "22", "3.4.5.6": "100"}}
                                        for key, values in new_csv_attack_data.items():
                                            if key != 'topN':
                                                inner = csv_attack_data.setdefault(key, {})
                                                for index, innerval in values.items():
                                                    inner[index] = int(inner.get(index, 0)) + int(innerval)
                                            else:
                                                #Key = topN
                                                topN_dest = csv_attack_data.setdefault('topN', {})
                                                for topN_key, topN_values in values.items():
                                                    inner = topN_dest.setdefault(topN_key, {})
                                                    for index, innerval in topN_values.items():
                                                        inner[index] = int(inner.get(index, 0)) + int(innerval)

                                        if 'epoch_from_time' not in locals() or this_epoch_from_time < epoch_from_time:
                                            epoch_from_time = int(this_epoch_from_time)
                                        if 'epoch_to_time' not in locals() or this_epoch_to_time > epoch_to_time:
                                            epoch_to_time = int(this_epoch_to_time)
                                        foundzip = True
                                        break
                            else:
                                update_log(f"WARNING: CSV not found in {file_path}")
                    else:
                        update_log(f"Notice: file {filename} in {manual_folder} does not end in .zip or .tar.gz and will be ignored")
                if not foundzip:
                    update_log(f"{color.YELLOW}Warning:{color.RESET} Forensics with attack details file not found.")
                    update_log("  Including forensics with attack details .zip files in the ./Manual/ folder will enhance the report.")
                if not foundtgz:
                    update_log(f"{color.RED}Error:{color.RESET} DefensePro Support file not found!")
                    update_log("Please place at least one DefensePro Support .tar.gz file and forensics with attack details .zip file in the ./Manual/ folder.")
                    update_log("The script will now exit.")
                    exit(0)
            else:
                #manual folder doesn't exist! Create it and exit
                os.makedirs(manual_folder)
                update_log(f"{color.RED}Error{color.RESET} The ./Manual/ folder did not exist and has been created for you.")
                update_log("Please place at least one DefensePro Support .tgz file and forensics with attack details .zip file in the ./Manual/ folder.")
                update_log("The script will now exit.")
                exit(0)
            #end of manual/offline file processing
            #Sort the attack data 
            for outer_key, inner_dict in csv_attack_data.items():
                if outer_key != 'topN':
                    csv_attack_data[outer_key] = dict(sorted(inner_dict.items(), key=lambda item: int(item[1]) if str(item[1]).isdigit() else -1, reverse=True))
                else:
                    for topN_key, topN_dict in inner_dict.items():
                        csv_attack_data['topN'][topN_key] = dict(sorted(topN_dict.items(), key=lambda item: int(item[1]) if str(item[1]).isdigit() else -1, reverse=True))
        else:
            #Not manual mode
            update_log("Beginning data collection")
            #Connect to Vision (instantiate v as a logged in vision instance. This will prompt a user for credentials)
            v = clsVision.clsVision()

            #Get start time and end time from the user input
            epoch_from_to_time_list = collector.prompt_user_time_period()
            epoch_from_time = epoch_from_to_time_list[0]
            epoch_to_time = epoch_from_to_time_list[1]
            from_month = epoch_from_to_time_list[2]
            start_year = epoch_from_to_time_list[3]
            to_month = epoch_from_to_time_list[4] if len(epoch_from_to_time_list) == 5 else None        

            #Prompt user for a list of DefensePros
            device_ips, dp_list_ip = collector.user_selects_defensePros(v)

            policies = {}
            args_used = False
            for ip in device_ips:
                ip = ip.strip()
                if args:
                    policy_input = args.pop(0).strip()
                    args_used = True
                else:
                    if len(sys.argv) == 1: #Only prompt if script is run without arguments. Length of 1 is 0 user arguments.
                        try:
                            policy_data = v.getDPPolicies(ip)['rsIDSNewRulesTable']
                            policy_names = ', '.join(policy['rsIDSNewRulesName'] for policy in policy_data)
                        except:
                            policy_names = "<unavailable>"
                        print(f"\nPlease enter the policy names for {dp_list_ip[ip]['name']} ({ip}), separated by commas")
                        print(f"    Available policies: ")
                        print(f"        {policy_names}")
                        policy_input = input(f"Policies (leave blank for All Policies): ").strip()
                    else:
                        #Args have been used elsewhere but no args have been specified for policies. Default to no filter.
                        policy_input = ""
                if policy_input:
                    policies[ip] = [policy.strip() for policy in policy_input.split(',')]

            #Get attack data
            attack_data = collector.get_attack_data(epoch_from_time, epoch_to_time, v, device_ips, policies, dp_list_ip)

            #Save the formatted JSON to a file
            with open(temp_folder + 'response.json', 'w') as file:
                json.dump(attack_data, file, indent=4)
            update_log("Response saved to response.json")

            #get bdos attack log from Defensepros
            found_files = sftp_module.get_attack_log(v, device_ips, from_month, start_year, to_month)
            update_log(f"Files found: {found_files}")
            #End automatic data collection

        #Done with data collection. Start processing       
        syslog_ids, syslog_details = data_parser.parse_response_file()
        #print(syslog_details)
        all_results = {}

        for file in found_files:
            #file_path = os.path.join(temp_folder, file)
            update_log(f"Processing file for BDoS attack logs: {file}")
            result = data_parser.parse_log_file(file, syslog_ids)
            all_results.update(result)
            #print(f"Result for {file}: {result}")
        #
        # print(all_results)
        categorized_logs = data_parser.categorize_logs_by_state(all_results)
        state_6_logs = data_parser.extract_state_6_footprints(all_results)
        #print(state_6_logs) 
        metrics = data_parser.calculate_attack_metrics(categorized_logs)
        
        for syslog_id in syslog_ids:
            if syslog_id in metrics and syslog_id in state_6_logs:
                syslog_details[syslog_id].update(metrics[syslog_id])
                syslog_details[syslog_id].update(state_6_logs[syslog_id])
                #print(syslog_details)
        # Calculate top BPS and PPS using html_data.get_top_n
        top_by_bps, top_by_pps, unique_protocols, count_above_threshold = data_parser.get_top_n(syslog_details, topN, threshold_gbps=1)
        for attack in top_by_bps + top_by_pps:
            dev = dp_list_ip.get(attack[1].get('Device IP', ''), {})
            attack[1]['Device Name'] = dev.get('name', 'N/A') if isinstance(dev, dict) else 'N/A'
            
        with open(temp_folder + 'TopMetrics.json', 'w') as file:
            json.dump({
                'top_by_bps': top_by_bps,
                'top_by_pps': top_by_pps,
                'unique_protocols': unique_protocols,
                'count_above_threshold': count_above_threshold
            }, file, ensure_ascii=False, indent=4)

        if not common_globals['Manual Mode']:#Make sure we're not in manual mode
            print("Retrieving sample data")
            bps_data, pps_data, unique_ips_bps, unique_ips_pps, deduplicated_sample_data, combined_unique_samples = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        else:
            bps_data, pps_data, unique_ips_bps, unique_ips_pps, deduplicated_sample_data, combined_unique_samples = None, None, None, None, None, None
        #print(combined_unique_samples)

        with open(temp_folder + 'SampleData.json', 'w') as file:
            json.dump({
                'bps_data': bps_data,
                'pps_data': pps_data,
                'unique_ips_bps': unique_ips_bps,
                'unique_ips_pps': unique_ips_pps,
                'deduplicated_sample_data': deduplicated_sample_data,
                'combined_unique_samples': combined_unique_samples
            }, file, ensure_ascii=False, indent=4)

        #print(metrics)
        #for each attack in syslog_details, check if ['graph'] is set to true. Graph is set to true for top_n graphs in the data_parser module.
        attack_graph_data = {}
        if not common_globals['Manual Mode']: #Make sure we're not in manual mode
            for syslogID, details in syslog_details.items():
                if details.get('graph', False):
                    attackData = v.getRawAttackSSH(details['Attack ID'])
                    if len(attackData.get('data',"")) > 2:
                        attackData['metadata'] = {
                            'DefensePro IP':details['Device IP'],
                            'DefensePro Name': dp_list_ip.get(details.get('Device IP',''),{}).get('name','N/A'),
                            'Policy':details['Policy']
                            }
                        attack_graph_data.update({details['Attack Name'].replace(' ','_') + '_' + details['Attack ID']: attackData})
        with open(temp_folder + 'AttackGraphData.json', 'w', encoding='utf-8') as file:
            json.dump(attack_graph_data, file, ensure_ascii=False, indent=4)

        #Get the overall attack rate graph data for the specified time period
        if not common_globals['Manual Mode']:#Make sure we're not in manual mode
            selected_devices = []
            if len(device_ips) > 0:
                for ip in device_ips:
                    selected_devices.append({'deviceId': ip, 'networkPolicies': policies.get(ip, []), 'ports': []})
            rate_data = {
                'bps': v.getAttackRate(epoch_from_time, epoch_to_time, "bps", selected_devices),
                'pps': v.getAttackRate(epoch_from_time, epoch_to_time, "pps", selected_devices)
                }
        else:
            rate_data = {}

        #Save the raw attack rate graph data to a file
        with open(temp_folder + 'BandwidthGraphData.json', 'w', encoding='utf-8') as file:
            json.dump(rate_data, file, ensure_ascii=False, indent=4)
        
        #Save a file with the details of the current run.
            #altenate datetime format .strftime('%a, %d %b %Y %H:%M:%S %Z')
        if not common_globals['Manual Mode']:#Make sure we're not in manual mode
            cc_details = f"\n<strong>Vision / Cyber Controller IP:</strong> {v.ip}"
            dp_details = f"""<strong>DPs:</strong> {", ".join(f"{dp_list_ip.get(ip, {}).get('name', 'N/A')}({ip})" for ip in device_ips if ip in dp_list_ip) or 'None'}"""
        else:
            cc_details = ""
            ##unsorted
            #dp_details = f"""DPs: {', '.join(f"{entry.get('name', 'N/A')}({ip})" for ip, entry in dp_list_ip.items()) or 'None'}"""
            ##sort by name
            #dp_details = f"""DPs: {', '.join(f"{entry.get('name', 'N/A')}({ip})" for ip, entry in sorted(dp_list_ip.items(), key=lambda item: item[1].get('name', '')) ) or 'None'}"""
            #sort by ip
            dp_details = f"""<strong>DPs:</strong>{'<span style="display:inline-block; padding-left:2em; text-indent:0;"">' if len(dp_list_ip) > 4 else ''}{', '.join(f"{entry.get('name', 'N/A')}({ip})" for ip, entry in sorted(dp_list_ip.items(), key=lambda item: ipaddress.ip_address(item[0])) ) or 'None'}{'</span>' if len(dp_list_ip) > 4 else ''}"""
            
            # policies = ""
            
            # unique_policies = set()
            # for content in dp_list_ip.values():
            #     unique_policies.update(content.get("policies", []))

            # policies += f"{', '.join(sorted(unique_policies))}\n"
            # Build: policy -> [IPs...]
            policy_to_ips = defaultdict(list)
            for ip, entry in dp_list_ip.items():
                for policy in entry.get("policies", []):
                    policy_to_ips[policy].append(ip)

            # Render HTML with IPs sorted numerically and values HTML-escaped
            policies = ", ".join(
                f'<span title="{html.escape(", ".join(sorted(ips, key=lambda x: ipaddress.ip_address(x))))}">'
                f'{html.escape(policy)}</span>'
                for policy, ips in sorted(policy_to_ips.items(), key=lambda kv: kv[0].casefold())
            )
        if len(common_globals['unavailable_devices']) > 0:
            unavailables = f"<strong>Unavailable DPs:</strong> {', '.join(common_globals['unavailable_devices'])}\n"
        else:
            unavailables = ""
        execution_statistics=f"""\
<strong>Top {topN} Attacks by BPS and PPS</strong>
<strong>Start Time:</strong> {datetime.datetime.fromtimestamp(epoch_from_time/1000, tz=datetime.timezone.utc).strftime(output_time_format)} 
<strong>End Time:</strong> {datetime.datetime.fromtimestamp(epoch_to_time  /1000, tz=datetime.timezone.utc).strftime(output_time_format)} {cc_details}
{dp_details}{unavailables}
<strong>Policies:</strong> {"All" if len(policies) == 0 else policies}"""
        #old: DPs: {', '.join(f"{dp_list_ip.get(attack[1].get(device, {}).get('name', 'N/A'), 'N/A')} ({device})" for device in device_ips)}

        execution_json = {
                            'header':execution_statistics,
                            'report_timeframe':{
                                'start_epoch':epoch_from_time,
                                'end_epoch':epoch_to_time
                                }
                          }
        with open(temp_folder + 'ExecutionDetails.json', 'w', encoding='utf-8') as file:
            json.dump(execution_json, file, ensure_ascii=False, indent=4)
            #file.write(execution_statistics)
        update_log("Data collection complete")
        ##############################End of Collect_Data section##############################


    if parse_data:
        update_log("Generating output:")
        # Load saved metrics
        
        try:
            with open(temp_folder + 'TopMetrics.json') as file:
                top_metrics = json.load(file)
        except FileNotFoundError:
            update_log(f"{temp_folder + 'TopMetrics.json'} not found! Unable to continue.")
            exit(0)
        top_by_bps = top_metrics['top_by_bps']
        top_by_pps = top_metrics['top_by_pps']
        unique_protocols = top_metrics['unique_protocols']
        count_above_threshold = top_metrics['count_above_threshold']

        # Read sample data from JSON file
        with open(temp_folder + 'SampleData.json') as file:
            sample_data = json.load(file)
        bps_data = sample_data['bps_data']
        pps_data = sample_data['pps_data']
        unique_ips_bps = sample_data['unique_ips_bps']
        unique_ips_pps = sample_data['unique_ips_pps']
        deduplicated_sample_data = sample_data['deduplicated_sample_data']
        combined_unique_samples = sample_data['combined_unique_samples']

        #Create a set of the topN attack IDs
        top_n_attack_ids = set()
        for attack in top_metrics['top_by_bps']:
            top_n_attack_ids.add(attack[1]['Attack ID'])
        for attack in top_metrics['top_by_pps']:
            top_n_attack_ids.add(attack[1]['Attack ID'])

        #Rename old files to new name - needed for old version offline mode compatability
        for old_name, new_name in [('AttackGraphsData.json','AttackGraphData.json'),
                                   ('TopGraphsData.json','BandwidthGraphData.json')]:
            old_path = os.path.join(temp_folder, old_name)
            new_path = os.path.join(temp_folder, new_name)
            if os.path.exists(old_path):
                os.rename(old_path, new_path)
                update_log(f"Renamed '{old_path}' to '{new_path}'")

        #Load graph data from JSON file
        with open(temp_folder + 'AttackGraphData.json') as data_file:
            attack_graph_data = json.load(data_file)
        with open(temp_folder + 'BandwidthGraphData.json') as data_file:
            rate_data = json.load(data_file)
        with open(temp_folder + 'response.json') as data_file:
            attack_data = json.load(data_file)

        #Open executionStatistics.txt and include the contained information in the header
        update_log("    Generating header")
        stats_for_header = ""
        execution_details = {}
        
        if os.path.isfile(temp_folder + 'ExecutionDetails.json'):
            with open(temp_folder + 'ExecutionDetails.json', "r") as file:
                execution_details = json.load(file)
                for line in execution_details['header'].splitlines():
                    stats_for_header += f"<p>{line.strip()}</p>\n"
        else:
            with open(temp_folder + 'ExecutionDetails.txt', "r") as file:
                for line in file:
                    stats_for_header += f"<p>{line.strip()}</p>\n"

        final_HTML = html_header.getHeader(stats_for_header) + html_graphs.graphPrerequisites()

        update_log("    Generating attack summary")
        html_summary = '\n<h2 style="text-align: center;">Attack Summary</h2>'
        html_summary += html_attack_summary.getSummary(top_metrics, rate_data, attack_graph_data, deduplicated_sample_data, attack_data, top_n_attack_ids, csv_attack_data, execution_details['report_timeframe']) 
        final_HTML += html_summary

        #Create the two graphs at the top of the HTML file
        final_HTML += "\n<h2>Traffic Bandwidth</h2>"
        update_log("    Generating first graphs")
        if len(rate_data) > 0:
            final_HTML += html_graphs.createTopGraphsHTML(rate_data['bps'], rate_data['pps'])

        #Create pie charts
        update_log("    Generating pie charts")
        final_HTML += html_graphs.createPieCharts(attack_data, top_n_attack_ids)

        #top_by_bps, top_by_pps, unique_protocols, count_above_threshold = html_data.get_top_n(syslog_details, topN, threshold_gbps=1)
        #bps_data, pps_data = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        # Call the function to get all sample data and unique source IPs
        #bps_data, pps_data, unique_ips_bps, unique_ips_pps = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        #bps_data, pps_data, unique_ips_bps, unique_ips_pps, deduplicated_sample_data, combined_unique_samples = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        #print(combined_unique_samples)
        #print("BPS Data:", bps_data)
        #print("PPS Data:", pps_data)
        update_log("    Generating Tables")
        attackdataHTML = html_data.generate_html_report(top_by_bps, top_by_pps, unique_protocols, count_above_threshold, bps_data, pps_data, unique_ips_bps, unique_ips_pps, deduplicated_sample_data, topN, threshold_gbps=1)
        final_HTML += attackdataHTML 

        #add a button to popup IP reputation info when clicked.
        
        if config.get("Reputation","use_abuseipdb", False) or config.get("Reputation","use_ipqualityscore", False):
            if deduplicated_sample_data != None:
                update_log("    Generating Reputation HTML")
                final_HTML +=  html_ip_reputation.getIpReputationHTML(deduplicated_sample_data)

        if len(attack_graph_data) > 0:
            #Create dynamic graph combining all attacks into one graph.
            final_HTML += "\n<h2>Combined Chart</h2>"
            update_log("    Generating combined charts")
            final_HTML += "\n" + html_graphs.createCombinedChart("Combined_Chart", attack_graph_data)


        #Add an individual graph for each attack
        update_log("    Generating per-attack graphs")
        for attackID, data in attack_graph_data.items():
            try:
                #inalHTML += html_graphs.createChart(attackID, data, epoch_from_time, epoch_to_time)
                final_HTML += html_graphs.createChart(attackID, data)
            except:
                update_log(f"Error graphing attackID '{attackID}':")
                #traceback.print_exc()
                error_message = traceback.format_exc()
                indented_error_message = "\n".join("\t" + line for line in error_message.splitlines())
                update_log(indented_error_message)

        endHTML = "</body></html>"
        final_HTML += endHTML

        update_log("    Saving output html file.")
        html_file_path = os.path.join(temp_folder, 'DP-Attack-Analyzer_Report.html')
        with open(html_file_path, 'w', encoding="utf-8") as file:
            file.write(final_HTML)
        update_log(f"    Success! The file has been saved to: {html_file_path}")
        
        #Script execution complete. Compress and delete the output folder
        update_log("Compressing Output")
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zipf:
            for item in os.listdir(temp_folder): 
                item_path = os.path.join(temp_folder, item)
                zipf.write(item_path, arcname=item)
            update_log(f"    {temp_folder} has been compressed to {output_file}")

        ##############################End of Parse_Data Section##############################

        ##############################Send email ############################################
        attack_count = 0
        for dp, data in attack_data.items():
            attack_count += len(data['data'])
        top_pps = 0
        top_bps = 0
        if len(top_by_pps) > 0:
            top_pps = top_by_pps[0][1].get('Max_Attack_Rate_PPS_formatted', 0)
        if len(top_by_bps) > 0:
            top_bps = top_by_bps[0][1].get('Max_Attack_Rate_Gbps', 0)
        if config.get("Email","send_email",False):
            send_email.send_email(['./Temp/DP-Attack-Analyzer_Report.html', output_file], attack_count, top_pps, top_bps, html_summary)
        if common_globals['unavailable_devices']:
            update_log(f"Execution complete with warnings: The following devices were unreachable {', '.join(common_globals['unavailable_devices'])}")
        else:
            update_log("Execution completed")