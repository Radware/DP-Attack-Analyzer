import os
import traceback
import json
import datetime
#import tarfile
import zipfile

#internal modules
import clsVision
import collector
import data_parser
import html_attack_summary
import html_data
import html_graphs
import html_header
import sftp_module
import send_email

#Default options such as topN and output folder are now stored in common.py. 
from common import *

#epoch_from_time = 1729479600000
#epoch_to_time = 1729486800000

collect_data=True
parse_data=True
if __name__ == '__main__':
    if collect_data and (not args or (args[0].lower() != '--offline' and args[0] != '-o')):
        update_log("Beginning data collection")
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
                    update_log(f"Failed to delete {file_path}. Reason: {e}")
            pass
        else:
            # Create the temp folder if it doesn't exist
            os.makedirs(temp_folder)
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
                    policy_data = v.getDPPolicies(ip)['rsIDSNewRulesTable']
                    policy_names = ', '.join(policy['rsIDSNewRulesName'] for policy in policy_data)
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
       
        syslog_ids, syslog_details = data_parser.parse_response_file(v)
        #print(syslog_details)
        all_results = {}

        for file in found_files:
            file_path = os.path.join(temp_folder, file)
            update_log(f"Processing file for BDoS attack logs: {file}")
            result = data_parser.parse_log_file(file_path, syslog_ids)
            
            all_results.update(result)
            #print(f"Result for {file}: {result}")
        #print(all_results)
        categorized_logs = data_parser.categorize_logs_by_state(all_results)
        #print(categorized_logs) 
        metrics = data_parser.calculate_attack_metrics(categorized_logs)
        for syslog_id in syslog_ids:
            if syslog_id in metrics:
                syslog_details[syslog_id].update(metrics[syslog_id])

        # Calculate top BPS and PPS using html_data.get_top_n
        top_by_bps, top_by_pps, unique_protocols, count_above_threshold = html_data.get_top_n(syslog_details, topN, threshold_gbps=1)
        for attack in top_by_bps + top_by_pps:
            attack[1]['Device Name'] = dp_list_ip.get(attack[1].get('Device IP', 'N/A'),'N/A')['name']
        with open(temp_folder + 'TopMetrics.json', 'w') as file:
            json.dump({
                'top_by_bps': top_by_bps,
                'top_by_pps': top_by_pps,
                'unique_protocols': unique_protocols,
                'count_above_threshold': count_above_threshold
            }, file, ensure_ascii=False, indent=4)

        bps_data, pps_data, unique_ips_bps, unique_ips_pps, deduplicated_sample_data, combined_unique_samples = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        print(combined_unique_samples)

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
        for syslogID, details in syslog_details.items():
            if details.get('graph', False):
                attackData = v.getRawAttackSSH(details['Attack ID'])
                if len(attackData.get('data',"")) > 2:
                    attackData['metadata'] = {
                        'DefensePro IP':details['Device IP'],
                        'DefensePro Name':dp_list_ip[details['Device IP']]['name'],
                        'Policy':details['Policy']
                        }
                    attack_graph_data.update({details['Attack Name'].replace(' ','_') + '_' + details['Attack ID']: attackData})
        with open(temp_folder + 'AttackGraphsData.json', 'w', encoding='utf-8') as file:
            json.dump(attack_graph_data, file, ensure_ascii=False, indent=4)

        #Get the overall attack rate graph data for the specified time period
        selectedDevices = []
        if len(device_ips) > 0:
            for ip in device_ips:
                selectedDevices.append({'deviceId': ip, 'networkPolicies': policies.get(ip, []), 'ports': []})
        rate_data = {
            'bps': v.getAttackRate(epoch_from_time, epoch_to_time, "bps", selectedDevices),
            'pps': v.getAttackRate(epoch_from_time, epoch_to_time, "pps", selectedDevices)
            }
        #Save the raw attack rate graph data to a file
        with open(temp_folder + 'TopGraphsData.json', 'w', encoding='utf-8') as file:
            json.dump(rate_data, file, ensure_ascii=False, indent=4)
        
        #Save a file with the details of the current run.
            #altenate datetime format .strftime('%a, %d %b %Y %H:%M:%S %Z')
        executionStatistics=f"""\
Top {topN} Attacks by BPS and CPS
Start Time: {datetime.datetime.fromtimestamp(epoch_from_time/1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S %Z')}
End Time: {datetime.datetime.fromtimestamp(epoch_to_time  /1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S %Z')}
Vision / Cyber Controller IP: {v.ip}
DPs: {', '.join(device_ips)}
Unavailable DPs: {', '.join(common_globals['unavailable_devices'])}
Policies: {"All" if len(policies) == 0 else policies}"""
        
        with open(temp_folder + 'ExecutionDetails.txt', 'w', encoding='utf-8') as file:
            file.write(executionStatistics)
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

        #Load graph data from JSON file
        with open(temp_folder + 'AttackGraphsData.json') as data_file:
            attack_graph_data = json.load(data_file)
        with open(temp_folder + 'TopGraphsData.json') as data_file:
            rate_data = json.load(data_file)
        with open(temp_folder + 'response.json') as data_file:
            attack_data = json.load(data_file)

        #Open executionStatistics.txt and include the contained information in the header
        update_log("Generating header")
        statsForHeader = ""
        with open(temp_folder + 'ExecutionDetails.txt', "r") as file:
            for line in file:
                statsForHeader += f"<p>{line.strip()}</p>\n"

        finalHTML = html_header.getHeader(statsForHeader) + html_graphs.graphPrerequesites()

        update_log("Generating attack summary")
        htmlSummary = '\n<h2 style="text-align: center;">Attack Summary</h2>'
        htmlSummary += html_attack_summary.getSummary(top_metrics, rate_data, attack_graph_data, deduplicated_sample_data, attack_data, top_n_attack_ids) 
        finalHTML += htmlSummary

        #Create the two graphs at the top of the HTML file
        finalHTML += "\n<h2>Traffic Bandwidth</h2>"
        update_log("Generating first graphs")
        graphHTML = html_graphs.createTopGraphsHTML(rate_data['bps'], rate_data['pps'])
        finalHTML += graphHTML

        #Create pie charts
        update_log("Generating pie charts")
        finalHTML += html_graphs.createPieCharts(attack_data, top_n_attack_ids)

        #top_by_bps, top_by_pps, unique_protocols, count_above_threshold = html_data.get_top_n(syslog_details, topN, threshold_gbps=1)
        #bps_data, pps_data = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        # Call the function to get all sample data and unique source IPs
        #bps_data, pps_data, unique_ips_bps, unique_ips_pps = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        #bps_data, pps_data, unique_ips_bps, unique_ips_pps, deduplicated_sample_data, combined_unique_samples = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        #print(combined_unique_samples)
        #print("BPS Data:", bps_data)
        #print("PPS Data:", pps_data)
        update_log("Generating Tables")
        attackdataHTML = html_data.generate_html_report(top_by_bps, top_by_pps, unique_protocols, count_above_threshold, bps_data, pps_data, unique_ips_bps, unique_ips_pps, deduplicated_sample_data, topN, threshold_gbps=1)
        finalHTML += attackdataHTML 

        #Create dynamic graph combining all attacks into one graph.
        finalHTML += "\n<h2>Combined Chart</h2>"
        update_log("Generating combined charts")
        #try:
        finalHTML += "\n" + html_graphs.createCombinedChart("Combined_Chart", attack_graph_data)
        #finalHTML += "\n<h2>Combined Chart(old)</h2>"
        #finalHTML += html_graphs.createCombinedChartOld("Custom", attack_graph_data) 
        #except:
        #    update_log("Unexpected createCombinedChart() error: ")
        #    error_message = traceback.format_exc()
        #    indented_error_message = "\n".join("\t" + line for line in error_message.splitlines())
        #    update_log(indented_error_message)

        #Charts per attack ID are removed from bottom of the output. To readd, uncomment the follwoing line and remove display: none; from the output of createChart()
        #finalHTML += "\n<h2>Charts per attack ID</h2>"  
        update_log("Generating per-attack graphs")
        #Add an individual graph for each attack
        for attackID, data in attack_graph_data.items():
            try:
                #inalHTML += html_graphs.createChart(attackID, data, epoch_from_time, epoch_to_time)
                finalHTML += html_graphs.createChart(attackID, data)
            except:
                update_log(f"Error graphing attackID '{attackID}':")
                #traceback.print_exc()
                error_message = traceback.format_exc()
                indented_error_message = "\n".join("\t" + line for line in error_message.splitlines())
                update_log(indented_error_message)

        endHTML = "</body></html>"
        finalHTML += endHTML

        update_log("Creating output file.")
        html_file_path = os.path.join(temp_folder, 'DP-Attack-Story_Report.html')
        with open(html_file_path, 'w') as file:
            file.write(finalHTML)
        update_log(f"Graphs and metrics saved to {html_file_path}")
        
        #Script execution complete. Compress and delete the output folder
        update_log("Compressing Output")
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        # with tarfile.open(output_file, "w:gz") as tar:
        #     for item in os.listdir(temp_folder):  # Iterate over the contents of temp_folder
        #         item_path = os.path.join(temp_folder, item)
        #         tar.add(item_path, arcname=item)  # Add each item with its base name
        #     print(f"{temp_folder} has been compressed to {output_file}")
        with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zipf:
            for item in os.listdir(temp_folder): 
                item_path = os.path.join(temp_folder, item)
                zipf.write(item_path, arcname=item)
            update_log(f"{temp_folder} has been compressed to {output_file}")
        # if os.path.exists(temp_folder):
        #     # Remove all files in the output folder
        #     for filename in os.listdir(temp_folder):
        #         file_path = os.path.join(temp_folder, filename)
        #         try:
        #             if os.path.isfile(file_path):
        #                 os.unlink(file_path)
        #         except Exception as e:
        #             update_log(f"Failed to delete {file_path}. Reason: {e}")
        #     try:
        #         os.rmdir(temp_folder)
        #         print(f"{temp_folder} has been deleted.")
        #     except FileNotFoundError:
        #         print(f"{temp_folder} does not exist.")
        #     except OSError:
        #         print(f"{temp_folder} is not empty or cannot be deleted.")

        ##############################End of Parse_Data Section##############################

        ##############################Send email ############################################
        attack_count = 0
        for dp, data in attack_data.items():
            attack_count += len(data)
        top_pps = top_by_pps[0][1]['Max_Attack_Rate_PPS_formatted']
        top_bps = top_by_bps[0][1]['Max_Attack_Rate_Gbps']
        if config.get("Email","send_email","False").upper() == "TRUE":
            send_email.send_email(output_file, attack_count, top_pps, top_bps, htmlSummary)
        if common_globals['unavailable_devices']:
            update_log(f"Execution complete with warnings: The following devices were unreachable {', '.join(common_globals['unavailable_devices'])}")
        else:
            update_log("Execution completed")