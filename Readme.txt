#DP-Attack-Story

# Owners

	Prateek Vishwanath - prateek.vishwanath@radware.com
	Steve Harris - steven.harris@radware.com
	Egor Egorov - egore@radware.com

# About

	This script will pull DefensePro attack details through Vision/CyberController and from DP directly. It uses these details to generate a user-friendly report.

# Prerequisites

	This script requires the requests, paramiko, and pysftp libraries. 'pip install requests paramiko pysftp' to download them.
	You will need to know your Vision/CC username, password and root password. You will need to know the username and password for every defensepro you are pulling data from.
	DefensePro version at least 8.32
	DefensePro must have BDOS attack lifecycle logging enabled: 'system internal security bdos attack-log-status set enable'. 'Unknown command' means your DefensePro must be upgraded.

# How to run
	Optional:
		Modify the Top_N variable in config.ini to adjust the number of events that appear in the final report. Default: 10.

	Without Arguments:
		1. Run the script 
			python main.py
		2. Enter Vision/CC login credentials
		3. Enter start and end times
		4. (optional - press enter to skip) Select target DPs 
		5. (optional - press enter to skip) Enter a comma separated list of policies for each DP.
		6. View your report under .\Output\

	With Arguments:
		1. Run the script with the -h argument for details.
			python main.py -h

		At the time of updating this section of the readme (30 October 2024), the output of python main.py -h is:
			Script syntax:
			python main.py [--environment <name>] [--offline | --use-cached | <Vision_IP Username Password RootPassword>] <Time-Range> <DefensePro-list> <First-DP-policy-list> <Second-DP-policy-list> <X-DP-policy-list>...
				***Note: The order of arguments is important and must not deviate from the above template.***
				--environment, -e      Optional: Specify an environment. This is used for output naming. Script will use 'Default' if not specified.
				--offline, -o         Instead of connecting to a live Vision appliance, use cached data stored in ./Temp/ for generating DP-Attack-Story_Report.html
				--use-cached, -c      Use information stored in 'config.ini' for Vision IP, username, and password
				<time-range> options:
					--hours, -h <number_of_hours>                      Select data from the past X hours.
					--date-range, -dr <start_datetime> <end_datetime>  Select data between two specified dates.
					--epoch-range, -er <epoch_start> <epoch_end>       Select data between two Unix epoch times.
					--previous-time-range, -p                          Use the cached time range from the last time the script was run.
				<defensepro-list>     Comma-separated list of DefensePro names or IP addresses (use '' for all).
				<policy-list>         Comma-separated list of policy names (use '' for all).
			Examples:
				python main.py -c --hours 3 DefensePro1,DefensePro2,192.168.1.20 DefensePro1_BdosProfile,DefensePro1_SynFloodProtection DP2_BdosProfile,DP2_SynFloodProtection DP3_Policy1
				python main.py 192.168.1.1 admin radware radware1 --epoch-range 859885200 859971600 '' ''
				python main.py --use-cached --date-range "11 Oct 2024 09:00:00" "11 Oct 2024 18:00:00" "DP1, DP2" "DP1_Policy1, DP1_Policy2" "DP2_Policy1, DP2_Policy2"

		** These arguments are subject to change. Don't trust the list on this page. They are only listed here to give you an idea of what options are available. **

		JSON launcher:
			The purpose of the json launcher is to run the script against multiple predefined environments in quick succession. It is run by calling 'python json_launcher.py'.
			json_launcher.py will automatically execute main.py with parameters based on the contents of launcher.json

			launcher.json format: 
				At it's top level it is a list. Each element contains a dictionary representing a separate execution of main.py [execution1details, execution2details, etc]
				The elements of each dictionary are:
					"environment" - String defining the environment name to be used for naming output files.
					"use_cached" - Boolean that identifies if cached credentials in config.ini should be used.
					"vision_ip", "vision_username", "vision_password", "vision_root_password" - Strings defining vision connection info.
					"time_range" - Dictionary containing two elements:
						"type" - String identifying the time range type. --hours, --date-range, --epoch-range, --previous-time-range are acceptable values. See 'main.py -h' for details.
						"value" - Varieant based on type specified. If selected type requires multiple inputs, place them in a list [StartTime, Endtime]
					"defensepros_policies" - Dictionary containing "defensepro" : "policies" pairs. Input a single space for the policy name to select 'All'
				See the included launcher.json.example for a sample.


# Version Control
	v0.17.0 - 31 January 2025 (Steve)
		Rewrote combined graph code.
			Datasets can now contan an arbitrary number of metadata lines that will be displayed in the onHover tooltip. 
			Currently: DefensePro IP, DefensePro Name, and Policy Name. More can be easily added on request.
		Added Changed 'Device IP' table column to 'Device Info'. It now includes Device Name
		Resolved an issue that occurrs when no attacks are present in specified time period.
	v0.16.7 - 9 January 2025 (Steve)
		Additional fix for very low traffic condition.
	v0.16.6 - 3 January 2025 (Prateek)
		Changed default exclude filter to "Memcached-Server-Reflect". See: [General] - ExcludeFilters. 
	v0.16.5 - 3 January 2025 (Steve + Prateek)
		hardcoded excluding packet anomalies and changed the use configurable exclude filter in ini file to be attack name based. See: [General] - ExcludeFilters. Default is "DOSS-DNS-Ref-L4-Above-3000"
	v0.16.4 - 3 January 2025 (Steve + Prateek)
		Added custom exclude filter option to ini file. See: [General] - ExcludeFilters. Default is "Anomalies,DOSShield"
	v0.16.3 - 31 December 2024 (Steve)
		Fixed a divide by zero condition that could occur during very low traffic conditions.
	v0.16.2 - 23 December 2024 (Prateek)
		Added functionality to ignore Packet Anomalies from the report (hardcoded)
	v0.16.1 - 19 December 2024 (Steve)
		The script now outputs to './Temp/'. The temp folder will be deleted at the beginning of each execution when the script is not run in offline mode.
		The contents of './Temp/' will be compressed to './Reports/<environment name>/<environment name>_%Y-%m-%d_%H.%M.%S.zip'
		<environment name> can be modified using the --environment runtime argument.
		Added environment name capability to json_launcher.py (example file updated accordingly)
		Added 'attack wave' section to Attack Summary. 
			By defaults attacks that occur within 5 minutes of a wave are grouped. This can be adjusted through config.ini [General]
		Corrected hardcoded path in sftp_module.py
		json_launcher now uses launcher.json file
		Minor visual improvements
		Improved logging
	v0.16.0 - 19 December 2024 (Egor)
		Added sending email option (user configurable).
	v0.15.1 - 14 November 2024 (Steve)
		Time range input now accepts UTC as an optional parameter to specify non-local timezone.
		Improved Vision/CC login error handling
		The 'Packet Anomalies' attack policy will be excluded from the Attack Summary attack timeframe.
		Misc minor Attack Summary improvements.
	v0.15.0 - 11 November 2024 (Steve)
		Config.ini now also supports using environmental variables. ini entries prefixed with a $ will be treated as environmental variables.
		Added Attack Summary section to the final attack report.
		Pie charts now only include data from topN attacks.
		Added '--offline' argument to run the script in offline mode and use data pulled during a previous run. 
			Only DP-Attack-Story_Report.html will be modified during an --offline run.
	v0.14.6 - 7 November 2024 (Prateek)
		Bug Fix related to BDoS lifecycle button
	v0.14.5 - 5 November 2024 (Prateek)
		Bug fix for JSON serializing.
	v0.14.4 - 5 November 2024 (Prateek)
		Restructred code for offline running.
		Modified BPS and PPS table to collect all BDoS data and display it in the collapsible 'BDOS Life Cycle' button
	v0.14.3 - 24 October 2024 (Prateek)
		Source IP list table fix.
		Added a table of aggregated sample data. 
	v0.14.2 - 22 October 2024 (Steve)
		Rolled back compressed file change.
	v0.14.1 - 22 October 2024 (Steve)
		Fixed a typo in common.py
	v0.14.0 - 22 October 2024 (Steve)
		Added support for running the script with predefined settings through launcher.json.
			Vision IP, Username, Password, and RootPassword support using OS Environmental variables. 
			If the first character is a $, the subsequent text will be treated as an environmental variable name.
		The script will now output to a unique temp folder each execution. 
		    The folder name is ./Output/<Year>-<Month>-<Day>_<Hour>.<Minute>.<Second>/
		    The script will then compress temp folder. 
			The compressed file will be saved to ./Output/<Year>-<Month>-<Day>_<Hour>.<Minute>.<Second>.tgz
			The temp folder will then be deleted.
			Compressing and deleting the temp folder can be disabled by setting 'Compress_Output = FALSE' in config.ini
		Config.ini now includes a Top_N value. Changing this number will change how many attacks are included in reported data.
		Added 2 pie charts comparing attack types by total bandwidth and packets.
		Moved Graph legends to top of graphs to accomodate hAxis label.
		Corrected label on first graph from BPS to KBPS
		Added Top_N label to top right of output html
		Fixed a typo in html_data.py.
	v0.13.0 - 21 October 2024 (Steve)
		Incorporated a 'Graph' button and a collapsible graph for every row of the attack tables.
		Added mini graph to attack tables. 
		    hAxis min and max values are currently set to the full time range. I might change this later based on user feedback.
		    Short attacks will appear as a vertical line. 
		    This approach aims to give users a quick view of when each attack occurred within the specified time range.
		Customizable graph overhaul.
		    Split into BPS and PPS graphs.
		    Checkboxes simplified to one per attack.
		    Checkboxes will display in multiple columns when there are many attacks.
		    Colors are maintained when checking and unchecking values.
		    Enabled animation.
	v0.12.2 - 17 October 2024 (Steve)
		Changed multiple print() statements to update_log() statements for more verbose logging.
		The script will now output each DefensePro's policy list when prompting user for per DP policy filters.
		Moved CSS out of html_data.py and into html_header.py
		Fixed several issues with arg inputs.
	v0.12.1 - 17 October 2024 (Prateek)
		Added a table to print all unique source IP addresses
		Added functionality to copy contents of the source IP address table
	v0.12.0 - 15 October 2024 (Steve)
		Quitting from manual date entry is now possible.
		The script can now be run using arguments. Arguments allow you to predefine input parameters to allow for scheduled execution. 
			'python main.py -h' for details.
			Please note: The order and format of arguments is likely to change. Do not set up recurring scheduled tasks until this feature is better tested.
		Changed our order of operations. Script now logs into vision prior to date selection.
	v0.11.3 - 9 October 2024 (Prateek)
		Added functionality to copy contents of sample data by column (eg: all Src IP, all Src Port)
		Attack Table Formatting: Removed underscores from "Max_Attack_Rate_BPS" and converted values to Gbps
		Attack Table Formatting: Removed underscores from "Max_Attack_Rate_PPS" and added comma separation in values for better readability
	v0.11.2 - 7 October 2024 (Steve)
		DefensePro name prompt is now case insensitive.
		Fixed error parsing manual date entries.
	v0.11.1 - 7 October 2024 (Egor)
		Added run.sh to gitignore
	v0.11.0 - 4 October 2024 (Steve)
		Code cleanup and refactoring.
		Added ability to quit manual date entry.
		Moved TopN definition to early in common.py.
		The same topN variable is now used throughout the script.
		The script will now accept DefensePro names (case sensitive) in addition to IPs.
		Added two time entry options. 'Manually enter epoch time' and 'Use time range from previous run'
		Renamed run.sh to run.sh.example
	v0.10.3 - 3 October 2024 (Prateek)
		Fixed color coding in table for above threshold attacks
	v0.10.2 - 3 October 2024 (Steve)
		Implemented a JavaScript function on the output html page to ensure that Google Charts displays times in UTC, compensating for automatic adjustments to the user's local time.
		Improved header formatting
		Header data is now populated
		Corrected typos in Readme.txt
	v0.10.1 - 30 September 2024 (Steve)
		Initial concept for a header.
	v0.10.0 - 1 October 2024 (Prateek)
		Added new feature to display sample data for the top N attacks 
	v0.9.8 - 26 September 2024 (Steve)
		Changed time format for first two graphs from date to datetime. onHover popup will now display the time as well as the date.
	v0.9.7 - 26 September 2024 (Prateek)
		Bug fix for Pagination during data collection
		Added Timezone (UTC) in attack report tables
		Modified wording for option to manually input timeframes
	v0.9.6.1
		Added run.sh to assist with running from a container
	v0.9.6 - 18 September 2024 (Prateek)
		Bug fix for LOW footprint strictness time calculation
		Separated functions for creating topN attacks in preparation for sample data collection
	v0.9.5 - 12 September 2024 (Prateek)
		Added enhancements to print BDoS lifecycle parsing for burst attacks accurately
		Added functionality to clear output folder before running the script
		Renamed "Syslog ID" in the output table as "BDOS Lifecycle log attack ID"
	v0.9.4 - 4 September 2024 (Prateek)
		Improved attack lifecycle calucation logic - transition between blocking and non-blocking states
		Cleaned unused libraries - mainly tabulate
	v0.9.3 - 4 September 2024 (Steve)
		Improved display of graph timestamps.
		We will now sort graph data received from vision prior to displaying it.
		Set option interpolateNulls: true for 'All Attacks' graph to account for some datasets containing null values when merged.
		Moved Vision log file to .\Output\ folder
		Increased verbosity of vision server logging.
	v0.9.2 - 28 August 2024 (Prateek)
		Added functionality to process different attack-id to syslog-id conversion
		Added AttackID to the HTML report
	v0.9.1 - 22 August 2024 (Steve)
		Will no longer include DefensePros in a 'FAILED' state in the list of available devices.
		Fixed potential issue where DP selection input is accepted when the user inputs a mix of valid and invalid IPs.
		Fixed device_ips "TypeError: 'int' object is not iterable"
	v0.9.0 - 21 August 2024 (Steve)
		Graph data now saves to a file.
		Data for combined graphs will now be filtered according to selected DPs and policies.
		Added error handling when entering a time range. Invalid entries will now prompt for a correction.
		Script will pull DefensePro CLI credentials from Vision instead of prompting user.
	v0.8.6 - 21 August 2024 (Prateek)
		added summary that displays attack vector for top n attacks
		added summary that displays x attacks are over "y" gbps
	v0.8.5 - 21 August 2024 (Steve)
		Added more robust error handling and reporting to graph operations. 
		Renamed output html file from graph.html to DP-Attack-Story_Report.html
	v0.8.4 - 21 August 2024 (Prateek)
		Added logic to ignore EAAF events.
	v0.8.3 - 15 August 2024 (Steve)
		Combined Graph: Added Attack Name to dataset names
		Combined Graph: Selecting a Both/Bps/Pps will now check/uncheck the appropriate boxes.
		Combined Graph: Data Points are now rounded to the nearest 15 seconds.
		Combined Graph: Ensured that Google Charts will always select a solid line of a unique color for each line when there are many datasets.
	v0.8.1 - 15 August 2024 (Steve)
		Fixed an error where graph_parser.py was overwritten.
	v0.8.0 - 15 August 2024 (Steve)
		Added 'Past X hours' option to time period selection.
		Changed deviceIP selection input so blank entry selects all instead of having to type 'All'
		Added graph for each attack ID.
		Added a graph that combines all Attack IDs with checkboxes to select individual attacks. 
		Updated launch.json for easier troubleshooting
	v0.7.0 - (Prateek)
	v0.6.0 - 8 July 2024 (Steve)
		Added graph functionality
		Added error handling for missing libraries
	v0.5.0 - 26 June 2024 - Restructure code (Egor)
		Added main.py
		Added collector.py
		Added parser.py (need to qa, do not have data to test)
	v0.4.1 - 26 June 2024 (Steve)
		Output has been moved to the folder ./Output/
		Removed commented lines after reviewing with the team.
	v0.4.0 - 25 June 2024 - Initial Dev Build (Steve)
		Merged my clsVision module into Prateek's code.

