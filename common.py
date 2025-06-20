import configparser
import datetime
import sys
import re
import os

args = sys.argv.copy()
script_filename = args.pop(0)
script_start_time = datetime.datetime.now()
common_globals = {'unavailable_devices':[]}

temp_folder = "./Temp/"
log_file = temp_folder + "Attack-Analyzer.log"
if not os.path.exists(temp_folder):
    os.makedirs(temp_folder)

log_cache = ""
log_state = 0
def update_log(message):
    global log_cache, log_state
    print(message)

    with(open(log_file,"w" if log_state == 1 else "a")) as file:
        log_entry = f"[{datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')}] {message}\n"
        log_cache += log_entry
        if log_state == 1:
            file.write(log_cache)
            log_state = 2
        else:    
            file.write(log_entry)

update_log(f"args: {args}")

if len(args) > 0 and (args[0].startswith('-h') or args[0].startswith('?') or args[0].startswith('--h')):
    #Display help message and exit
    print("  Script syntax:")
    print("  python main.py [--environment <name>] [--offline | --use-cached | <Vision_IP Username Password RootPassword>] <Time-Range> <DefensePro-list> <First-DP-policy-list> <Second-DP-policy-list> <X-DP-policy-list>...")
    print("    ***Note: The order of arguments is important and must not deviate from the above template.***")
    print("    --environment, -e      Optional: Specify an environment. This is used for output naming. Script will use 'Default' if not specified.")
    print(f"    --offline, -o         Instead of connecting to a live Vision appliance, use cached data stored in {temp_folder} for generating DP-Attack-Analyzer_Report.html")
    print("    --use-cached, -c      Use information stored in 'config.ini' for Vision IP, username, and password")
    print("    <time-range> options:")
    print("        --hours, -h <number_of_hours>                      Select data from the past X hours.")
    print("        --date-range, -dr <start_datetime> <end_datetime>  Select data between two specified dates.")
    print("        --epoch-range, -er <epoch_start> <epoch_end>       Select data between two Unix epoch times.")
    print("        --previous-time-range, -p                          Use the cached time range from the last time the script was run.")
    print("    <defensepro-list>     Comma-separated list of DefensePro names or IP addresses (use '' for all).")
    print("    <policy-list>         Comma-separated list of policy names (use '' for all).")
    print("  Examples:")
    print("    python main.py -c --hours 3 DefensePro1,DefensePro2,192.168.1.20 DefensePro1_BdosProfile,DefensePro1_SynFloodProtection DP2_BdosProfile,DP2_SynFloodProtection DP3_Policy1")    
    print("    python main.py 192.168.1.1 admin radware radware1 --epoch-range 859885200 859971600 '' ''")    
    print('    python main.py --use-cached --date-range "11 Oct 2024 09:00:00" "11 Oct 2024 18:00:00" "DP1, DP2" "DP1_Policy1, DP1_Policy2" "DP2_Policy1, DP2_Policy2"')    
    exit(0)


if '-e' in args:
    index = args.index('-e')
elif '--environment' in args:
    index = args.index('--environment')
else:
    index = -1

if index > -1:
    if index + 1 < len(args):
        environment_name = args.pop(index + 1)
        args.pop(index)
        update_log(f"Using environment {environment_name}")
    else:
        update_log("--environment used without specifying environment.")
        exit(1)
else:
    environment_name = "Default"
    update_log(f"--environment <environment name> not specified, output will use 'Default'.")

output_folder = f"./Reports/{environment_name}/"
output_file = f"{output_folder}{environment_name}_{script_start_time.strftime('%Y-%m-%d_%H.%M.%S')}.zip"

class clsConfig():
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read("config.ini")

        if not self.config.has_section('Vision'):
            self.config.add_section('Vision')
        visionOptions = ['ip', 'username', 'password', 'rootPassword']
        for option in visionOptions:
            if not self.config.has_option('Vision', option):
                self.config.set('Vision', option, '')
        if not self.config.has_option('General', 'Top_N'):
            self.set('General','Top_N','10')
        if not self.config.has_option('General', 'minimum_minutes_between_waves'):
            self.set('General','minimum_minutes_between_waves','5')
        if not self.config.has_option('General', 'ExcludeFilters'):
            self.set('General','ExcludeFilters','Memcached-Server-Reflect')
        if not self.config.has_option('Reputation', 'use_abuseipdb'):
            self.set('Reputation','use_abuseipdb','False')
        if not self.config.has_option('Reputation', 'abuseipdb_api_key'):
            self.set('Reputation','abuseipdb_api_key','# To obtain an API key for abuseipdb, register at https://www.abuseipdb.com/. API key can be found under https://www.abuseipdb.com/account/api (free tier upto 1000 queries per day)')
        if not self.config.has_option('Reputation', 'use_ipqualityscore'):
            self.set('Reputation','use_ipqualityscore','False')
        if not self.config.has_option('Reputation', 'ip_quality_score_api_key'):
            self.set('Reputation','ip_quality_score_api_key','# To obtain an API key for ipqualityscore, register at https://www.ipqualityscore.com. API key can be found under https://www.ipqualityscore.com/user/settings (free tier limit is 5000 per month as of 2/9/2024)')
        if not self.config.has_option('Reputation', 'full_country_names'):
            self.set('Reputation','full_country_names','False')
        if not self.config.has_option('Reputation', 'included_columns'):
            self.set('Reputation','included_columns','AbuseIPDB_abuseConfidenceScore,AbuseIPDB_countryCode,AbuseIPDB_domain,AbuseIPDB_isp,IPQualityScore_fraud_score,IPQualityScore_country_code,IPQualityScore_host,IPQualityScore_ISP')
        if not self.config.has_option('Reputation', 'use_proxy'):
            self.set('Reputation','use_proxy','True')
        if not self.config.has_option('Reputation', 'http_proxy_address'):
            self.set('Reputation','http_proxy_address','http://http_proxy_url/')
        if not self.config.has_option('Reputation', 'https_proxy_address'):
            self.set('Reputation','https_proxy_address','https://https_proxy_url/')
        #################Email settings####################
        if not self.config.has_option('Email', 'send_email'):
            self.set("Email","send_email","FALSE")
        if not self.config.has_option('Email', 'smtp_auth'):
            self.set("Email","smtp_auth","FALSE")
        if not self.config.has_option('Email', 'smtp_password'):
            self.set("Email","smtp_password","$SMTP_PASSWD")
        if not self.config.has_option('Email', 'smtp_server'):
            self.set("Email","smtp_server","smtp.server.com")
        if not self.config.has_option('Email', 'smtp_server_port'):
            self.set("Email","smtp_server_port","25")
        if not self.config.has_option('Email', 'smtp_sender'):
            self.set("Email","smtp_sender","sender@gmail.com")
        if not self.config.has_option('Email', 'smtp_list'):
            self.set("Email","smtp_list","emailrecepient1@domain.com,emailrecepient2@domain.com")

    def save(self):
        with open("config.ini", "w") as config_file:
            self.config.write(config_file)

    def get(self, Section, Option, Fallback=None, **kwargs):
        value = self.config.get(Section, Option, fallback=Fallback, **kwargs)
        if isinstance(value, str) and value.startswith('$'):
            env_var = value[1:]
            value = os.getenv(env_var, value)  # Use the environment variable, fallback to original if not found
        if isinstance(value, str):
            if value.strip().upper() == 'TRUE':
                value = True
            elif value.strip().upper() == 'FALSE':
                value = False
            return value
        
    def set(self, section, option, value):
        if not self.config.has_section(section):
            self.config.add_section(section)
        if isinstance(value, (int, float)): 
            value = str(value) 
        if isinstance(value, bool):
             value = 'true' if value else 'false'
        self.config.set(section, option, value)
        self.save()

        


config = clsConfig()
topN = int(config.get("General","Top_N","10"))
reputation_included_columns = config.get("Reputation","included_columns","AbuseIPDB_abuseConfidenceScore,AbuseIPDB_countryCode,AbuseIPDB_domain,AbuseIPDB_isp,IPQualityScore_fraud_score,IPQualityScore_country_code,IPQualityScore_host,IPQualityScore_ISP").split(",")
