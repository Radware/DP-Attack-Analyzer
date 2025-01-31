import configparser
import datetime
import sys
import re
import os

args = sys.argv.copy()
script_filename = args.pop(0)
script_start_time = datetime.datetime.now()

temp_folder = "./Temp/"
log_file = temp_folder + "Attack-Story.log"
if not os.path.exists(temp_folder):
    os.makedirs(temp_folder)

def update_log(message):
    print(message)
    with(open(log_file,"a")) as file:
        timeStamp = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
        log_entry = f"[{timeStamp}] {message}\n"
        file.write(log_entry)

update_log(f"args: {args}")
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



if len(args) > 0 and (args[0].startswith('-h') or args[0].startswith('?') or args[0].startswith('--h')):
    print("  Script syntax:")
    print("  python main.py [--environment <name>] [--offline | --use-cached | <Vision_IP Username Password RootPassword>] <Time-Range> <DefensePro-list> <First-DP-policy-list> <Second-DP-policy-list> <X-DP-policy-list>...")
    print("    ***Note: The order of arguments is important and must not deviate from the above template.***")
    print("    --environment, -e      Optional: Specify an environment. This is used for output naming. Script will use 'Default' if not specified.")
    print(f"    --offline, -o         Instead of connecting to a live Vision appliance, use cached data stored in {temp_folder} for generating DP-Attack-Story_Report.html")
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
            
        #if not self.config.has_option('General', 'Compress_Output'):
        #    self.set("General","Compress_Output","TRUE")
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
            return os.getenv(env_var, value)  # Use the environment variable, fallback to original if not found
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