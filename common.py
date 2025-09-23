import configparser
import datetime
import sys
import re
import os
import io
import json
import math
import subprocess
from typing import Union, List, Dict, Any, Optional

args = sys.argv.copy()
script_filename = args.pop(0)
script_start_time = datetime.datetime.now()
common_globals = {'unavailable_devices':[]}
common_globals['Manual Mode'] = False

temp_folder = "./Temp/"
manual_folder = "./manual/"
log_file = temp_folder + "Attack-Analyzer.log"
if not os.path.exists(temp_folder):
    os.makedirs(temp_folder)



log_cache = ""
log_state = 0
ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
def update_log(message, newline=True, toconsole=True, write_cache=False):
    global log_cache, log_state
    
    if write_cache:
        log_state = 1

    end_char = '\n' if newline else ''

    def supports_color():
        import sys, os
        if not sys.stdout.isatty():
            return False
        if os.environ.get("TERM") == "dumb":
            return False
        if "NO_COLOR" in os.environ:
            return False
        return True

    clean_message = ansi_escape.sub('', message)

    if toconsole:
        if supports_color():
            print(message, end=end_char, flush=True)
        else:
            print(clean_message, end=end_char, flush=True)
            
    with(open(log_file,"w" if log_state == 1 else "a")) as file:
        
        log_entry = f"[{datetime.datetime.now().strftime('%d-%b-%Y %H:%M:%S')}] {clean_message}{end_char}"
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
        first_time = False

        if not self.config.has_section('Vision'):
            self.config.add_section('Vision')
            first_time = True
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
        if not self.config.has_option('General', 'OutputTimeFormat'):
            self.set('General','OutputTimeFormat','%%d-%%b-%%Y %%H:%%M:%%S %%Z') #Default '%d-%b-%Y %H:%M:%S %Z' looks like 11-Oct-2024 14:30:00 UTC
        if not self.config.has_option('General', 'HexBasedSyslogIDs'):
            self.set('General','UsesHexBasedSyslogIDs','True')
        #Reputation settings
        if not self.config.has_option('Reputation', 'use_abuseipdb'):
            self.set('Reputation','use_abuseipdb','False')
        if not self.config.has_option('Reputation', 'abuseipdb_api_key'):
            self.set('Reputation','abuseipdb_api_key','# To obtain an API key for abuseipdb, register at https://www.abuseipdb.com/. API key can be found under https://www.abuseipdb.com/account/api (free tier upto 1000 queries per day)')
        if not self.config.has_option('Reputation', 'use_ipqualityscore'):
            self.set('Reputation','use_ipqualityscore','False')
        if not self.config.has_option('Reputation', 'ip_quality_score_api_key'):
            self.set('Reputation','ip_quality_score_api_key','# To obtain an API key for ipqualityscore, register at https://www.ipqualityscore.com. API key can be found under https://www.ipqualityscore.com/user/settings (free tier limit is 5000 per month as of 2/9/2024)')
        if not self.config.has_option('Reputation', 'full_country_names'):
            self.set('Reputation','full_country_names','True')
        if not self.config.has_option('Reputation', 'included_columns'):
            self.set('Reputation','included_columns','AbuseIPDB_abuseConfidenceScore,AbuseIPDB_countryCode,AbuseIPDB_domain,AbuseIPDB_isp,IPQualityScore_fraud_score,IPQualityScore_country_code,IPQualityScore_host,IPQualityScore_ISP')
        if not self.config.has_option('Reputation', 'use_proxy'):
            self.set('Reputation','use_proxy','True')
        if not self.config.has_option('Reputation', 'http_proxy_address'):
            self.set('Reputation','http_proxy_address','http://http_proxy_url/')
        if not self.config.has_option('Reputation', 'https_proxy_address'):
            self.set('Reputation','https_proxy_address','https://https_proxy_url/')
        if not self.config.has_option('Reputation', 'prune_stale_entries'):
            self.set('Reputation','prune_stale_entries','False')
        
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

        if first_time:
            print("")
            print("")
            update_log("As this appears to be your first time running the script, config.ini has now been created. ")
            update_log("Feel free to open it and make modifications.")
            update_log("There are a lot of settings contained within that enable useful features.")
            print("")
            update_log("The script will now exit. This message won't appear again.")
            exit(0)

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
output_time_format = config.get("General","OutputTimeFormat","%d-%m-%Y %H:%M:%S %Z")

class color:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"

def friendly_bits(bits: int | float | str, precision: int = 3, base: float = 1000.0, is_rate: bool = False) -> str:
    """
    Ingests a large number and outputs the number in the largest SI unit:
    Bits, Kb, Mb, Gb, Tb, Petabits, Exabits

    :param bits: Number of bits (can be int or float).
    :param precision: Optional: default 3. Max decimal places to show (without trailing zeros).
    :param base: Optional: default 1000.0, You may prefer to use 1024.0.
    :param is_rate: Optional: if true, returns a rate instead of a standalone value. Kbps instead of Kb
    :return: e.g., "1.23 Gb", "987 Mb", "432 Bits"
    """

    if is_rate:
        units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps", "Ebps"]
    else:
        units = ["Bit", "Kb", "Mb", "Gb", "Tb", "Petabit", "Exabit"]
    
    original_str = str(bits)

    if isinstance(bits, str):
        s = bits.strip().replace(",", "").replace("_", "")
    else:
        s = bits

    try:
        num = float(s)
    except (ValueError, TypeError):
        return original_str
        
     # Validate value/base
    if not math.isfinite(num):
        return original_str
    if base <= 1:
        base = 1000.0  # sane fallback

    # Handle sign and magnitude
    sign = "-" if num < 0 else ""
    value = abs(num)

    # Scale to largest unit
    unit_idx = 0
    while value >= base and unit_idx < len(units) - 1:
        value /= base
        unit_idx += 1

    # Format with commas, trim trailing zeros
    number_string = f"{value:.{precision}f}".rstrip("0").rstrip(".")
    if "." in number_string:
        int_part, frac = number_string.split(".", 1)
        int_part = f"{int(int_part):,}"
        number_string = f"{int_part}.{frac}"
    else:
        number_string = f"{int(number_string):,}"
    
    # Add plural 's' if [bit, petabit, or exabit] and value >= 2
    unit_name = units[unit_idx]
    if unit_idx in (0,5,6) and (number_string != "1") and not is_rate:
        unit_name += "s"

    return f"{sign}{number_string} {unit_name}"

def friendly_duration(start: datetime, end: datetime) -> str:
    """Return a human-friendly duration string between two datetimes."""
    delta = abs(end - start)  # allow either order
    seconds = int(delta.total_seconds())

    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if secs or not parts:  # show seconds if nonzero, or if everything else is zero
        parts.append(f"{secs} second{'s' if secs != 1 else ''}")

    return " ".join(parts)


def get_readme_version(path="Readme.txt"):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        # Regex: find "# Version control" followed by newline, then capture the next line
        match = re.search(r"# Version Control\s*\n([^\n^(]+)", text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ""
    except:
        return ""
    


def get_current_branch():
    try:
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"],stderr=subprocess.DEVNULL).decode().strip()
        return branch
    except Exception as e:
        return f"Error: {e}"