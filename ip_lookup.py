#

import requests
import json
import os
import csv
from common import *

try:
    import requests
except ImportError:
    print("The python module 'requests' is not installed. Please install it by running: pip install requests")

#if config.get("Reputation", "use_abuseipdb", False) or config.get("Reputation", "use_ipqualityscore", False):
#    if config.get("Reputation","full_country_names", False):
#        try:
#            import pycountry
#        except ImportError:
#            print("config: [Reputation] full_country_names is set to true and the python module 'pycountry' is not installed.")
#            print("Please install it by running: pip install pycountry")
#            print("pycountry is needed to resolve 2-letter ISO 3166-1 alpha-2 country codes into full country names")
#            exit()

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(category=requests.packages.urllib3.exceptions.InsecureRequestWarning)
enable_proxy = config.get('Reputation', 'use_proxy', False)
IPQualityScore_limit_reached = False
AbuseIPDB_limit_reached = False

try:
    with open('reputation_cache.json', encoding='utf-8') as file:
        reputation_cache = json.load(file)
except FileNotFoundError:
    update_log(f"reputation_cache.json not found.")
    reputation_cache = {}

update_log("Pruning stale cached ip reputation data")
now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
ips_to_prune = []
for ip in reputation_cache.keys():
    if now - reputation_cache[ip].get('AbuseIPDB',{}).get('cachedAt',99999999999) > 2419200 :
        update_log(f"    {ip} - AbuseIPDB is >4 weeks stale. Pruning.")
        reputation_cache[ip].pop('AbuseIPDB', None)
    if now - reputation_cache[ip].get('IPQualityScore',{}).get('cachedAt',99999999999) > 2419200:
        update_log(f"    {ip} - IPQualityScore is >4 weeks stale. Pruning.")
        reputation_cache[ip].pop('IPQualityScore')
    if reputation_cache[ip].get('IPQualityScore',{}).get('success',True) == False:
        update_log(f"    {ip} - IPQualityScore last access attempt failed. Pruning")
        reputation_cache[ip].pop('IPQualityScore')
    if reputation_cache[ip].get('AbuseIPDB',False) == False and reputation_cache[ip].get('IPQualityScore',False) == False:
        update_log(f"    {ip} - all data pruned. Removing entry.")
        ips_to_prune.append(ip)
for ip in ips_to_prune:
    if ip in reputation_cache:
        del reputation_cache[ip]
with open('reputation_cache.json', 'w', encoding='utf-8') as file:
    json.dump(reputation_cache, file, ensure_ascii=False, indent=4)

def get_ip_abuse_data(ip):
    cached = reputation_cache.get(ip,{})
    write_updates = False
    #if the cached time is older than 2 weeks (1209600 seconds), update the cache.
    if int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - int(cached.get('AbuseIPDB',{}).get('cachedAt',0)) > 1209600:
        if config.get('Reputation', 'use_abuseipdb', False):
            global AbuseIPDB_limit_reached
            if AbuseIPDB_limit_reached == False:
                try:
                    abuse_ip_db_response = abuse_ip_db_call(ip)
                    if abuse_ip_db_response:
                        cached['AbuseIPDB'] = abuse_ip_db_response.get("data",{})
                        cached['AbuseIPDB']['cachedAt'] = datetime.datetime.now(datetime.timezone.utc).timestamp()
                        write_updates = True
                    else:
                        raise
                except:
                    cached['AbuseIPDB'] = {'data':{'abuseConfidenceScore':'Error'}}
                    cached['AbuseIPDB']['cachedAt'] = 0
    else:
        update_log(f"    AbuseIPDB cached data for {ip} is less than 2 weeks old. Using cache")

    if int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - cached.get('IPQualityScore',{}).get('cachedAt',0) > 1209600:
        if config.get('Reputation', 'use_ipqualityscore', False):
            global IPQualityScore_limit_reached
            if IPQualityScore_limit_reached == False:
                try:
                    ip_quality_score_response = ip_quality_score_call(ip)
                    cached['IPQualityScore'] = ip_quality_score_response
                    if ip_quality_score_response.get('success'):
                        cached['IPQualityScore']['cachedAt'] = datetime.datetime.now(datetime.timezone.utc).timestamp()
                        write_updates = True
                    else:
                        update_log(f"    Error updating ipqualityscore.com data for {ip}. Error: {ip_quality_score_response}")
                        cached['IPQualityScore']['cachedAt'] = 0
                        if ip_quality_score_response.get('message',"").startswith("You have exceeded"):
                            IPQualityScore_limit_reached = True
                except:
                    cached['IPQualityScore'] = {'fraud_score':'Error'}
                    cached['IPQualityScore']['cachedAt'] = 0
                    update_log(f"    Error retreiving IPQualityScore info for {ip}.")
            else:
                if cached.get('IPQualityScore',{}).get('cachedAt',0) > 0:
                    update_log(f"    Ipqualityscore.com limit reached. Stale cached data will be used for {ip}.")
                else:
                    update_log(f"    Ipqualityscore.com limit reached. No cached data is available for {ip}.")
    else:
        update_log(f"    IPQualityScore cached data for {ip} is less than 2 weeks old. Using cache")

    reputation_cache[ip] = cached
    if write_updates:
        with open('reputation_cache.json', 'w', encoding='utf-8') as file:
            json.dump(reputation_cache, file, ensure_ascii=False, indent=4)
    
    output = reputation_cache[ip]
    if config.get("Reputation","use_abuseipdb", False) or config.get("Reputation","use_ipqualityscore", False):
        if config.get("Reputation","full_country_names", False):
            if len(output.get('AbuseIPDB',{}).get('countryCode','')) == 2:
                #country = pycountry.countries.get(alpha_2=output['AbuseIPDB']['countryCode'].upper())
                country = country_name_from_code(output['AbuseIPDB']['countryCode'].upper())
                if country:
                    output['AbuseIPDB']['countryCode'] = country
            if len(output.get('IPQualityScore',{}).get('country_code','')) == 2:
                #country = pycountry.countries.get(alpha_2=output['IPQualityScore']['country_code'].upper())
                country = country_name_from_code(output['IPQualityScore']['country_code'].upper())
                if country:
                    output['IPQualityScore']['country_code'] = country
    
    return output

def abuse_ip_db_call(ipAddress):
    # Call to https://api.abuseipdb.com
    key = config.get('Reputation', 'abuseipdb_api_key', '').split('#')[0].strip().strip('"').strip("'")
    if key != '' and key != None:
        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': ipAddress,
            'maxAgeInDays': '90'
        }
        
        headers = {
            'Accept': 'application/json',
            'Key': key
        }
        
        proxy = {
            'http': config.get('Reputation', 'http_proxy_address', 'http://your_proxy_url'),
            'https': config.get('Reputation', 'https_proxy_address', 'https://your_proxy_url')
        }
        update_log(f"  Querying api.abuseipdb.com for {ipAddress}")
        try:
            if enable_proxy:
                response = requests.request(method='GET', url=url, headers=headers, params=querystring, proxies=proxy, verify=False)
            else:
                response = requests.request(method='GET', url=url, headers=headers, params=querystring, verify=False)
            if response.status_code != 200:
                raise requests.HTTPError(f"AbuseIPDB responded with status {response.status_code}: {response.text}")
            update_log(f"Response object: {response}")
        except Exception as e:
            update_log(f"Exception occurred during AbuseIPDB request: {e}")
            update_log(f"     url: {url}")
            update_log(f"     headers: {headers}")
            update_log(f"     querystring: {querystring}")
            update_log(f"     Text: {response.text}")
            if 'response' in locals() and response is not None:
                update_log("Partial response info (if available):")
                update_log(f"  Status Code: {response.status_code}")
                update_log(f"  Reason: {response.reason}")
                update_log(f"  Text: {response.text}")
            return None
        
        # Formatted output
        decodedResponse = json.loads(response.text)
        # print(json.dumps(decodedResponse, sort_keys=True, indent=4))

        return decodedResponse
    else:
        update_log('Error: Missing abuseipdb API Key')
        return 'Missing abuseipdb API Key'


def ip_quality_score_call(ip):
    key = config.get('Reputation', 'ip_quality_score_api_key', '').split('#')[0].strip().strip('"').strip("'")
    if key != '' and key != None:
        # Call to https://ipqualityscore.com
        url = f'https://ipqualityscore.com/api/json/ip/{key}/{ip}'

        # Send the API request
        update_log(f"  Querying ipqualityscore.com for {ip}")
        response = requests.get(url, verify=False)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            data = response.json()
            return(data)
        else:
            update_log(f"Error: {response.status_code}")
            return({"success": False})
    else:
        update_log('Missing ip_quality_score API Key')
        return {'success': False, 'message':'Missing ip_quality_score API Key'}

def parse_data_create_report():
    # Parse collected data

    with open( 'abuse_dic_raw.json', 'r') as f:
        abuse_dic_raw_str = f.read()
        abuse_dic_raw_dict= json.loads(abuse_dic_raw_str)

    # Create report csv and headers
    with open('abuse_report.csv', mode='w', newline="") as abuseipdb_report:
        bdos_writer = csv.writer(abuseipdb_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        bdos_writer.writerow(['IP Address' , 'Confidence of Abuse' , 'Fraud Score','Proxy Status','VPN Status','TOR Status','Bot Activity','Recent Abuse', 'Country' , 'Usage Type' , 'ISP' , 'Domain Name', 'Hosnames', 'Total Reports', 'Distinct Users' , 'Last reported'])


    for ip, ip_details in abuse_dic_raw_dict.items():
        abuse_confidence_score_abuse_ipdb = 'N/A'
        fraud_score_ipquality_score = 'N/A'
        proxy_ipquality_score = 'N/A'
        vpn_ipquality_score = 'N/A'
        tor_ipquality_score = 'N/A'
        bot_ipquality_score = 'N/A'
        recent_abuse_ipquality_score = 'N/A'
        country_abuse_ipdb = 'N/A'
        usage_type_abuse_ipdb = 'N/A'
        isp_abuse_ipdb = 'N/A'
        domain_abuse_ipdb = 'N/A'
        hostnames_abuse_ipdb = 'N/A'
        total_reports_abuse_ipdb = 'N/A'
        distinct_users_abuse_ipdb = 'N/A'
        last_reported_abuse_ipdb = 'N/A'

        if True:
            abuse_ipdb_details = ip_details.get('AbuseIPDB Src IP details')
            if abuse_ipdb_details:
                abuse_confidence_score_abuse_ipdb = abuse_ipdb_details.get('abuseConfidenceScore')
                country_abuse_ipdb = abuse_ipdb_details.get('countryCode')
                usage_type_abuse_ipdb = abuse_ipdb_details.get('usageType')
                isp_abuse_ipdb = abuse_ipdb_details.get('isp')
                domain_abuse_ipdb = abuse_ipdb_details.get('domain')
                hostnames_abuse_ipdb = (', '.join(abuse_ipdb_details.get('hostnames')))
                total_reports_abuse_ipdb = abuse_ipdb_details.get('totalReports')
                distinct_users_abuse_ipdb = abuse_ipdb_details.get('numDistinctUsers')
                last_reported_abuse_ipdb = abuse_ipdb_details.get('lastReportedAt')

        if True:
            ip_quality_score_details = ip_details.get('IPQualityScore Src IP details')
            if ip_quality_score_details:
                fraud_score_ipquality_score = ip_quality_score_details.get('fraud_score')
                proxy_ipquality_score = ip_quality_score_details.get('proxy')
                vpn_ipquality_score = ip_quality_score_details.get('vpn')
                tor_ipquality_score = ip_quality_score_details.get('tor')
                bot_ipquality_score = ip_quality_score_details.get('bot_status')
                recent_abuse_ipquality_score = ip_quality_score_details.get('recent_abuse')

        with open('abuse_report.csv', mode='a', newline="") as abuseipdb_report:
            bdos_writer = csv.writer(abuseipdb_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            bdos_writer.writerow([ip , abuse_confidence_score_abuse_ipdb , fraud_score_ipquality_score, proxy_ipquality_score, vpn_ipquality_score, tor_ipquality_score,bot_ipquality_score,recent_abuse_ipquality_score, country_abuse_ipdb , usage_type_abuse_ipdb , isp_abuse_ipdb , domain_abuse_ipdb, hostnames_abuse_ipdb, total_reports_abuse_ipdb, distinct_users_abuse_ipdb , last_reported_abuse_ipdb])
def country_name_from_code(code):
    countries = {
        'US': 'United States',
        'CA': 'Canada',
        'GB': 'United Kingdom',
        'FR': 'France',
        'DE': 'Germany',
        'IT': 'Italy',
        'ES': 'Spain',
        'CN': 'China',
        'JP': 'Japan',
        'IN': 'India',
        'BR': 'Brazil',
        'RU': 'Russia',
        'MX': 'Mexico',
        'ZA': 'South Africa',
        'AU': 'Australia',
        'NZ': 'New Zealand',
        'AR': 'Argentina',
        'CL': 'Chile',
        'CO': 'Colombia',
        'EG': 'Egypt',
        'NG': 'Nigeria',
        'KE': 'Kenya',
        'KR': 'South Korea',
        'SE': 'Sweden',
        'NO': 'Norway',
        'FI': 'Finland',
        'DK': 'Denmark',
        'NL': 'Netherlands',
        'BE': 'Belgium',
        'CH': 'Switzerland',
        'AT': 'Austria',
        'IE': 'Ireland',
        'PL': 'Poland',
        'CZ': 'Czech Republic',
        'HU': 'Hungary',
        'GR': 'Greece',
        'TR': 'Turkey',
        'IL': 'Israel',
        'SA': 'Saudi Arabia',
        'AE': 'United Arab Emirates',
        'PK': 'Pakistan',
        'BD': 'Bangladesh',
        'TH': 'Thailand',
        'VN': 'Vietnam',
        'PH': 'Philippines',
        'MY': 'Malaysia',
        'SG': 'Singapore',
        'ID': 'Indonesia',
        'IR': 'Iran',
        'IQ': 'Iraq',
        'SY': 'Syria',
        'UA': 'Ukraine',
        'RO': 'Romania',
        'SK': 'Slovakia',
        'BG': 'Bulgaria',
        'HR': 'Croatia',
        'SI': 'Slovenia',
        'RS': 'Serbia',
        'BA': 'Bosnia and Herzegovina',
        'ME': 'Montenegro',
        'MK': 'North Macedonia',
        'AL': 'Albania',
        'BY': 'Belarus',
        'KZ': 'Kazakhstan',
        'GE': 'Georgia',
        'AM': 'Armenia',
        'AZ': 'Azerbaijan',
        'AF': 'Afghanistan',
        'LK': 'Sri Lanka',
        'NP': 'Nepal',
        'MM': 'Myanmar',
        'KH': 'Cambodia',
        'LA': 'Laos',
        'MN': 'Mongolia',
        'UZ': 'Uzbekistan',
        'TJ': 'Tajikistan',
        'TM': 'Turkmenistan',
        'KG': 'Kyrgyzstan',
        'ET': 'Ethiopia',
        'SD': 'Sudan',
        'DZ': 'Algeria',
        'MA': 'Morocco',
        'TN': 'Tunisia',
        'LY': 'Libya',
        'GH': 'Ghana',
        'CI': 'Côte d’Ivoire',
        'SN': 'Senegal',
        'UG': 'Uganda',
        'TZ': 'Tanzania',
        'ZM': 'Zambia',
        'ZW': 'Zimbabwe',
        'MW': 'Malawi',
        'MZ': 'Mozambique',
        'AO': 'Angola',
        'CM': 'Cameroon',
        'CD': 'Democratic Republic of the Congo',
        'CG': 'Republic of the Congo',
        'GA': 'Gabon',
        'NA': 'Namibia',
        'BW': 'Botswana',
        'QA': 'Qatar',
        'BH': 'Bahrain',
        'KW': 'Kuwait',
        'OM': 'Oman',
        'YE': 'Yemen',
        'IS': 'Iceland',
        'LU': 'Luxembourg',
        'LI': 'Liechtenstein',
        'MC': 'Monaco',
        'SM': 'San Marino',
        'VA': 'Vatican City',
        'MT': 'Malta',
        'CY': 'Cyprus',
        'BB': 'Barbados',
        'JM': 'Jamaica',
        'TT': 'Trinidad and Tobago',
        'BS': 'Bahamas',
        'CU': 'Cuba',
        'DO': 'Dominican Republic',
        'HT': 'Haiti',
        'PA': 'Panama',
        'CR': 'Costa Rica',
        'GT': 'Guatemala',
        'HN': 'Honduras',
        'SV': 'El Salvador',
        'NI': 'Nicaragua',
        'BZ': 'Belize',
        'PE': 'Peru',
        'BO': 'Bolivia',
        'EC': 'Ecuador',
        'PY': 'Paraguay',
        'UY': 'Uruguay',
        'VE': 'Venezuela',
        'SR': 'Suriname',
        'GY': 'Guyana',
        'TJ': 'Tajikistan',
        'BT': 'Bhutan',
        'RW': 'Rwanda',
        'LS': 'Lesotho',
        'SZ': 'Eswatini',
        'ML': 'Mali',
        'NE': 'Niger',
        'BF': 'Burkina Faso',
        'TG': 'Togo',
        'GM': 'Gambia',
        'SL': 'Sierra Leone',
        'LR': 'Liberia',
        'GN': 'Guinea',
        'GW': 'Guinea-Bissau',
        'DJ': 'Djibouti',
        'ER': 'Eritrea',
        'SO': 'Somalia',
        'CF': 'Central African Republic',
        'SS': 'South Sudan',
        'NR': 'Nauru',
        'TV': 'Tuvalu',
        'FJ': 'Fiji',
        'WS': 'Samoa',
        'TO': 'Tonga',
        'PG': 'Papua New Guinea',
        'SB': 'Solomon Islands',
        'VU': 'Vanuatu',
        'MH': 'Marshall Islands',
        'FM': 'Micronesia',
        'PW': 'Palau',
        'KI': 'Kiribati',
        'TL': 'Timor-Leste'
    }
    return countries.get(code.upper(), 'Unknown country code')
