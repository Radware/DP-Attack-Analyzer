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
    print("You can install all required modules using: pip install requests paramiko pysftp")
    exit(1)

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

if config.get('Reputation', 'prune_stale_entries', True):
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
    if config.get('Reputation', 'use_abuseipdb', False):
        if int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - int(cached.get('AbuseIPDB',{}).get('cachedAt',0)) > 1209600:
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
        #else:
        #    update_log(f"    AbuseIPDB cached data for {ip} is less than 2 weeks old. Using cache")
    if config.get('Reputation', 'use_ipqualityscore', False):
        if int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - cached.get('IPQualityScore',{}).get('cachedAt',0) > 1209600:
        
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
                except Exception as e:
                    cached['IPQualityScore'] = {'fraud_score':'Error'}
                    cached['IPQualityScore']['cachedAt'] = 0
                    update_log(f"    Error retreiving IPQualityScore info for {ip}. Type: {type(e).__name__}, Error: {e}")
            else:
                if cached.get('IPQualityScore',{}).get('cachedAt',0) > 0:
                    update_log(f"    Ipqualityscore.com limit reached. Stale cached data will be used for {ip}.")
                else:
                    update_log(f"    Ipqualityscore.com limit reached. No cached data is available for {ip}.")
        #else:
        #    update_log(f"    IPQualityScore cached data for {ip} is less than 2 weeks old. Using cache")

    reputation_cache[ip] = cached
    if write_updates:
        with open('reputation_cache.json', 'w', encoding='utf-8') as file:
            json.dump(reputation_cache, file, ensure_ascii=False, indent=4)
    
    output = reputation_cache[ip]
    if config.get("Reputation","use_abuseipdb", False) or config.get("Reputation","use_ipqualityscore", False):
        if config.get("Reputation","full_country_names", True):
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
                # 5 seconds for connect timeout, 15 seconds for read timeout
                response = requests.request(method='GET', url=url, headers=headers, params=querystring, proxies=proxy, verify=False, timeout=(5, 15))
            else:
                response = requests.request(method='GET', url=url, headers=headers, params=querystring, verify=False, timeout=(5, 15))
            if response.status_code != 200:
                raise requests.HTTPError(f"AbuseIPDB responded with status {response.status_code}: {response.text}")
            update_log(f"    Response object: {response}")
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
        update_log(f"  Querying ipqualityscore.com for {ip}:")
        # 5 seconds for connect timeout, 15 seconds for read timeout
        try:
            if enable_proxy:
                proxy = {
                    'http': config.get('Reputation', 'http_proxy_address', 'http://your_proxy_url'),
                    'https': config.get('Reputation', 'https_proxy_address', 'https://your_proxy_url')
                }
                # 5 seconds for connect timeout, 15 seconds for read timeout
                response = requests.request(method='GET', url=url, proxies=proxy, verify=False, timeout=(5, 15))
            else:
                response = requests.request(method='GET', url=url, verify=False, timeout=(5, 15))
            if response.status_code != 200:
                raise requests.HTTPError(f"ipqualityscore.com responded with status {response.status_code}: {response.text}")
            update_log(f"    Response object: {response}")
        except Exception as e:
            update_log(f"Exception occurred during ipqualityscore.com request: {e}")
            update_log(f"     url: {url}")
            update_log(f"     Text: {response.text}")
            if 'response' in locals() and response is not None:
                update_log("Partial response info (if available):")
                update_log(f"  Status Code: {response.status_code}")
                update_log(f"  Reason: {response.reason}")
                update_log(f"  Text: {response.text}")
            return None

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


def country_name_from_code(code):
    countries = {
        'AD': 'Andorra', 'AE': 'United Arab Emirates', 'AF': 'Afghanistan', 'AG': 'Antigua and Barbuda',
        'AI': 'Anguilla', 'AL': 'Albania', 'AM': 'Armenia', 'AO': 'Angola', 'AQ': 'Antarctica',
        'AR': 'Argentina', 'AS': 'American Samoa', 'AT': 'Austria', 'AU': 'Australia', 'AW': 'Aruba',
        'AX': 'Aland Islands', 'AZ': 'Azerbaijan', 'BA': 'Bosnia and Herzegovina', 'BB': 'Barbados',
        'BD': 'Bangladesh', 'BE': 'Belgium', 'BF': 'Burkina Faso', 'BG': 'Bulgaria', 'BH': 'Bahrain',
        'BI': 'Burundi', 'BJ': 'Benin', 'BL': 'Saint Barthelemy', 'BM': 'Bermuda', 'BN': 'Brunei',
        'BO': 'Bolivia', 'BQ': 'Caribbean Netherlands', 'BR': 'Brazil', 'BS': 'Bahamas',
        'BT': 'Bhutan', 'BV': 'Bouvet Island', 'BW': 'Botswana', 'BY': 'Belarus', 'BZ': 'Belize',
        'CA': 'Canada', 'CC': 'Cocos Islands', 'CD': 'Congo (Kinshasa)', 'CF': 'Central African Republic',
        'CG': 'Congo (Brazzaville)', 'CH': 'Switzerland', 'CI': 'Ivory Coast', 'CK': 'Cook Islands',
        'CL': 'Chile', 'CM': 'Cameroon', 'CN': 'China', 'CO': 'Colombia', 'CR': 'Costa Rica',
        'CU': 'Cuba', 'CV': 'Cape Verde', 'CW': 'Curacao', 'CX': 'Christmas Island', 'CY': 'Cyprus',
        'CZ': 'Czech Republic', 'DE': 'Germany', 'DJ': 'Djibouti', 'DK': 'Denmark', 'DM': 'Dominica',
        'DO': 'Dominican Republic', 'DZ': 'Algeria', 'EC': 'Ecuador', 'EE': 'Estonia', 'EG': 'Egypt',
        'EH': 'Western Sahara', 'ER': 'Eritrea', 'ES': 'Spain', 'ET': 'Ethiopia', 'FI': 'Finland',
        'FJ': 'Fiji', 'FM': 'Micronesia', 'FO': 'Faroe Islands', 'FR': 'France', 'GA': 'Gabon',
        'GB': 'United Kingdom', 'GD': 'Grenada', 'GE': 'Georgia', 'GF': 'French Guiana', 'GG': 'Guernsey',
        'GH': 'Ghana', 'GI': 'Gibraltar', 'GL': 'Greenland', 'GM': 'Gambia', 'GN': 'Guinea',
        'GP': 'Guadeloupe', 'GQ': 'Equatorial Guinea', 'GR': 'Greece', 'GT': 'Guatemala', 'GU': 'Guam',
        'GW': 'Guinea-Bissau', 'GY': 'Guyana', 'HK': 'Hong Kong', 'HM': 'Heard Island and McDonald Islands',
        'HN': 'Honduras', 'HR': 'Croatia', 'HT': 'Haiti', 'HU': 'Hungary', 'ID': 'Indonesia',
        'IE': 'Ireland', 'IL': 'Israel', 'IM': 'Isle of Man', 'IN': 'India', 'IO': 'British Indian Ocean Territory',
        'IQ': 'Iraq', 'IR': 'Iran', 'IS': 'Iceland', 'IT': 'Italy', 'JE': 'Jersey', 'JM': 'Jamaica',
        'JO': 'Jordan', 'JP': 'Japan', 'KE': 'Kenya', 'KG': 'Kyrgyzstan', 'KH': 'Cambodia',
        'KI': 'Kiribati', 'KM': 'Comoros', 'KN': 'Saint Kitts and Nevis', 'KP': 'North Korea',
        'KR': 'South Korea', 'KW': 'Kuwait', 'KY': 'Cayman Islands', 'KZ': 'Kazakhstan', 'LA': 'Laos',
        'LB': 'Lebanon', 'LC': 'Saint Lucia', 'LI': 'Liechtenstein', 'LK': 'Sri Lanka', 'LR': 'Liberia',
        'LS': 'Lesotho', 'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'LY': 'Libya',
        'MA': 'Morocco', 'MC': 'Monaco', 'MD': 'Moldova', 'ME': 'Montenegro', 'MF': 'Saint Martin',
        'MG': 'Madagascar', 'MH': 'Marshall Islands', 'MK': 'Macedonia', 'ML': 'Mali', 'MM': 'Burma',
        'MN': 'Mongolia', 'MO': 'Macao', 'MP': 'Northern Mariana Islands', 'MQ': 'Martinique',
        'MR': 'Mauritania', 'MS': 'Montserrat', 'MT': 'Malta', 'MU': 'Mauritius', 'MV': 'Maldives',
        'MW': 'Malawi', 'MX': 'Mexico', 'MY': 'Malaysia', 'MZ': 'Mozambique', 'NA': 'Namibia',
        'NC': 'New Caledonia', 'NE': 'Niger', 'NF': 'Norfolk Island', 'NG': 'Nigeria', 'NI': 'Nicaragua',
        'NL': 'Netherlands', 'NO': 'Norway', 'NP': 'Nepal', 'NR': 'Nauru', 'NU': 'Niue', 'NZ': 'New Zealand',
        'OM': 'Oman', 'PA': 'Panama', 'PE': 'Peru', 'PF': 'French Polynesia', 'PG': 'Papua New Guinea',
        'PH': 'Philippines', 'PK': 'Pakistan', 'PL': 'Poland', 'PM': 'Saint Pierre and Miquelon',
        'PN': 'Pitcairn Islands', 'PR': 'Puerto Rico', 'PT': 'Portugal', 'PW': 'Palau', 'PY': 'Paraguay',
        'QA': 'Qatar', 'RE': 'Reunion', 'RO': 'Romania', 'RS': 'Serbia', 'RU': 'Russia', 'RW': 'Rwanda',
        'SA': 'Saudi Arabia', 'SB': 'Solomon Islands', 'SC': 'Seychelles', 'SD': 'Sudan', 'SE': 'Sweden',
        'SG': 'Singapore', 'SH': 'Saint Helena', 'SI': 'Slovenia', 'SJ': 'Svalbard and Jan Mayen',
        'SK': 'Slovakia', 'SL': 'Sierra Leone', 'SM': 'San Marino', 'SN': 'Senegal', 'SO': 'Somalia',
        'SR': 'Suriname', 'SS': 'South Sudan', 'ST': 'Sao Tome and Principe', 'SV': 'El Salvador',
        'SX': 'Sint Maarten', 'SY': 'Syria', 'SZ': 'Swaziland', 'TC': 'Turks and Caicos Islands',
        'TD': 'Chad', 'TF': 'French Southern Territories', 'TG': 'Togo', 'TH': 'Thailand', 'TJ': 'Tajikistan',
        'TK': 'Tokelau', 'TL': 'East Timor', 'TM': 'Turkmenistan', 'TN': 'Tunisia', 'TO': 'Tonga',
        'TR': 'Turkey', 'TT': 'Trinidad and Tobago', 'TV': 'Tuvalu', 'TZ': 'Tanzania', 'UA': 'Ukraine',
        'UG': 'Uganda', 'UM': 'U.S. Minor Outlying Islands', 'US': 'United States', 'UY': 'Uruguay',
        'UZ': 'Uzbekistan', 'VA': 'Vatican City', 'VC': 'Saint Vincent and the Grenadines',
        'VE': 'Venezuela', 'VG': 'British Virgin Islands', 'VI': 'U.S. Virgin Islands', 'VN': 'Vietnam',
        'VU': 'Vanuatu', 'WF': 'Wallis and Futuna', 'WS': 'Samoa', 'YE': 'Yemen', 'YT': 'Mayotte',
        'ZA': 'South Africa', 'ZM': 'Zambia', 'ZW': 'Zimbabwe'
    }
    return countries.get(code.upper(), 'code')