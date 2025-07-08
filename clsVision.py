import getpass
import sys
import datetime
import os
import json
import time

from common import *

try:
    import requests
except ImportError:
    print("The python module 'requests' is not installed. Please install it by running: pip install requests")
    print("You can install all required modules using: pip install requests paramiko pysftp")
    exit()

try:
    import paramiko
except ImportError:
    print("The python module 'paramiko' is not installed. Please install it by running: pip install paramiko")
    print("You can install all required modules using: pip install requests paramiko pysftp")
    exit()


#We ignore if Vision has an invalid security certificate. The next lines prevent an error from being displayed every time we send a command or query to vision
requests.packages.urllib3.disable_warnings(category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

##configuration 
class clsVision:
    #Initialize and log in to vision instance
    def __init__(self):
        
        #config = load_config()
        #create_connection_section(config)
        #config = clsConfig() #Imported from common.py
        
        if len(args) >1:
            if args[0] == "--use-cached" or args[0] == "-c":
                args.pop(0)
                ip = config.get('Vision', 'ip') 
                username = config.get('Vision', 'username')
                password = config.get('Vision', 'password')
                self.rootpassword = config.get('Vision', 'rootpassword')
            else:
                if len(args) >=4:
                    ip = args.pop(0)
                    username = args.pop(0)
                    password = args.pop(0)
                    self.rootpassword = args.pop(0)
                else:
                    update_log(f"Incorrect number of arguments. Expected at least 4 (VisionIP Username Password RootPassword). Received {len(args)}. Run main.py -h for more info.")
                    exit(1)
        else:
            print(f"\nPlease enter Vision \\ Cyber Controller Information")
            print("")
            ip = input(f"Enter Management IP [{config.get('Vision', 'ip')}]: ") or config.get('Vision', 'ip')
            username = input(f"Enter Username [{config.get('Vision', 'username')}]: ") or config.get('Vision', 'username') 

            # Use getpass to securely handle password input
            stored_password = config.get('Vision', 'password')
            stars=''
            for char in stored_password:
                stars+='*'
            password = getpass.getpass(prompt=f"Enter Password [{stars}]: ") or stored_password if len(sys.argv) == 1 else stored_password

            # Check if entered password is different from the stored password
            if password != stored_password:
                if input("Password has changed. Do you want to save the new password? (yes/no): ").lower() in ['yes','y']:
                    config.set('Vision', 'password', password)

            #Do it again for the root password
            stored_rootpassword = config.get('Vision', 'rootpassword')
            stars=''
            for char in stored_rootpassword:
                stars+='*'
            rootpassword = getpass.getpass(prompt=f"Enter root Password [{stars}]: ") or stored_rootpassword if len(sys.argv) == 1 else stored_rootpassword

            # Check if entered password is different from the stored password
            if rootpassword != stored_rootpassword:
                if input("Root password has changed. Do you want to save the new password? (yes/no): ").lower() in ['yes','y']:
                    config.set('Vision', 'rootpassword', rootpassword)
            self.rootpassword = rootpassword

            # Save the management IP and username in the configuration
            config.set('Vision', 'ip', ip)
            config.set('Vision', 'username', username)

            # Save the configuration
            #save_config(config)
            config.save()

        stars=""
        for char in password:
            stars+='*'
        print("")
        update_log(f"Connecting to Management IP: {ip} Username: {username} Password: {stars}")

        # Perform the actual connection using the gathered information

        self.ip = ip
        self.auth_data = {"username": username, "password": password}
        self.sess = requests.Session()
        self.sess.headers.update({"Content-Type": "application/json"})
        
        login_url = f"https://{self.ip}/mgmt/system/user/login"
        try:
            r = self.sess.post(url=login_url, json=self.auth_data, verify=False)
            r.raise_for_status()  # Raises an error for HTTP errors
        except requests.exceptions.RequestException as err:
            update_log(err)  # Assuming update_log is defined elsewhere
            raise SystemExit(err)
        
        try:
            response = r.json()
            r.raise_for_status()
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.SSLError,
                requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout) as err:
            update_log(f"Error logging in to Vision at {ip}\n{r}\n{err}\nExiting.")
            raise SystemExit(err)

        if response['status'] == 'ok':
            self.sess.headers.update({"JSESSIONID": response['jsessionid']})
            update_log("Vision login successful")
        else:
            update_log(f"Error logging in to Vision at {ip}.\n{r}")
            raise Exception(f"Error logging in to Vision at {ip}.\n{r}")
            
    def __del__(self):
        if hasattr(self, "client"):
            self.client.close()
            print("Closed SSH session")

    def _post(self, URL, requestData = ""):
        try:
            r = self.sess.post(url=URL, verify=False, data=requestData)
        except any as err:
            raise err
        
        try:
            r.raise_for_status()
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.SSLError,
            requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout) as err:
            update_log(f"Error processing POST to {URL}.\n{r.json()}")
            raise err

        return r
    
    def _get(self, URL):
        try:
            r = self.sess.get(url=URL, verify=False)
        except any as err:
            raise err
        
        try:
            r.raise_for_status()
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.SSLError,
            requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout) as err:
            update_log(f"Error processing GET to {URL}.\n{r.json()}")
            raise err
        return r
    
    def isLocked(self, DeviceIP):
        print(f"Checking {DeviceIP} Lock Status")
        APIUrl = f"https://{self.ip}/mgmt/system/config/tree/device/byip/{DeviceIP}/lock"
        
        response = self._get(APIUrl).json()
        print(response)
        if response['status'] == 'ok':
            if "is not locked" in response['message']:
                return False
            else:
                return True
        else:
            update_log(f"Error checking lock status for {DeviceIP}.\n{response}")
            raise Exception(f"Error checking lock status for {DeviceIP}.\n{response}")

    def LockDevice(self, DeviceIP):
        print(f"Locking {DeviceIP}")
        APIUrl = f"https://{self.ip}/mgmt/system/config/tree/device/byip/{DeviceIP}/lock"
        
        response = self._post(APIUrl).json()
        if response['status'] == 'ok':
            update_log(f"Config lock acquired for {DeviceIP}")
            return True
        else:
            update_log(f"Error acquiring config lock for {DeviceIP}.\n{response}")
            raise Exception(f"Error acquiring config lock for {DeviceIP}.\n{response}")

    def UnlockDevice(self, DeviceIP):
        update_log(f"Unlocking {DeviceIP}")
        APIUrl = f"https://{self.ip}/mgmt/system/config/tree/device/byip/{DeviceIP}/unlock"
        
        response = self._post(APIUrl).json()
        if response['status'] == 'ok':
            update_log(f"Config lock released for {DeviceIP}")
            return True
        else:
            update_log(f"Error releasing config lock for {DeviceIP}.\n{response}")
            raise Exception(f"Error releasing config lock for {DeviceIP}.\n{response}")

    def CreateTechData(self, AlteonIP):
        update_log(f"Attempting to create TechData on {AlteonIP}")
        print("Please be patient. This may take several minutes.")
        APIUrl = f"https://{self.ip}/mgmt/device/byip/{AlteonIP}/config/techdump?usekey=no&IncludeDNSSEC=no&Includeper=no&IncludeUDP=no"
        
        response = self._post(APIUrl).json()
        
        if response['status'] == 'ok':
            update_log(f"Successfully created TechData on {AlteonIP}")
            return True
        else:
            update_log(f"Error creating TechData on {AlteonIP}.\n{response}")
            raise Exception(f"Error creating TechData on {AlteonIP}.\n{response}")
        
    def DownloadTechData(self, AlteonIP, file = None):
        '''Unused in '''
        filePath = f"./TechData_{datetime.datetime.now().strftime('%d%b%Y')}/"
        fileName = file or f"Techdata.{AlteonIP.replace(':','.')}.tgz"
        update_log(f"Attempting to download TechData from {AlteonIP} to {filePath}{fileName}")
        APIUrl = f"https://{self.ip}/mgmt/device/byip/{AlteonIP}/config/gettechdata"
        response = self._get(APIUrl)
        
        if response.status_code == 200:
            if not os.path.exists(filePath):
                os.makedirs(filePath)
            with open(filePath + fileName, "wb") as file:
                file.write(response.content)
            update_log("Techdata File Exported Successfully")
            return True
        else:
            update_log(f"Error downloading Techdata from {AlteonIP}. Response: {response}")
            raise Exception(f"{response}")
        
    def getDPDeviceList(self):
        APIUrl = f"https://{self.ip}/mgmt/system/config/itemlist/defensepro"
        r = self._get(APIUrl)
        if r.status_code == 200:
            return r.json()
        else:
            print("Error getting Device list.")
            update_log(f"Error getting Device list. Status code: {r.status_code}")
            raise Exception(f"Error getting Device list: {r}")
        
    def getDeviceData(self, DeviceIP):
        APIUrl = f"https://{self.ip}/mgmt/system/config/tree/device/byip/{DeviceIP}"
        r = self._get(APIUrl)
        if r.status_code == 200:
            return r.json()
        else:
            update_log(f"Error getting device data for {DeviceIP}")
            raise Exception(f"Error getting device data for {DeviceIP} - {r}")

    def getActiveVersion(self, DeviceIP):
        APIUrl = f"https://{self.ip}/mgmt/device/byip/{DeviceIP}/config/rsFSapplList?props=rsFSapplVersion,rsFSapplActive"
        r = self._get(APIUrl)
        if r.status_code == 200:
            data = r.json()
            # Find the rsFSapplVersion where rsFSapplActive is "1"
            active_version = next((item['rsFSapplVersion'] for item in data.get("rsFSapplList", []) if item.get("rsFSapplActive") == "1"), None)
            return active_version
        else:
            # Log and raise an exception if the request failed
            update_log(f"Error getting application data for {DeviceIP}")
            raise Exception(f"Error getting application data for {DeviceIP} - {r.status_code}: {r.text}")
    
    def getDPPolicies(self, DeviceIP):
        APIUrl = f"https://{self.ip}/mgmt/device/byip/{DeviceIP}/config/rsIDSNewRulesTable"
        r = self._get(APIUrl)
        if r.status_code == 200:
            return r.json()
        else:
            update_log(f"Error getting device data for {DeviceIP} - {r}")
            raise Exception(f"Error getting device data for {DeviceIP} - {r}")

    def getAttackReports(self, DeviceIP, StartTime, EndTime, filter_json=None):
        criteria = [
            {
                "type": "timeFilter",
                "inverseFilter": False,
                "field": "endTime",
                "lower": StartTime,
                "upper": EndTime,
                "includeUpper": False,
                "includeLower": False
            },
            {
                "type": "orFilter",
                "inverseFilter": False,
                "filters": [
                    {
                        "type": "termFilter",
                        "inverseFilter": False,
                        "field": "deviceIp",
                        "value": DeviceIP
                    }
                ]
            },
            {
                "type": "termFilter",
                "inverseFilter": True,
                "field": "enrichmentContainer.eaaf.eaaf",
                "value": "true"
            },
            {
                "type": "termFilter",
                "inverseFilter": True,
                "field": "ruleName",
                "value": "Packet Anomalies"
            }
        ]
        excludes = config.get("General","ExcludeFilters", "")
        if len(excludes) > 0:
            for exclude in excludes.split(","):
                criteria.append(
                        {
                            "type": "termFilter",
                            "inverseFilter": True,
                            "field": "name",
                            "value": exclude.strip()
                        }
                    )
        if filter_json:
            criteria.append(filter_json)

        data = {
            "criteria": criteria,
            "order": [
                {
                    "aggregationName": None,
                    "field": "endTime",
                    "order": "DESC",
                    "sortingType": "STRING",
                    "type": "Order"
                }
            ],
            "pagination": {
                "page": 0,
                "size": 10000,  # Fetch a larger amount per page if needed
                "topHits": 10000
            },
            "aggregation": None,
            "sourceFilters": [],
            "sourceIncludeFilters": [],
            "useFullTableScan": False,
            "validateReportStructure": False
        }

        APIUrl = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_ATTACK_REPORTS'
        update_log(f"Getting attack reports from {DeviceIP} using url {APIUrl} and query data {data}")

        all_data = []
        current_page = 0
        total_hits = 0
        metaData = None  # To store metaData from the first response

        while True:
            data["pagination"]["page"] = current_page
            response = self._post(APIUrl, json.dumps(data))
            
            if response.status_code == 200:
                response_data = response.json()
                if "data" in response_data:
                    all_data.extend(response_data["data"])  # Append the current page's data
                    if not metaData:
                        metaData = response_data.get("metaData", {})  # Get metaData only once
                    total_hits += len(response_data["data"])

                    # Stop if the current page has fewer results than the page size
                    if len(response_data["data"]) < data["pagination"]["size"]:
                        break  # No more data to fetch
                    
                    current_page += 1  # Move to the next page
                else:
                    update_log(f"No data in the response from {DeviceIP}")
                    break
            else:
                update_log(f"Error pulling attack report from {DeviceIP}")
                raise Exception(f"Error pulling attack report from {DeviceIP}")

        # Return the results in the same structure, with all data combined and the same metaData
        return {
            "data": all_data,
            "metaData": metaData or {"totalHits": total_hits}
        }

    def get_sample_data(self, attack_id):
        data = {
            "criteria": [
                {
                    "type": "termFilter",
                    "inverseFilter": False,
                    "field": "attackIpsId",
                    "value": attack_id
                }
            ],
            "order": [
                {
                    "type": "Order",
                    "order": "ASC",
                    "field": "startTime",
                    "aggregationName": None,
                    "sortingType": "LONG"
                }
            ],
            "pagination": None,
            "aggregation": None,
            "sourceFilters": []
        }

        APIUrl = f'https://{self.ip}/reporter/mgmt/monitor/reporter/reports-ext/DP_SAMPLE_DATA'
        print(f"Getting Sample Data using URL {APIUrl} and query data {data}")
        response = self._post(APIUrl, json.dumps(data))
        if response.status_code == 200:
            print(f"Successfully pulled sample data for attack id {attack_id}")
            return response.json()
        else:
            print(f"Error pulling sample data for attack id {attack_id}")
            raise Exception(f"Error pulling sample data for attack id {attack_id}")

    def getAttackRate(self, StartTime, EndTime, Units = "bps", selectedDevices = []):
        """Returns a JSON file containing the graph data from the specified time period.
        Units can be 'bps' or 'pps'"""
        
        APIUrl = f'https://{self.ip}/mgmt/vrm/monitoring/traffic/periodic/report'
        data = {
            "direction": "Inbound",
            "timeInterval": {
                "from": StartTime,
                "to": EndTime
            },
        }
        if Units:
            data.update({"unit": Units})
        if len(selectedDevices) > 0:
            data.update({"selectedDevices": selectedDevices})

        update_log(f"  Pulling attack rate. Time range: {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(StartTime/1000))} - {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(EndTime/1000))}")
        update_log(f"    url: {APIUrl} Query Data: {data}")

        response = self._post(APIUrl,json.dumps(data))
        update_log(f"    Response code: {response.status_code}")
        if response.status_code == 200:
            update_log(f"    Successfully pulled attack rate. Time range: {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(StartTime/1000))} - {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(EndTime/1000))}")
            update_log(f"    Response datapoints: {len(response.json()['data'])}")
            return response.json()
        else:
            update_log(f"Error pulling attack rate data. Time range: {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(StartTime/1000))} - {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(EndTime/1000))}")
            raise Exception(f"Error pulling attack rate data. Time range: {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(StartTime/1000))} - {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(EndTime/1000))}")
    def getAttackRate15sAvg(self, StartTime, EndTime, Units = "bps", selectedDevices = []):
        """
        Calls getAttackRate() in X-hour chunks and aggregates 'data' entries and min/max values from 'dataMap'.
        """
        POLL_INTERVAL_IN_HOURS = 1
        FOUR_HOURS_MS = POLL_INTERVAL_IN_HOURS * 60 * 60 * 1000  # X hours in milliseconds
        all_data = []
        global_min = None
        global_max = None

        current_start = StartTime
        while current_start < EndTime:
            current_end = min(current_start + FOUR_HOURS_MS, EndTime)
            try:
                chunk = self.getAttackRate(current_start, current_end, Units, selectedDevices)
                if not chunk:
                    continue

                # Append data points
                if "data" in chunk:
                    all_data.extend(chunk["data"])

                # Track global min and max
                data_map = chunk.get("dataMap", {})
                for key in ["minValue", "maxValue"]:
                    value = data_map.get(key)
                    if value:
                        if key == "minValue":
                            if (global_min is None) or (value["trafficValue"] < global_min["trafficValue"]):
                                global_min = value
                        elif key == "maxValue":
                            if (global_max is None) or (value["trafficValue"] > global_max["trafficValue"]):
                                global_max = value

            except Exception as e:
                update_log(f"❌ Failed chunk {current_start} - {current_end}: {e}")
            current_start = current_end
            time.sleep(.15)

        return {
            "data": all_data,
            "dataMap": {
                "minValue": global_min,
                "maxValue": global_max
            }
        }
    
    def connectSSH(self):
        #Initialize the client
        self.client = paramiko.SSHClient()
        #Auto accept and add the server's host key
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            update_log(f"Attempting root SSH to Vision at {self.ip}")
            self.client.connect(self.ip, 22, 'root', self.rootpassword)
            update_log("SSH connected successfully")
        except paramiko.AuthenticationException:
            update_log("root authentication failed. Please verify the root password!")
            exit(1)
        except paramiko.SSHException as sshException:
            update_log(f"Unable to establish SSH connection: {sshException}")
            exit(1)
        except Exception as e:
            update_log(f"Exception in establishing SSH connection to the server: {e}")
            exit(1)

    def getRawAttackSSH(self, AttackID):
        if not hasattr(self, "client"):
            self.connectSSH()

        command = f"""curl -X GET http://localhost:9200/dp-ts-attack-raw*/_search -H 'Content-Type: application/json' -d '
{{
  "query": {{
    "bool": {{
      "must": {{
        "term": {{
          "attackIpsId": "{AttackID}"
        }}
      }}
    }}
  }},
  "size": 1000
}}'"""
        update_log(f"SSH: Pulling graph data for attack {AttackID}")
        stdin, stdout, stderr = self.client.exec_command(command)
        #print("---stdout---")
        rawout = stdout.read().decode()
        outjson = json.loads(rawout)
        err = stderr.read().decode()
        print(err)

        if outjson.get('_shards',False):
            if outjson['_shards']['failed'] > 0:
                update_log(f"SSH: Pulling attack details for attack id {AttackID} has failed!")
                update_log(outjson)
                exit(1)
        
        #List of keys to include in output:
        includedKeys = ['startTime', 'maxAttackPacketRatePps', 'maxAttackRateBps']
        out = []
        for hit in outjson['hits']['hits']:
            curOut = {}
            source = hit['_source']
            for key in includedKeys:
                if key in source:
                    if key == 'startTime':
                        curOut.update({'timeStamp': source[key]})
                    else:
                        curOut.update({key.replace("maxAttackPacketRate","").replace("maxAttackRate",""): source[key]})
            if len(curOut) > 0:
                out.append({'row': curOut})

        return {'data': out}
