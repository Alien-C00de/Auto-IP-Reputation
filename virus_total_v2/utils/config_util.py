import os
from configparser import ConfigParser


class Configuration:
     # Reading Configs
     config = ConfigParser()
     config_path = os.path.join("./config", "config.ini")
     config.read(config_path)
    
     'General' in config
     VERSION = config['General']['VERSION']
     AUTHOR = config['General']['AUTHOR']
     YEAR = config['General']['YEAR']

     'VirusTotal' in config
     VIRUS_TOTAL_API_KEY =  config['VirusTotal']['API_KEY']   
     VIRUS_TOTAL_ENDPOINT_URL = config['VirusTotal']['ENDPOINT_URL'] 
     VIRUS_TOTAL_REPORT_LINK = config['VirusTotal']['REPORT_LINK']  
     VIRUS_TOTAL_REPORT_FILE_NAME = config['VirusTotal']['FILE_NAME']
     VIRUS_TOTAL_REPORT_TITLE = config['VirusTotal']['REPORT_TITLE']
     VIRUS_TOTAL_REPORT_SUB_TITLE = config['VirusTotal']['REPORT_SUB_TITLE']

     'MetaDefender' in config
     META_DEFENDER_API_KEY = config['MetaDefender']['API_KEY']
     META_DEFENDER_ENDPOINT_URL = config['MetaDefender']['ENDPOINT_URL']
     META_DEFENDER_REPORT_FILE_NAME = config['MetaDefender']['FILE_NAME']
     META_DEFENDER_REPORT_TITLE = config['MetaDefender']['REPORT_TITLE']
     META_DEFENDER_REPORT_SUB_TITLE = config['MetaDefender']['REPORT_SUB_TITLE']

     'AbuseIPDB' in config
     ABUSEIPDB_API_KEY = config['AbuseIPDB']['API_KEY']
     ABUSEIPDB_ENDPOINT_URL = config['AbuseIPDB']['ENDPOINT_URL']
     ABUSEIPDB_REPORT_FILE_NAME = config['AbuseIPDB']['FILE_NAME']
     ABUSEIPDB_REPORT_TITLE = config['AbuseIPDB']['REPORT_TITLE']
     ABUSEIPDB_REPORT_SUB_TITLE = config['AbuseIPDB']['REPORT_SUB_TITLE']

     'CriminalIP' in config
     CRIMINAL_IP_API_KEY = config['CriminalIP']['API_KEY']
     CRIMINAL_IP_ENDPOINT_URL = config['CriminalIP']['ENDPOINT_URL']
     CRIMINAL_IP_REPORT_FILE_NAME = config['CriminalIP']['FILE_NAME']
     CRIMINAL_IP_REPORT_TITLE = config['CriminalIP']['REPORT_TITLE']
     CRIMINAL_IP_REPORT_SUB_TITLE = config['CriminalIP']['REPORT_SUB_TITLE']

     'CISCO_Talos' in config
     TALOS_ENDPOINT_URL = config['CISCO_Talos']['ENDPOINT_URL']
     TALOS_REFERER = config['CISCO_Talos']['REFERER']
     TALOS_REPORT_FILE_NAME = config['CISCO_Talos']['FILE_NAME']
     TALOS_REPORT_TITLE = config['CISCO_Talos']['REPORT_TITLE']
     TALOS_REPORT_SUB_TITLE = config['CISCO_Talos']['REPORT_SUB_TITLE']
