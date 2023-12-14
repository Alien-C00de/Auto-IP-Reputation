import asyncio
import datetime
import pandas as pd
import os
from colorama import Fore, Style

class CSV_util:

    def __init__(self) -> None:
        pass

    async def create_csv(self, *args):
        try:
            timestamp = str(args[0])
            target_url = args[1]
            isFile = bool(args[2])
            vt_lst = args[3]
            abs_lst = args[4]
            meta_lst = args[5]
            file_name = "Final_Summary"

            ips = []            
            if isFile:
                with open(target_url, "r") as url_file:
                    for url in url_file.readlines():
                        ips.append(url.strip())
                    ips = list(ips)
            else:
                ips =list(target_url.split(",")) 

            ips_dt = pd.DataFrame(ips, columns=['IP Address'])

            vt_err_code = str(vt_lst[0])
            if 'Quota exceeded' in vt_err_code:
                vt_dt = pd.DataFrame(vt_lst, columns=['VirusTotal Error'])
            else: 
                vt_dt = pd.DataFrame(vt_lst, columns=['VirusTotal community Score']) 

            abs_err_code = str(abs_lst[0])
            if '429' in abs_err_code:
                abs_dt = pd.DataFrame(abs_lst, columns=['AbuseIpDB Error'])
            else: 
                abs_dt = pd.DataFrame(abs_lst, columns=['AbuseIpDB Confidence Score']) 

            # abs_dt = pd.DataFrame(abs_lst, columns=[ 'AbuseIpDB Confidence Score'])
            meta_err_code = str(meta_lst[0])
            if '429000' in meta_err_code:
                meta_dt = pd.DataFrame(meta_lst, columns=['MetaDefender Error'])
            else: 
                meta_dt = pd.DataFrame(meta_lst, columns=['MetaDefender community Score', 'Geo Info']) 

            final_df = pd.concat([ips_dt, vt_dt, abs_dt, meta_dt], axis=1)

            # timestamp = int(datetime.datetime.now().timestamp())
            file_name_csv = '%s_%s.csv' % (file_name.replace("/", "_"), timestamp)
            file_name_csv = os.path.join('./output', file_name_csv)
            final_df.to_csv(file_name_csv, index=False, header=True)

            print(Fore.MAGENTA + Style.BRIGHT + f"[+] Final Summary" + Fore.WHITE + Style.BRIGHT, file_name_csv.partition("output/")[-1],  Fore.MAGENTA + Style.BRIGHT  + f"File Is Ready\n", Fore.RESET)
        except Exception as ex:
            error_msg = ex.args[0]
            msg = "[-] " + "Error: Create CSV, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)