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
            vt_lst = args[1]
            abs_lst = args[2]
            meta_lst = args[3]
            file_name = "Final_Summary"
            
            vt_dt = pd.DataFrame(vt_lst, columns=['VirusTotal IP', 'VirusTotal Score'])
            abs_dt = pd.DataFrame(abs_lst, columns=['AbuseIpDB IP', 'AbuseIpDB Score'])
            err_code = str(meta_lst[0][0])
            if '429000' in err_code:
                meta_dt = pd.DataFrame(meta_lst, columns=['MetaDefender IP', 'MetaDefender Score'])
            else: 
                meta_dt = pd.DataFrame(meta_lst, columns=['MetaDefender IP', 'MetaDefender Score', 'Geo Info']) 

            final_df = pd.concat([vt_dt, abs_dt, meta_dt], axis=1)

            # timestamp = int(datetime.datetime.now().timestamp())
            file_name_csv = '%s_%s.csv' % (file_name.replace("/", "_"), timestamp)
            file_name_csv = os.path.join('./output', file_name_csv)
            final_df.to_csv(file_name_csv, index=False, header=True)

            print(Fore.MAGENTA + Style.BRIGHT + f"[+] Final Summary" + Fore.WHITE + Style.BRIGHT, file_name_csv.partition("output/")[-1],  Fore.MAGENTA + Style.BRIGHT  + f"File Is Ready\n", Fore.RESET)
        except Exception as ex:
            error_msg = ex.args[0]
            msg = "[-] " + "Error: Create CSV, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)