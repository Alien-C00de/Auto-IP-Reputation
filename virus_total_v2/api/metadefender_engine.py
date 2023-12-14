import asyncio
import json
import time
from datetime import datetime

import aiohttp
import numpy as np
import pandas as pd
from colorama import Fore, Style

from utils.config_util import Configuration
from utils.html_util import HTML_util

class meta_defender():
    meta_lst = []

    def __init__(self) -> None:
        pass
    
    async def __link_Formating(self, ip):
        config = Configuration()
        url = config.META_DEFENDER_ENDPOINT_URL + ip
        return url
    
    async def __formating_Input(self, decodedResponse):
        html = ""
        output = ""

        for response in decodedResponse:
            try:
                ipv4 = response["address"]
                print(Fore.CYAN + Style.BRIGHT + "[+] Processing", ipv4 + Fore.RESET)
                output = await self.__formating_Output(response, ipv4)
                html = html + output
                yield html
            except Exception as ex:
                code = "Error Code : " + str(response["error"]["code"])
                err_msg =  ' '.join(map(str, response["error"]["messages"])) 
                err = code + " " + err_msg
                self.meta_lst.append([err])
                msg = "[-] " + "MetaDefender Engine Error: Formating Input Error, " + err_msg
                print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
                continue

        print(Fore.CYAN + Style.BRIGHT + "[+] Finished Processing List --> Generating " + Fore.YELLOW + f"MetaDefender OPSWAT Report" + Fore.RESET)

    async def __formating_Output(self, decodedResponse, target_url):
        try:
            dataframe = pd.DataFrame.from_dict(decodedResponse, orient='index')

            dataframe.columns = [target_url]

            community_score = (decodedResponse["lookup_results"]["detected_by"])
            total_reviewers = len(decodedResponse["lookup_results"]["sources"])
            community_score_info = str(community_score) + ("/") + str(total_reviewers) + ("  :  security vendors flagged this as malicious")

            dataframe.loc['Community Score', :] = community_score_info
            last_analysis_date =  datetime.fromisoformat(decodedResponse["lookup_results"]["start_time"][:-5])
            dataframe.loc['Last Analysis Date', :] = last_analysis_date
            geo_info = ""
            if decodedResponse['geo_info']:
                geo_info = "County : " + decodedResponse["geo_info"]["country"]["name"] + "  City : " + decodedResponse["geo_info"]["city"]["name"] + "  Location : " + str(decodedResponse["geo_info"]["location"]["latitude"]) + " , " + str(decodedResponse["geo_info"]["location"]["longitude"])
            else:
                geo_info = "There is no information available about the location of this IP address."
            dataframe.loc['Geo Info', :] = geo_info 
            
            dataframe.sort_index(inplace=True)
            # change column labels
            col_labels = {'status': 'Result', 'provider': 'Source',
                        'detect_time': 'Last Detected', 'update_time': 'Last Update'}

            self.meta_lst.append([community_score, geo_info])

            mt_analysis_result = pd.DataFrame(decodedResponse["lookup_results"]["sources"])
            mt_analysis_result.rename(columns=col_labels, inplace=True)
            
            dataframe = dataframe.drop(['geo_info'], axis="index")
            dataframe = dataframe.drop(['lookup_results'], axis="index")
            dataframe = dataframe.drop(['address'], axis="index")
            
            html1 = dataframe.to_html(render_links=True, escape=False)
            html2 = mt_analysis_result.to_html(render_links=True, escape=False, index=False)
            htmlValue = html1 + html2
        except Exception as ex:
            error_msg = ex.args[0]
            msg = "[-] " + "MetaDefender Engine Error: " + target_url + " Formating Output Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            htmlValue = msg
        return htmlValue

    async def generate_Report(self, target_url, isFile=False):
        config = Configuration()
        htmlTags = ""
        tasks = []
        decodedResponse = []

        headers = {
                    'apikey': config.META_DEFENDER_API_KEY
                    }
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                if isFile:
                    ips = list(target_url)
                else:
                    ips = list(target_url.split(","))
                for ip in ips:
                    url = await self.__link_Formating(ip)
                    tasks.append(asyncio.create_task(session.request(method="GET", url=url)))

                responses = await asyncio.gather(*tasks)
                for response in responses:
                    # load returned json from virustotal into a python dictionary called decodedResponse
                    decodedResponse.append(await response.json())

            async for val in self.__formating_Input(decodedResponse):
                htmlTags = val
            return htmlTags

        except Exception as ex:
            error_msg = ex.args[0]
            msg = "[-] " + "MetaDefender Error: " + ip + " Gererate Report Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            return msg

    async def meta_defender_Report(self, timestamp, target_url, isFile=False):
        config  = Configuration()
        if isFile:
            iplist = []
            with open(target_url, "r") as url_file:
                for url in url_file.readlines():
                    iplist.append(url.strip())
            finalhtml = await self.generate_Report(iplist, isFile=True)
        else:
            finalhtml = await self.generate_Report(target_url, isFile=False)
        
        summary_lst = await self.__formating_list()

        HTML_Report = HTML_util(finalhtml)
        await HTML_Report.outputHTML(config.META_DEFENDER_REPORT_FILE_NAME, config.META_DEFENDER_REPORT_TITLE, config.META_DEFENDER_REPORT_SUB_TITLE, timestamp)

        return summary_lst

    
    async def __formating_list(self):
        return self.meta_lst
