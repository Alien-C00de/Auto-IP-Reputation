import asyncio
import aiohttp
import base64
import hashlib
import re
import time

import aiohttp
import pandas as pd
from colorama import Back, Fore, Style

from utils.config_util import Configuration
from utils.html_util import HTML_util


class virus_total():
    vt_lst = []

    def __init__(self, islist=False):
        self.__islist = islist

    # begin function for encrypting our hyperlink string to sha256
    async def __encrypt_string(self, hash_string):
        sha_signature = \
            hashlib.sha256(hash_string.encode()).hexdigest()
        return sha_signature

    async def __link_Formating(self, target_url):
        config = Configuration()
        url_id = base64.urlsafe_b64encode(
            target_url.encode()).decode().strip("=")
        # amend the virustotal apiv3 url to include the unique generated url_id
        url = config.VIRUS_TOTAL_ENDPOINT_URL + url_id
        return url

    async def __find_ip_address(self, string):
        pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        match = re.search(pattern, string)
        if match:
            return match.group()
        else:
            return None

    async def formating_Input(self, decodedResponse):
        html = ""
        output = ""
        for response in decodedResponse:
            try:
                ipv4 = await self.__find_ip_address(response["data"]["attributes"]["url"])
                print(Fore.CYAN + Style.BRIGHT + "[+] Processing", ipv4 + Fore.RESET)
                output = await self.__formating_Output(response, ipv4)
                html = html + output
                yield html
            except Exception as ex:
                code = "Error Code : " + str(response["error"]["code"])
                err_msg = response["error"]["message"]
                self.vt_lst.append([code, err_msg])
                msg = "[-] " + "VirusTotal Engine Error: Formating Input Error, " + err_msg
                print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
                continue

        print(Fore.CYAN + Style.BRIGHT + "[+] Finished Processing List --> Generating " + Fore.YELLOW  + f"Virus Total Report" + Fore.RESET)

    async def __formating_Output(self, decodedResponse, target_url):
        try:
            config = Configuration()
            # grab "last_analysis_date" key data to convert epoch timestamp to human readable date time formatted
            epoch_time = (decodedResponse["data"]["attributes"]["last_analysis_date"])
            # the original key last_analysis_date from the returned virustotal json will be removed and replaced with an updated last_analysis_date value that's now human readable
            time_formatted = time.strftime('%c', time.localtime(epoch_time))
            # create sha256 encoded vt "id" of each url or ip address to generate a hypertext link to a virustotal report in each table
            # create a string value of the complete url to be encoded
            UrlId_unEncrypted = ("http://" + target_url + "/")
            # encrypt and store our sha256 hashed hypertext string as
            sha_signature = await self.__encrypt_string(UrlId_unEncrypted)
            # create the hypertext link to the virustotal.com report
            vt_urlReportLink = (config.VIRUS_TOTAL_REPORT_LINK + sha_signature)
            # strip the "data" and "attribute" keys from the decodedResponse dictionary and only include the keys listed within "attributes" to create a more concise list stored in a new dictionary called a_json
            filteredResponse = (decodedResponse["data"]["attributes"])
            lastAnalysisResponse = decodedResponse["data"]["attributes"]["last_analysis_results"]
            # create an array of keys to be removed from attributes to focus on specific content for quicker/higher-level analysis
            keys_to_remove = ["last_http_response_content_sha256", "last_http_response_code", "last_http_response_content_length",
                                "url", "last_analysis_date", "tags", "last_submission_date", "threat_names",
                                "last_http_response_headers", "categories", "last_modification_date", "title",
                                "outgoing_links", "first_submission_date", "total_votes", "type", "id",
                                "links", "trackers", "last_http_response_cookies", "html_meta", "last_analysis_results"]

            # iterate through the filteredResponse dictionary using the keys_to_remove array and pop to remove additional keys listed in the array
            for key in keys_to_remove:
                filteredResponse.pop(key, None)
            self.vt_lst.append([target_url, decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"]])
            # orient="index" is necessary in order to list the index of attribute keys as rows and not as columns
            dataframe = pd.DataFrame.from_dict(filteredResponse, orient='index')
            dataframe.columns = [target_url]
            # grab "malicious" key data from last_analysis_stats to create the first part of the community_score_info
            community_score = (decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"])
            # grab the sum of last_analysis_stats to create the total number of security vendors that reviewed the URL for the second half of the community_score_info
            total_vt_reviewers = (decodedResponse["data"]["attributes"]["last_analysis_stats"]["harmless"]) + \
                                    (decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"]) + \
                                    (decodedResponse["data"]["attributes"]["last_analysis_stats"]["suspicious"]) + \
                                    (decodedResponse["data"]["attributes"]["last_analysis_stats"]["undetected"]) + \
                                    (decodedResponse["data"]["attributes"]["last_analysis_stats"]["timeout"])

            # create a custom community score using community_score and the total_vt_reviewers values
            community_score_info = str(community_score) + ("/") + str(total_vt_reviewers) + ("  :  security vendors flagged this as malicious")
            # amend dataframe with extra community score row
            dataframe.loc['Community Score', :] = community_score_info
            dataframe.loc['Last Analysis Date', :] = time_formatted
            dataframe.loc['VirusTotal_Report_Link', :] = vt_urlReportLink
            # change row labels name
            row_labels = {'last_analysis_stats': 'Last Analysis Stats', 'reputation': 'Reputation', 
                          'times_submitted': 'Times Submitted', 'last_final_url': 'Last Final URL'}

            dataframe.rename(index=row_labels, inplace=True)
            # sort dataframe index in alphabetical order to put the community score at the top
            dataframe.sort_index(inplace=True)
            # change column labels
            col_labels = {'category': 'Category', 'result': 'Result', 'method': 'Method', 'engine_name': 'Engine Name'}

            vt_analysis_result = pd.DataFrame.from_dict((lastAnalysisResponse), orient="index")
            vt_analysis_result.sort_values(by=['category'], ascending=False)
            vt_analysis_result.rename(columns=col_labels, inplace=True)

            # dataframe is output as an html table, and stored in the html variable
            html1 = dataframe.to_html(render_links=True, escape=False)
            html2 = vt_analysis_result.to_html(render_links=True, escape=False)
            htmlValue = html1 + html2
        except Exception as ex:
            error_msg = ex.args[0]
            msg = "[-] " + "VirusTotal Engine Error: " + target_url + " Formating Output Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            htmlValue = msg
        return htmlValue

    async def generate_Report(self, target_url, isFile=False):
        config = Configuration()
        htmlTags = ""
        tasks = []
        decodedResponse = []
        # while you can enter your API key directly for the "x-apikey" it's not recommended as a "best practice" and should be stored-accessed separately in a .env file (see comment under "load_dotenv()"" for more information
        headers = {
            "Accept": "application/json",
            "x-apikey": config.VIRUS_TOTAL_API_KEY
        }
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                if isFile:
                    ips = list(target_url)
                else:
                    ips = list(target_url.split(","))
                for ip in ips:
                    url = await self.__link_Formating(ip)
                    tasks.append(asyncio.create_task(
                        session.request(method="GET", url=url)))

                responses = await asyncio.gather(*tasks)
                for response in responses:
                    # load returned json from virustotal into a python dictionary called decodedResponse
                    decodedResponse.append(await response.json())

            async for val in self.formating_Input(decodedResponse):
                htmlTags = val
            return htmlTags

        except Exception as ex:
            error_msg = ex.args[0]
            msg = "[-] " + "VirusTotal Error: " + ip + " Gererate Report Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            return msg

    async def virus_total_Report(self, timestamp, target_url, isFile=False):
        config = Configuration()
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
        await HTML_Report.outputHTML(config.VIRUS_TOTAL_REPORT_FILE_NAME, config.VIRUS_TOTAL_REPORT_TITLE, config.VIRUS_TOTAL_REPORT_SUB_TITLE, timestamp)

        return summary_lst
    
    async def __formating_list(self):
        return self.vt_lst
