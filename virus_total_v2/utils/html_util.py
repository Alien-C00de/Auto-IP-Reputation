import asyncio
import datetime
import os
import time

import pdfkit
from colorama import Back, Fore, Style
from utils.config_util import Configuration


class HTML_util:

    def __init__(self, html):
        self.__html = html
    
    # Create new folders
    async def __create_dirs(self, root, subfolders=None):
        root = root if subfolders == None else f'{root}/{subfolders}/'
        if not os.path.exists(root):
            os.makedirs(f'{root}', exist_ok=True)

    async def outputHTML(self, file_name, report_title, report_sub_title, timestamp):
        # save html with css styled boilerplated code up to the first <body> tag to a variable named "header"
        config = Configuration()
        header = """<!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Automated VirusTotal Analysis Report | API v3</title>
            <style>
                body {
                font-family: Sans-Serif;
                color: #1d262e;
                }
                h1 {
                    font-size: 1.25em;
                    margin: 50px 0 0 50px;
                }
                h2 {
                    font-size: .75em;
                    font-weight:normal;
                    margin: 5px 0 15px 50px;
                    color: #7d888b;
                }
                h3 {
                    font-size: 1em;
                    font-weight:normal;
                    margin: 0 0 20px 50px;
                    color: #7d888b;
                }
                h4 {
                    font-size: .750em;
                    font-weight:normal;
                    margin: 0 0 20px 50px;
                    text-align:right;
                    color: orange;
                }
                table {
                    text-align: left;
                    width: 100%;
                    border-collapse: collapse;
                    border: none;
                    padding: 0;
                    margin-left: 50px;
                    margin-bottom: 40px;
                    max-width: 1200px;
                }
                th { 
                    text-align: left;
                    border:none;
                    padding: 10px 0 5px 10px;
                    margin-left: 10px;
                }
                tr { 
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                    border-top: none;
                    border-left: none;
                    border-right: none;
                    padding-left: 10px;
                    margin-left: 0;
                }
                td { 
                    border-bottom: none;
                    border-top: none;
                    border-left: none;
                    border-right: none;
                    padding-left: 10px;
                }
                tr th {
                    padding: 10px 10px 5px 10px;
                }

            </style>
        </head>
        <body>
        <h1 class="reportHeader">""" + report_title + """</h1>
        <h2>""" + report_sub_title + """</h2>
        """
        # add report timestamp
        report_timestamp = str("<h3>" + time.strftime('%c', time.localtime(time.time())) + "</h3>")

        # save html closing </ body> and </ html> tags to a variable named "footer"
        footer = """
             <script>
                const td_ele = document.querySelectorAll("td");
                function change_td_ele_color() {
                    for (let i = 0; i < td_ele.length; i++) { // iterate all thorugh td
                        if(td_ele[i].innerText.includes("malicious")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/malicious/g,'<span style="color:red">malicious</span>');                            
                        }
                        if(td_ele[i].innerText.includes("malware")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/malware/g,'<span style="color:red">malware</span>');                            
                        }
                        if(td_ele[i].innerText.includes("suspicious")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/suspicious/g,'<span style="color:orange">suspicious</span>');                            
                        }
                        if(td_ele[i].innerText.includes("undetected")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/undetected/g,'<span style="color:grey">undetected</span>');                            
                        }
                        if(td_ele[i].innerText.includes("unrated")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/unrated/g,'<span style="color:grey">unrated</span>');                
                        }
                        if(td_ele[i].innerText.includes("harmless")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/harmless/g,'<span style="color:green">harmless</span>');                            
                        }
                        if(td_ele[i].innerText.includes("clean")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/clean/g,'<span style="color:green">clean</span>');                            
                        }
                    }
                }        
                change_td_ele_color();
            </script>
            <h2 align="right">Developed by : """ + config.AUTHOR  + """  """ +  config.YEAR + """ ver: """ + config.VERSION + """</h2>
            </body>
            </html>
        """
        # create and open the new VirusTotalReport.html file
        # timestamp = int(datetime.datetime.now().timestamp())
        file_name_html = '%s_%s.html' % (file_name.replace("/", "_"), timestamp)
        file_name_pdf = '%s_%s.pdf' % (file_name.replace("/", "_"), timestamp)
        await self.__create_dirs('output')
    
        file_name_html = os.path.join('./output', file_name_html)
        file_name_pdf = os.path.join('./output', file_name_pdf)

        with open(file_name_html, "a", encoding='UTF-8') as f: 
            f.write(header)
            f.write(report_timestamp)
            for x in self.__html:
                f.write(x)
            f.write(footer)

        filenameH = file_name_html.partition("output/")[-1]
        print(Fore.GREEN + Style.BRIGHT + f"\n[+] HTML" + Fore.WHITE + Style.BRIGHT, filenameH,  Fore.GREEN + Style.BRIGHT  + f"File Is Ready", Fore.RESET)

        #Create pdf file from HTML file
        options = {
            'page-size': 'A4',
            'margin-top': '0.30in',
            'margin-right': '0.60in',
            'margin-bottom': '0.30in',
            'margin-left': '0.60in',
            'footer-right': '[page]',
            'encoding': "UTF-8",
            'custom-header': [
                ('Accept-Encoding', 'gzip')
            ]
        }
        filenameP = file_name_pdf.partition("output/")[-1]
        pdfkit.from_file(file_name_html, file_name_pdf, options=options)
        print(Fore.GREEN + Style.BRIGHT + f"[+] PDF" + Fore.WHITE + Style.BRIGHT, filenameP,  Fore.GREEN + Style.BRIGHT  + f"File Is Ready\n", Fore.RESET)

