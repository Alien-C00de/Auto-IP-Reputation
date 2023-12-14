import argparse
import asyncio
import os
from time import perf_counter

import colorama
from colorama import Back, Fore, Style

from api.engine import  engine 
from utils.config_util import Configuration


async def Main() -> None:
    # Parser to take the arguments
    config = Configuration()
    colorama.init (autoreset= True)

    parser = argparse.ArgumentParser(description="Python Tool: Generating Report From VirusTotal API's for IP & URL")
    parser.add_argument("-s", "--single-entry", help="ip or url for analysis")
    parser.add_argument("-i", "--ip-list", help="bulk ip address analysis")
    parser.add_argument("-V", "--version", help="show program version", action="store_true")
    args = parser.parse_args()

    start_time = perf_counter()

    os.system('clear')
    search_engin = engine() 

    try:
        if args.single_entry:
            print(f"[+] Reading IP : {args.single_entry.strip()}", flush=True)
            await search_engin.all_Analysis(args.single_entry.strip(), isFile=False)
        elif args.ip_list:
            print(f"[+] Reading List of IP / URL From {args.ip_list.strip()} File", flush=True)
            await search_engin.all_Analysis(args.ip_list.strip(), isFile=True)
        elif args.version:
            print(f"\nPython Tool: Generating IP Reputation Report From Multi Reputation Website.\nDeveloped by: {config.AUTHOR} {config.YEAR} ver: {config.VERSION}")
        else:
            print("usage: main.py [-h] [-s SINGLE_ENTRY] [-i IP_LIST] [-V]")
    except Exception as ex:
        error_msg = str(ex.args[0])
        msg = "[-] " + "Main Error: Reading Error, " + error_msg
        print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
        
    print(Fore.BLUE + Style.BRIGHT + f"\n[+] Total Time Taken: {round(perf_counter() - start_time, 2)} Seconds \n", flush=True)
    print(Style.RESET_ALL)
    
if __name__ == '__main__':
    asyncio.run(Main())