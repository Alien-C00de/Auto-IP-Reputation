import asyncio
import datetime
import pandas as pd

from api.metadefender_engine import meta_defender
from api.virus_total_engine import virus_total
from api.abuseIpDB_engine import abuseIPDB
from api.criminalip_engine import criminalip
# from api.cisco_talos_engine import cisco_talos
from utils.csv_util import CSV_util



class engine():
    def __init__(self) -> None:
        pass

    async def all_Analysis(self, target_url, isFile = False):

        vt_lst = []
        meta_lst = []
        abs_lst = []
        timestamp  =  pd.Timestamp.now().strftime("%Y-%m-%d_%H-%M-%S")

        virus_total_eng = virus_total()
        meta_defender_eng = meta_defender()
        abuseIPDB_eng = abuseIPDB()
        criminalip_eng = criminalip()
        # cisco_talos_eng = cisco_talos()

        #Run report in parallel
        vt_lst, abs_lst, meta_lst = await asyncio.gather(
                virus_total_eng.virus_total_Report(timestamp, target_url, isFile),
                abuseIPDB_eng.abuseipDB_Report(timestamp, target_url, isFile),
                meta_defender_eng.meta_defender_Report(timestamp, target_url, isFile))
                # criminalip_eng.criminal_ip_Report(target_url, isFile))
                # cisco_talos_eng.cisco_talos_Report(target_url, isFile))
        
        await self.summary_report(timestamp, target_url, isFile, vt_lst, abs_lst, meta_lst)

    async def summary_report(self, *args):
        csv = CSV_util()
        await csv.create_csv(*args)