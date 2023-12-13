# Auto-IP-Reputation Tool
This is auto IP Reputation Tool with following Engine. 
Generates details reports and summary report.

1. Virus Total ([virustotal.com](https://www.virustotal.com))
2. MetaDefender (https://metadefender.opswat.com/)
3. AbuseIPDB (https://www.abuseipdb.com/)
   
Install following library to run the code.

    pip install Pandas
    pip install requests
    pip install configparser
    Install wkhtmltopdf (for Debian/Ubuntu)
    sudo apt-get install wkhtmltopdf -  (https://pypi.org/project/pdfkit/)
    pip install pdfkit

Following are the command to run the code.

    For Single ip search --> python main.py -s 8.8.8.8

    For List of IP search from file --> python main.py -i target_ip.txt

Files

    ./config/conftg.ini - This file conain API keys and URL links. 
    Please get your API key to run the program.
    
    File contain sample list of IP for search - target_ip.txt
    
    HTML report files under ./output directory 
      1. virus_total_timestamp.html
      2. meta_defender_timestamp.html
      3. abuseIpDB_timestamp.html
      
    PDF report files under ./output directory
      1. virus_total_timestamp.pdf
      2. meta_defender_timestamp.pdf
      3. abuseIpDB_timestamp.pdf
    
    CSV Final Summary Report - final_summary_timstamp.csv
    

