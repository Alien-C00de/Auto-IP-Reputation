# Auto IP Reputation Tool

The Auto IP Reputation Tool is designed to provide comprehensive reports on IP reputation, utilizing data from multiple trusted sources. This tool is essential for cybersecurity analysts and network administrators who need to assess the trustworthiness of IP addresses.

## Supported Engines
This tool gathers data using the following engines:
- **Virus Total**: [virustotal.com](https://www.virustotal.com/)
- **MetaDefender**: [metadefender.opswat.com](https://metadefender.opswat.com/)
- **AbuseIPDB**: [abuseipdb.com](https://www.abuseipdb.com/)

## Installation
To install and run the Auto IP Reputation Tool, follow these steps:

1. Install the required Python libraries:
    ```bash
    pip install Pandas
    pip install requests
    pip install aiohttp
    pip install configparser
    ```

2. Install wkhtmltopdf for generating PDF reports (for Debian/Ubuntu):
    ```bash
    sudo apt-get install wkhtmltopdf
    ```

3. Install pdfkit via pip:
    ```bash
    pip install pdfkit
    ```

## Usage

Execute the tool using the following commands:

- For a single IP search:
    ```bash
    python main.py -s 8.8.8.8
    ```

- For a list of IP searches from a file:
    ```bash
    python main.py -i target_ip.txt
    ```

## Files

- `./config/conftg.ini`: This file contains API keys and URL links. Please obtain your API key to run the program.
- `target_ip.txt`: Contains a sample list of IPs for search. You can also add your own list of IPs to search.

## Report Files

HTML report files are located under the `./output` directory:

1. `virus_total_timestamp.html`
2. `meta_defender_timestamp.html`
3. `abuseIpDB_timestamp.html`

PDF report files can also be found under the `./output` directory:

1. `virus_total_timestamp.pdf`
2. `meta_defender_timestamp.pdf`
3. `abuseIpDB_timestamp.pdf`

## CSV Final Summary Report

The final summary report is available as:

`final_summary_timestamp.csv`

🚀 Happy IP reputation analysis! 🚀
