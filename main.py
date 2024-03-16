import requests
# from bs4 import BeautifulSoup
from datetime import datetime
# from selenium import webdriver
# from selenium.webdriver.common.by import By

import json
import requests

cve_json_databases = [r"https://services.nvd.nist.gov/rest/json/cves/2.0",
                      r"https://services.nvd.nist.gov/rest/json/cvehistory/2.0"]

cve_database = [r"https://vulmon.com/vulnerabilitydetails?qid=CVE-2017-0144",
                r"https://www.exploit-db.com/search?cve=CVE-2017-0144",
                r"https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2017-0144",
                r"https://vulners.com/search?query=CVE-2017-0144",
                r"https://vulmon.com/vulnerabilitydetails?qid=CVE-2017-0144"]


def cve_exist(cve_id):
    api_url = cve_json_databases[0]
    # for api_url_1 in cve_json_databases:
    # for api_url_2 in cve_database:
    # Send GET request and handle response
    response = requests.get(api_url)
    # Check for successful response
    if response.status_code == 200:
        # Parse the JSON response
        data = response.json()

        # Check if the CVE exists in the JSON data
        for vulnerability in data.get("vulnerabilities", []):
            cve = vulnerability.get("cve", {})
            if cve.get("id") == cve_id:
                print(f"{cve_id} exists in the JSON data.")
                sourceIdentifier = cve.get("sourceIdentifier")
                published = cve.get("published")
                lastModified = cve.get("lastModified")
                vulnStatus = cve.get("vulnStatus")
                descriptions = cve.get("descriptions")
                descriptions1 = descriptions[0]["value"]
                print(f'Description: {descriptions1}')
                metrics = cve.get("metrics")
                metrics_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = metrics_data["baseScore"]
                access_vector = metrics_data["vectorString"]
                severity = metrics["cvssMetricV2"][0]["baseSeverity"]
                references = cve.get("references")
                print(sourceIdentifier, published, lastModified, vulnStatus)
                print(f'{cvss_score} {severity}, Access vector: {access_vector}')
                for ref_url in references:
                    print(ref_url["url"])
                ###############   WE HAVE TO ADD URL DESCRIPTION FOR URL
                return  # Exit the function once CVE is found

        print(f"{cve_id} does not exist in the JSON data.")

    else:
        print(f"Error: API request failed with status code {response.status_code}")


if __name__ == "__main__":
    """ while True:
         try:
             cve_input_year = int(input("Insert CVE year: "))
             if 1999 <= cve_input_year <= datetime.now().year:
                 if len(str(cve_input_year)) != 4:
                     print("Invalid input. Please enter a 4-character year.")
                     continue
             else:
                 print("Please enter correct year!")
                 continue
         except ValueError:
             print("Please enter a numeric value for the year.")
             continue
 
         while True:  # Nested loop for the CVE number input
 
             try:
                 cve_input_number = input("Insert number of CVE: ")
                 cve_input_number1 = ""
                 if int(cve_input_number) > 0:
                     for i in cve_input_number:
                         i = int(i)
                         if type(i) is int:
                             cve_input_number1 = cve_input_number1 + str(i)
 
                 if len(str(cve_input_number)) < 4:
                     print("Invalid input. Must be 4-digits or greater!.")
                     continue
                 else:
                     break  # Exit the CVE number input loop
             except ValueError:
                 print("Please enter a numeric value for the CVE number.")
                 continue
 
         # This part executes only if both year and number are 4 characters long
         cve_id = "CVE-" + str(cve_input_year) + "-" + str(cve_input_number)
         cve_exist(cve_id)
         break  # Exit the main loop"""
    cve_exist("CVE-1999-0095")

    # print(vuln_severity(CVE))
# print(vuln_description(CVE))
