import requests
from bs4 import BeautifulSoup
import csv
from io import StringIO
from main import cve_id

CVE = "CVE-2017-0144"


# from main import cve_id
def vuln_finder(cve):
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'}
    request = requests.get('https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cve, headers=headers)
    soup = BeautifulSoup(request.text, 'html.parser')
    exists = soup.find("h2").text.strip()
    if exists == f"ERROR: Couldn't find '{cve}'":
        print("There is no cve in this id")


vuln_finder('CVE-1999-0000')


def cve_parse_json(cve_id):
    api_url = r"https://services.nvd.nist.gov/rest/json/cves/2.0"
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
                descriptions = cve.get("descriptions")
                descriptions1 = descriptions[0]["value"]
                print(f'Description: {descriptions1}')

                references = cve.get("references")
                print(sourceIdentifier)

                # CVSS2 SCORE
                metrics = cve.get("metrics")
                metrics_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = metrics_data["baseScore"]
                access_vector = metrics_data["vectorString"]
                access_complex = metrics_data["accessComplexity"]
                authentication = metrics_data["authentication"]
                confidentialityImpact = metrics_data["confidentialityImpact"]
                integrityImpact = metrics_data["integrityImpact"]
                availabilityImpact = metrics_data["availabilityImpact"]
                severity = metrics["cvssMetricV2"][0]["baseSeverity"]

                print(
                    f'{cvss_score} {severity}, \nAccess vector: {access_vector}, Access Complexity: {access_complex}, Privileges required: {authentication}, Confidentiality Impact: {confidentialityImpact}, Integrity Impact: {integrityImpact}, Availability Impact: {availabilityImpact}')
                for ref_url in references:
                    print(ref_url["url"])
                ###############   WE HAVE TO ADD URL DESCRIPTION FOR URL
                return  # Exit the function once CVE is found

        print(f"{cve_id} does not exist in the JSON data.")

    else:
        print(f"Error: API request failed with status code {response.status_code}")


cve_parse_json(cve_id)


def vuln_nist(cve):
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'}
    request = requests.get('https://nvd.nist.gov/vuln/detail/' + cve, headers=headers)
    soup = BeautifulSoup(request.text, 'html.parser')
    id_vuln = soup.find("span", {"data-testid": "page-header-vuln-id"}).text.strip()
    severity_func = soup.find("a", id="Cvss3NistCalculatorAnchor").text.strip()
    description_func = soup.find("p", {"data-testid": "vuln-description"}).text.strip()
    vector_func = soup.find("span", {"data-testid": "vuln-cvss3-nist-vector"}).text.strip()
    #   Existing related links
    ref_links = []
    link_number = 0  # Start with link number 1
    while True:
        link = soup.find("td", {"data-testid": f"vuln-hyperlinks-link-{link_number}"})
        if link is not None:
            ref_links.append(link.text.strip())
            link_number += 1
        else:
            break  # Exit the loop when no more links are found
    return id_vuln, severity_func, description_func, vector_func, ref_links


id_element, severity, description, vector, references = vuln_nist(CVE)

print(id_element)
print(severity)
print(description)
print(vector)
print(references)


def related_exp(cve):
    gitlab_file_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    gitlab_file_response = requests.get(gitlab_file_url)
    gitlab_data = gitlab_file_response.text

    # Convert the GitLab data into a file-like object
    gitlab_file = StringIO(gitlab_data)

    # Read the CSV data
    gitlab_reader = csv.DictReader(gitlab_file)

    # Extract all CVE IDs from your data
    cve_id = cve
    # Iterate over each row in the GitLab data and find matches with your CVE IDs
    for row in gitlab_reader:
        if cve_id in row["codes"]:
            related_id = row["id"]
            file = row["file"]
            description = row["description"]
            codes = row["codes"]
            source_url = row["source_url"]
            verified = row["verified"]
            print(codes, related_id, file, description, source_url)
            print("Download link: ", f"https://www.exploit-db.com/exploits/{related_id}")
            print(verified)

