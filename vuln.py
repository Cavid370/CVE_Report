import requests  # Import the requests module for sending HTTP requests
from bs4 import BeautifulSoup  # Import BeautifulSoup for web scraping
import csv  # Import the csv module for CSV file handling
from io import StringIO  # Import StringIO for handling in-memory file-like objects
import webbrowser  # Import webbrowser for opening URLs in the web browser


def vuln_finder(cve):
    """
    Find information about a CVE (Common Vulnerabilities and Exposures) ID.

    Args:
        cve (str): CVE ID to search for.

    Returns:
        str: Information about the CVE if found, otherwise an error message.
    """
    # Define headers to mimic a web browser's user agent
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'
    }
    # Send a GET request to the CVE website to check if the CVE exists
    request = requests.get('https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cve, headers=headers)
    # Parse the HTML content of the response
    soup = BeautifulSoup(request.text, 'html.parser')
    # Check if the CVE exists on the website
    exists = soup.find("h2").text.strip()
    result = ""

    # If the CVE does not exist on the website, search for it in other sources
    if exists == f"ERROR: Couldn't find '{cve}'":
        # Check if the CVE exists in the NVD JSON feed
        cve_parse_result = cve_parse_json(cve)
        if not cve_parse_result:
            result += r"We can't find CVE in 'https://services.nvd.nist.gov/rest/json/cves/2.0' !!" + '\n'
        # Check if the CVE exists in the NVD website
        vuln_nist_result = vuln_nist(cve)
        if not vuln_nist_result:
            result += rf"We can't find CVE either in 'https://nvd.nist.gov/vuln/detail/{cve}'" + '\n'
        else:
            result += rf"We found it CVE in 'https://nvd.nist.gov/vuln/detail/{cve}'" + '\n'
            return result
    else:
        # If the CVE exists on the website, retrieve its information
        if not cve_parse_json(cve):
            result += r"We can't find CVE in 'https://services.nvd.nist.gov/rest/json/cves/2.0' !!" + '\n'
            if not vuln_nist(cve):
                result += rf"We can't find CVE either in 'https://nvd.nist.gov/vuln/detail/{cve}'" + '\n'
                result += "Nothing found"
                return result
            else:
                result += rf"We found it CVE in 'https://nvd.nist.gov/vuln/detail/{cve}'" + '\n'
                return result
        else:
            result += rf"We found it CVE in 'https://services.nvd.nist.gov/rest/json/cves/2.0' !!" + '\n'
            return result


def cve_parse_json(cve_id):
    """
    Parse JSON data from the NVD (National Vulnerability Database) to find information about a CVE.

    Args:
        cve_id (str): CVE ID to search for.

    Returns:
        tuple or bool: Information about the CVE if found, False otherwise.
    """
    api_url = r"https://services.nvd.nist.gov/rest/json/cves/2.0"
    # Send a GET request to the NVD API to retrieve JSON data
    response = requests.get(api_url)
    # Check if the response is successful
    if response.status_code == 200:
        # Parse the JSON response
        data = response.json()

        # Check if the CVE exists in the JSON data
        for vulnerability in data.get("vulnerabilities", []):
            cve = vulnerability.get("cve", {})
            if cve.get("id") == cve_id:
                sourceIdentifier = cve.get("sourceIdentifier")
                descriptions = cve.get("descriptions")
                descriptions1 = descriptions[0]["value"]
                references = cve.get("references")

                # Extract CVSS2 score and other metrics
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

                related_exp(cve_id)
                return cve_id, sourceIdentifier, descriptions1, cvss_score, severity, access_vector, access_complex, authentication, confidentialityImpact, integrityImpact, availabilityImpact  # Exit the function once CVE is found

        return False
    else:
        print(f"Error: API request failed with status code {response.status_code}")
        return False


def vuln_nist(cve):
    """
    Retrieve information about a CVE from the NVD (National Vulnerability Database) website.

    Args:
        cve (str): CVE ID to search for.

    Returns:
        tuple or bool: Information about the CVE if found, False otherwise.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'}
    request = requests.get('https://nvd.nist.gov/vuln/detail/' + cve, headers=headers)

    soup = BeautifulSoup(request.text, 'html.parser')
    exists = soup.find("h2").text.strip()
    if exists == "CVE ID Not Found":
        return False
    else:
        try:
            id_vuln = soup.find("span", {"data-testid": "page-header-vuln-id"}).text.strip()
            # Find CVSS2 data
            if soup.find("a", id="Cvss3NistCalculatorAnchor") == None:
                severity_func = soup.find("a", id="Cvss2CalculatorAnchor").text.strip()
                severity_parts = severity_func.split()
                # Extract the severity and score
                severity = severity_parts[1]
                score = float(severity_parts[0])

                vector_func = soup.find("span", {"class": "tooltipCvss2NistMetrics"}).text.strip()
            # Find CVSS3 data
            else:
                severity_func = soup.find("a", id="Cvss3NistCalculatorAnchor").text.strip()
                severity_parts = severity_func.split()
                # Extract the severity and score
                severity = severity_parts[1]
                score = float(severity_parts[0])
                vector_func = soup.find("span", {"data-testid": "vuln-cvss3-nist-vector"}).text.strip()
            description_func = soup.find("p", {"data-testid": "vuln-description"}).text.strip()
            related_exp(cve)
            # Existing related links
            ref_links = []
            link_number = 0  # Start with link number 1
            while True:
                link = soup.find("td", {"data-testid": f"vuln-hyperlinks-link-{link_number}"})
                if link is not None:
                    ref_links.append(link.text.strip())
                    link_number += 1
                    if link_number == 5:
                        break  # it should be fix again. !!!!!!!
                else:
                    break  # Exit the loop when no more links are found
            return id_vuln, score, severity, description_func, vector_func, ref_links
        except:
            print("There is nothing like that")


def related_exp(cve):
    gitlab_file_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    gitlab_file_response = requests.get(gitlab_file_url)
    gitlab_data = gitlab_file_response.text

    # Convert the GitLab data into a file-like object
    gitlab_file = StringIO(gitlab_data)

    # Read the CSV data
    gitlab_reader = csv.DictReader(gitlab_file)

    # Extract all CVE IDs from your data
    cve1 = cve
    # Iterate over each row in the GitLab data and find matches with your CVE IDs
    exploits = []
    for row in gitlab_reader:
        if cve1 in row["codes"]:
            exploits_child = []
            related_id = row["id"]
            description1 = row["description"]
            verified = row["verified"]
            download_link = f"https://www.exploit-db.com/exploits/{related_id}"

            exploits_child.append(description1)
            if verified == "1":
                exploits_child.append("Verified")
            elif verified == "0":
                exploits_child.append("Not verified")
            exploits_child.append(download_link)
            exploits.append(exploits_child)

    if exploits == []:
        b = ["There is no related exploit"]
        return b
    return exploits


# Function to open-top references
def open_top_references(cve_id):
    # Define a list of reference URLs
    reference_urls = [
        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        f"https://www.exploit-db.com/search?cve={cve_id}",
        f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id.lower()}",
        f"https://vulners.com/search?query={cve_id}",
        f"https://vulmon.com/vulnerabilitydetails?qid={cve_id}"
    ]

    # Open up to five top references
    for url in reference_urls:
        headers = {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'}
        try:
            response = requests.head(url, allow_redirects=True,headers=headers )
            if response.status_code == 200:
                webbrowser.open_new_tab(url)
            else:
                print(f"Failed to open reference URL: {url} (Status code: {response.status_code})")
        except Exception as e:
            print(f"Failed to open reference URL: {url} ({e})")


# Test the function

