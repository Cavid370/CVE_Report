import requests
from bs4 import BeautifulSoup

CVE = "CVE-2017-0144"

cve_database = [r"https://www.exploit-db.com/search?cve=CVE-2017-0144",
                r"https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2017-0144",
                r"https://vulners.com/search?query=CVE-2017-0144",
                r"https://vulmon.com/vulnerabilitydetails?qid=CVE-2017-0144",
                r"https://nvd.nist.gov/vuln/detail/CVE-2017-0144"]


# from main import cve_id
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
