# GROUP_E - **CVE Identifier Validator and Vulnerability Finder**
![image](https://github.com/Cavid370/GROUP_E/assets/147253759/533358dc-0f98-4b1f-91de-ec315baab204)

## **What is CVE?**
* CVE stands for Common Vulnerabilities and Exposures. It is a dictionary of publicly known information security vulnerabilities and exposures. Each CVE entry represents a unique identifier for a specific vulnerability, along with detailed information about the vulnerability, including its description, affected software, severity level, and any available remediation steps.

* CVE identifiers are used by cybersecurity professionals, organizations, and vendors to reference and track vulnerabilities across different systems, applications, and devices. This standardized naming convention allows for easier communication, coordination, and prioritization of security efforts.

* CVE entries are managed and maintained by the CVE Program, which is sponsored by the Cybersecurity and Infrastructure Security Agency (CISA) and operated by the MITRE Corporation. The CVE Program works collaboratively with security researchers, vendors, and organizations worldwide to assign CVE identifiers to newly discovered vulnerabilities and ensure that accurate and up-to-date information is available to the cybersecurity community.

* CVE entries are widely used in vulnerability management processes, including vulnerability assessment, patch management, and security incident response. By referencing CVE identifiers, organizations can quickly identify and address known vulnerabilities in their systems and applications, thereby reducing the risk of security breaches and data compromises.

## _Prerequisites_

Before running the code, ensure that you have Python installed on your system. Additionally, make sure that the vuln module is available and contains the vuln_finder function.

## _Usage_
* Install requirements package from requirements.txt. (pip install -r requirements.txt)
* First, execute flask_test.py with python 3.x. Connect to Local host 5000 port (127.0.0.1:5000)
  
In order to get the information, the user is expected to provide a CVE ID. Based on given CVE ID, the program then extracts the data from the database and provide it to the user. If the provided CVE ID is valid, the script will display information about the vulnerability associated with that CVE ID. If the input is invalid, the script will prompt you to enter a valid CVE ID.

### Input Format

The app expects the user to input a CVE ID following the given format:

**CVE-YYYY-NNNN**

#### Where:

* YYYY - represents the year of the vulnerability disclosure.

* NNNN - represents the sequential number assigned to the vulnerability within the year.

Example

Please follow the format 'CVE-YYYY-NNNN': CVE-2022-1234

Output:

[Information about CVE-2022-1234]

## Roles of the team members in the project

* Cavid - backend developer
* Vahab - testing and integration of backend and frontend
* Mehriban - frontend developer
* Hamid - frontend developer

