# GROUP_E
![image](https://github.com/Cavid370/GROUP_E/assets/147253759/533358dc-0f98-4b1f-91de-ec315baab204)
**CVE Identifier Validator and Vulnerability Finder**

This Python script allows users to validate Common Vulnerabilities and Exposures (CVE) identifiers and find information about vulnerabilities associated with valid CVE IDs. The script checks whether the provided CVE ID follows the correct format and validates the year part. If the input is valid, it utilizes a function from a separate module named vuln to retrieve information about the vulnerability.

_Prerequisites_

Before running the script, ensure that you have Python installed on your system. Additionally, make sure that the vuln module is available and contains the vuln_finder function.

_Usage_

Clone the repository or download the script file (cve_validator.py) to your local machine.

Ensure that the vuln module is present in the same directory as the script, or it is accessible from the Python path.

Open a terminal or command prompt.

Navigate to the directory containing the script.

Run the script by executing the following command:

Copy code
python cve_validator.py
Follow the on-screen instructions to input a CVE ID.

If the provided CVE ID is valid, the script will display information about the vulnerability associated with that CVE ID. If the input is invalid, the script will prompt you to enter a valid CVE ID.

Input Format
The script expects the user to input a CVE ID following one of the following formats:

CVE-YYYY-NNNN
CVE-YYYY-NNNNNN
Where:

YYYY represents the year of the vulnerability disclosure.
NNNN represents the sequential number assigned to the vulnerability within the year.
Example
lua
Copy code
Please follow the format 'CVE-YYYY-NNNN' or 'CVE-YYYY-NNNNNN': CVE-2022-1234
Output:

csharp
Copy code
[Information about CVE-2022-1234]
Contributing
Contributions are welcome! If you find any issues with the script or have suggestions for improvements, please open an issue or submit a pull request.

