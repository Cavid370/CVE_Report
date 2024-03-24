from datetime import datetime
import vuln
import re
from datetime import datetime


def is_valid_cve_id(cve_id):
    pattern = r"^CVE-(?!0000)\d{4}-(?:\d{4}|\d{6})$"
    if re.match(pattern, cve_id, re.IGNORECASE) is None:
        return False

    year_part = int(cve_id[4:8])
    current_year = datetime.now().year
    if year_part < 1999 or year_part > current_year:
        return False

    return True


if __name__ == "__main__":
    while True:
        cve = input("Please follow the format 'CVE-YYYY-NNNN' or 'CVE-YYYY-NNNNNN': ").upper()
        if is_valid_cve_id(cve):
            a = vuln.vuln_finder(cve)
            print(a)
            break
        else:
            print("Invalid input. Please follow the format 'CVE-YYYY-NNNN' or 'CVE-YYYY-NNNNNN'.")
