import re  # Import the regular expression module for pattern matching
import vuln  # Import the custom module for vulnerability analysis
from datetime import datetime  # Import the datetime module for handling date and time


def is_valid_cve_id(cve_id):
    """
    Check if the provided CVE ID follows the correct format and is within the valid year range.

    Args:
        cve_id (str): CVE ID to be validated.

    Returns:
        bool: True if the CVE ID is valid, False otherwise.
    """
    pattern = r"^CVE-\d{4}-(?!0000)\d{4,8}$"  # Define the regex pattern for CVE ID
    if re.match(pattern, cve_id) is None:  # Check if the provided CVE ID matches the pattern
        return False

    year_part = int(cve_id[4:8])  # Extract the year part from the CVE ID
    current_year = datetime.now().year  # Get the current year
    if year_part < 1999 or year_part > current_year:  # Check if the year part is within the valid range
        return False
    return True


if __name__ == "__main__":
    # Main execution block
    while True:
        cve = input("Please follow the format 'CVE-YYYY-NNNN' or 'CVE-YYYY-NNNNNN': ").upper()  # Prompt user for input
        if is_valid_cve_id(cve):  # Validate the provided CVE ID
            a = vuln.vuln_finder(cve)  # Perform vulnerability analysis
            print(a)  # Print the analysis result
            break
        else:
            print("Invalid input. Please follow the format 'CVE-YYYY-NNNN' or 'CVE-YYYY-NNNNNN'.")  # Prompt for valid input
