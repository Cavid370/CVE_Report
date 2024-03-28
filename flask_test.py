from flask import Flask, render_template, request, send_file  # Import necessary modules from Flask
import os  # Import the os module for interacting with the operating system
import validation  # Import custom module for validation
import vuln  # Import custom module for vulnerability analysis
from docx import Document  # Import Document class from python-docx for creating Word documents
from fpdf import FPDF  # Import FPDF class from fpdf for creating PDF documents

app = Flask(__name__)  # Create a Flask application


def create_output_folder(cve):
    """
    Create a folder for storing output files related to a CVE ID.

    Args:
        cve (str): CVE ID.

    Returns:
        str: Path of the created output folder.
    """
    output_folder = f'{cve} Outputs'  # Define the name of the output folder
    if not os.path.exists(output_folder):  # Check if the output folder doesn't exist
        os.makedirs(output_folder)  # Create the output folder
    return output_folder  # Return the path of the created output folder


@app.route('/')
def index():
    """
    Route for the home page.

    Returns:
        str: Rendered template for the home page.
    """
    return render_template('Home.html')  # Render the Home.html template


@app.route('/result')
def result():
    """
    Route for displaying the result of vulnerability analysis.

    Returns:
        str: Rendered template for displaying the analysis result.
    """
    cve = request.args.get('cve', '').upper()  # Get the CVE ID from the request and convert it to uppercase
    if validation.is_valid_cve_id(cve):  # Check if the provided CVE ID is valid
        result = vuln.vuln_finder(cve)  # Perform vulnerability analysis
        if fr"We found it CVE in 'https://nvd.nist.gov/vuln/detail/{cve}'" in result:
            # If the CVE is found in the NVD database
            id_vuln, cvss_score, severity, description_func, vector_func, ref_links, = vuln.vuln_nist(cve)
            # Extract information about the vulnerability
            relat_exp = vuln.related_exp(cve)  # Get related exploits
            relat_exp_str = ', '.join(map(str, relat_exp))  # Convert related exploits to a string
            output = f"CVE ID: {id_vuln}\nCVSS Score: {cvss_score}\Severity: {severity}\nDescription: {description_func}\nVector: {vector_func}\nReference Links: {ref_links}\nRelated Exploits: {relat_exp_str}"
            # Create a formatted output string

            output_folder = create_output_folder(cve)  # Create the output folder

            with open(os.path.join(output_folder, f'{cve}.txt'), 'w') as file:
                file.write(output)  # Write the output to a text file

            pdf = FPDF()  # Create an instance of FPDF class
            pdf.add_page()
            pdf.set_font("Arial", size=12)

            for line in output.split('\n'):
                pdf.multi_cell(0, 10, txt=line)  # Add each line of the output to the PDF document

            pdf.output(os.path.join(output_folder, f"{cve}.pdf"))  # Save the PDF document

            with open(os.path.join(output_folder, f'{cve}.md'), 'w') as file:
                file.write(output)  # Write the output to a markdown file

            vuln.open_top_references(cve)  # Open top references related to the CVE
            return render_template('result.html', cve_id=id_vuln, cvss_score=cvss_score, severity=severity,
                                   description=description_func,
                                   source_urls=ref_links, vector_func=vector_func, relat_exp=relat_exp)
            # Render the result.html template with the analysis information
        elif r"We found it CVE in 'https://services.nvd.nist.gov/rest/json/cves/2.0'" in result:
            # If the CVE is found in the NVD JSON feed
            cve_id, sourceIdentifier, descriptions1, cvss_score, severity, access_vector, access_complex, authentication, confidentialityImpact, integrityImpact, availabilityImpact = vuln.cve_parse_json(
                cve)
            # Extract information about the vulnerability from JSON
            relat_exp = vuln.related_exp(cve)  # Get related exploits
            relat_exp_str = ', '.join(map(str, relat_exp))  # Convert related exploits to a string
            output = f"CVE ID: {cve_id}\nSource Identifier: {sourceIdentifier}\nDescription: {descriptions1}\nCVSS Score: {cvss_score}\nSeverity: {severity}\nAccess Vector: {access_vector}\nAccess Complexity: {access_complex}\nAuthentication: {authentication}\nConfidentiality Impact: {confidentialityImpact}\nIntegrity Impact: {integrityImpact}\nAvailability Impact: {availabilityImpact}\nRelated Exploits: {relat_exp_str}"
            # Create a formatted output string

            output_folder = create_output_folder()  # Create the output folder

            with open(os.path.join(output_folder, f'{cve}.txt'), 'w') as file:
                file.write(output)  # Write the output to a text file

            pdf = FPDF()  # Create an instance of FPDF class
            pdf.add_page()
            pdf.set_font("Arial", size=12)

            for line in output.split('\n'):
                pdf.multi_cell(0, 10, txt=line)  # Add each line of the output to the PDF document

            pdf.output(os.path.join(output_folder, f"{cve}.pdf"))  # Save the PDF document

            with open(os.path.join(output_folder, f'{cve}.md'), 'w') as file:
                file.write(output)  # Write the output to a markdown file

            doc = Document()  # Create an instance of Document class
            doc.add_paragraph(output)  # Add the output as a paragraph to the document
            doc.save(os.path.join(output_folder, f"{cve}.docx"))  # Save the document as a Word file

            return render_template('result.html', cve_id=cve_id, severity=severity, description=descriptions1,
                                   source_url=sourceIdentifier, access_vector=access_vector,
                                   access_complex=access_complex, authentication=authentication,
                                   confidentialityImpact=confidentialityImpact, integrityImpact=integrityImpact,
                                   availabilityImpact=availabilityImpact, relat_exp=relat_exp)
            # Render the result.html template with the analysis information
        return "CVE not exist."  # If the CVE is not found, return a message
    else:
        return "Invalid input. Please follow the format 'CVE-YYYY-NNNN' or 'CVE-YYYY-NNNNNN'."  # If the input is invalid, return a message

@app.route('/download/<filename>')
def download(filename):
    return send_file(filename, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
