from flask import Flask, render_template, request, send_file
import os
import validation
import vuln
from docx import Document
from fpdf import FPDF

app = Flask(__name__)


def create_output_folder(cve):
    output_folder = f'{cve} Outputs'
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    return output_folder


@app.route('/')
def index():
    return render_template('Home.html')


@app.route('/result')
def result():
    cve = request.args.get('cve', '').upper()
    if validation.is_valid_cve_id(cve):
        result = vuln.vuln_finder(cve)
        if fr"We found it CVE in 'https://nvd.nist.gov/vuln/detail/{cve}'" in result:
            id_vuln, cvss_score, severity, description_func, vector_func, ref_links, = vuln.vuln_nist(cve)
            relat_exp = vuln.related_exp(cve)
            relat_exp_str = ', '.join(map(str, relat_exp))
            output = f"CVE ID: {id_vuln}\nCVSS Score: {cvss_score}\Severity: {severity}\nDescription: {description_func}\nVector: {vector_func}\nReference Links: {ref_links}\nRelated Exploits: {relat_exp_str}"

            output_folder = create_output_folder(cve)

            with open(os.path.join(output_folder, f'{cve}.txt'), 'w') as file:
                file.write(output)

            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)

            for line in output.split('\n'):
                pdf.multi_cell(0, 10, txt=line)

            pdf.output(os.path.join(output_folder, f"{cve}.pdf"))

            with open(os.path.join(output_folder, f'{cve}.md'), 'w') as file:
                file.write(output)
            vuln.open_top_references(cve)
            return render_template('result.html', cve_id=id_vuln, cvss_score=cvss_score, severity=severity,
                                   description=description_func,
                                   source_urls=ref_links, vector_func=vector_func, relat_exp=relat_exp)
        elif r"We found it CVE in 'https://services.nvd.nist.gov/rest/json/cves/2.0'" in result:
            cve_id, sourceIdentifier, descriptions1, cvss_score, severity, access_vector, access_complex, authentication, confidentialityImpact, integrityImpact, availabilityImpact = vuln.cve_parse_json(
                cve)
            relat_exp = vuln.related_exp(cve)
            relat_exp_str = ', '.join(map(str, relat_exp))
            output = f"CVE ID: {cve_id}\nSource Identifier: {sourceIdentifier}\nDescription: {descriptions1}\nCVSS Score: {cvss_score}\nSeverity: {severity}\nAccess Vector: {access_vector}\nAccess Complexity: {access_complex}\nAuthentication: {authentication}\nConfidentiality Impact: {confidentialityImpact}\nIntegrity Impact: {integrityImpact}\nAvailability Impact: {availabilityImpact}\nRelated Exploits: {relat_exp_str}"

            output_folder = create_output_folder()

            with open(os.path.join(output_folder, f'{cve}.txt'), 'w') as file:
                file.write(output)

            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)

            for line in output.split('\n'):
                pdf.multi_cell(0, 10, txt=line)

            pdf.output(os.path.join(output_folder, f"{cve}.pdf"))

            with open(os.path.join(output_folder, f'{cve}.md'), 'w') as file:
                file.write(output)

            doc = Document()
            doc.add_paragraph(output)
            doc.save(os.path.join(output_folder, f"{cve}.docx"))

            return render_template('result.html', cve_id=cve_id, severity=severity, description=descriptions1,
                                   source_url=sourceIdentifier, access_vector=access_vector,
                                   access_complex=access_complex, authentication=authentication,
                                   confidentialityImpact=confidentialityImpact, integrityImpact=integrityImpact,
                                   availabilityImpact=availabilityImpact, relat_exp=relat_exp)
        return "CVE not exist."
    else:
        return "Invalid input. Please follow the format 'CVE-YYYY-NNNN' or 'CVE-YYYY-NNNNNN'."


@app.route('/download/<filename>')
def download(filename):
    return send_file(filename, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
