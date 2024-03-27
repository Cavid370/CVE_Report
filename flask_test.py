from flask import Flask, render_template, request, redirect, url_for
import validation
import vuln

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('Home.html')


@app.route('/result')
def result():
    cve = request.args.get('cve', '').upper()
    if validation.is_valid_cve_id(cve):
        result = vuln.vuln_finder(cve)
        if fr"We found it CVE in 'https://nvd.nist.gov/vuln/detail/{cve}'" in result:
            id_vuln, severity_func, description_func, vector_func, ref_links = vuln.vuln_nist(cve)
            relat_exp = vuln.related_exp(cve)
            relat_exp_str = ', '.join(map(str, relat_exp))
            output = f"CVE ID: {id_vuln}\nSeverity: {severity_func}\nDescription: {description_func}\nVector: {vector_func}\nReference Links: {ref_links}\nRelated Exploits: {relat_exp_str}"
            with open(f'{cve}.txt', 'w') as file:
                file.write(output)
            return render_template('result.html', cve_id=id_vuln, severity=severity_func, description=description_func,
                                   source_url=ref_links, vector_func=vector_func, relat_exp=relat_exp)
        elif r"We found it CVE in 'https://services.nvd.nist.gov/rest/json/cves/2.0'" in result:
            cve_id, sourceIdentifier, descriptions1, cvss_score, severity, access_vector, access_complex, authentication, confidentialityImpact, integrityImpact, availabilityImpact = vuln.cve_parse_json(
                cve)
            relat_exp = vuln.related_exp(cve)
            relat_exp_str = ', '.join(map(str, relat_exp))
            output = f"CVE ID: {cve_id}\nSource Identifier: {sourceIdentifier}\nDescription: {descriptions1}\nCVSS Score: {cvss_score}\nSeverity: {severity}\nAccess Vector: {access_vector}\nAccess Complexity: {access_complex}\nAuthentication: {authentication}\nConfidentiality Impact: {confidentialityImpact}\nIntegrity Impact: {integrityImpact}\nAvailability Impact: {availabilityImpact}\nRelated Exploits: {relat_exp_str}"
            with open(f'{cve}.txt', 'w') as file:
                file.write(output)
            return render_template('result.html', cve_id=cve_id, severity=severity, description=descriptions1,
                                   source_url=sourceIdentifier, access_vector=access_vector,
                                   access_complex=access_complex, authentication=authentication,
                                   confidentialityImpact=confidentialityImpact, integrityImpact=integrityImpact,
                                   availabilityImpact=availabilityImpact, relat_exp=relat_exp)
        return "Output written to output.txt file successfully."
    else:
        return "Invalid input. Please follow the format 'CVE-YYYY-NNNN' or 'CVE-YYYY-NNNNNN'."


if __name__ == '__main__':
    app.run(debug=True)
