from datetime import datetime
import vuln


if __name__ == "__main__":
    while True:
        try:
            cve_input_year = int(input("Insert CVE year: "))
            if 1999 <= cve_input_year <= datetime.now().year:
                if len(str(cve_input_year)) != 4:
                    print("Invalid input. Please enter a 4-character year.")
                    continue
            else:
                print("Please enter correct year!")
                continue
        except ValueError:
            print("Please enter a numeric value for the year.")
            continue

        while True:  # Nested loop for the CVE number input

            try:
                cve_input_number = input("Insert number of CVE: ")
                cve_input_number1 = ""
                if int(cve_input_number) > 0:
                    for i in cve_input_number:
                        i = int(i)
                        if type(i) is int:
                            cve_input_number1 = cve_input_number1 + str(i)

                if len(str(cve_input_number)) < 4:
                    print("Invalid input. Must be 4-digits or greater!.")
                    continue
                else:
                    break  # Exit the CVE number input loop
            except ValueError:
                print("Please enter a numeric value for the CVE number.")
                continue

        # This part executes only if both year and number are 4 characters long
        cve_id = "CVE-" + str(cve_input_year) + "-" + str(cve_input_number)
        vuln.vuln_finder(cve_id)
        print(vuln.vuln_finder(cve_id))
        break  # Exit the main loop
