import xml.etree.ElementTree as ET
import os
import matplotlib.pyplot as plt
from fpdf import FPDF

def parse_dmarc_report(file_path):
    """Parses a DMARC XML report and extracts relevant data."""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        results = []

        for record in root.findall('.//record'):
            source_ip = record.find('row/source_ip').text
            spf_pass = record.find('row/policy_evaluated/spf').text
            dkim_pass = record.find('row/policy_evaluated/dkim').text
            alignment = record.find('row/policy_evaluated/disposition').text
            count = int(record.find('row/count').text)
            domain = record.find('identifiers/header_from').text if record.find('identifiers/header_from') is not None else "Unknown"

            results.append({
                "Source IP": source_ip,
                "SPF Pass": spf_pass,
                "DKIM Pass": dkim_pass,
                "Alignment": alignment,
                "Count": count,
                "Domain": domain,
            })
        return results
    except Exception as e:
        print(f"Error parsing DMARC report: {e}")
        return []

def analyze_data(reports):
    """Analyzes the parsed DMARC data and provides policy recommendations."""
    total_emails = sum(r['Count'] for r in reports)
    if total_emails == 0:
        return "No data available for analysis."

    spf_dkim_pass = [r for r in reports if r['SPF Pass'] == 'pass' and r['DKIM Pass'] == 'pass']
    passed_count = sum(r['Count'] for r in spf_dkim_pass)
    failed_count = total_emails - passed_count

    unauthorized_sources = [r for r in reports if r['Alignment'] != 'pass']
    unauthorized_count = sum(r['Count'] for r in unauthorized_sources)

    pass_rate = (passed_count / total_emails) * 100
    fail_rate = 100 - pass_rate

    recommendation = ""
    if fail_rate < 5 and unauthorized_count < 2:
        recommendation = "Recommend 'reject' policy."
    elif fail_rate < 15:
        recommendation = "Recommend 'quarantine' policy."
    else:
        recommendation = "Stay at 'none' policy and investigate further."

    detailed_analysis = {
        "Total Emails": total_emails,
        "SPF/DKIM Pass Count": passed_count,
        "Unauthorized Email Count": unauthorized_count,
        "Fail Rate": fail_rate,
        "Domains with Failures": list(set(r['Domain'] for r in unauthorized_sources)),
        "Recommendation": recommendation,
    }

    return detailed_analysis

def generate_visualizations(reports):
    """Generates visualizations for the DMARC analysis and saves them as images."""
    try:
        spf_dkim_pass = sum(r['Count'] for r in reports if r['SPF Pass'] == 'pass' and r['DKIM Pass'] == 'pass')
        total_count = sum(r['Count'] for r in reports)
        unauthorized_sources = [r for r in reports if r['Alignment'] != 'pass']
        unauthorized_count = sum(r['Count'] for r in unauthorized_sources)

        # Calculate the "Failures" segment correctly
        failures = total_count - spf_dkim_pass - unauthorized_count
        failures = max(0, failures)  # Ensure no negative values

        # Ensure all values are non-negative
        spf_dkim_pass = max(0, spf_dkim_pass)
        unauthorized_count = max(0, unauthorized_count)
        failures = max(0, failures)

        # Pie chart of pass/fail rates
        labels = ["SPF+DKIM Pass", "Failures", "Unauthorized Emails"]
        values = [spf_dkim_pass, failures, unauthorized_count]

        if sum(values) == 0:
            print("No data available for visualization.")
            return

        # Save pie chart as an image
        plt.figure(figsize=(8, 8))
        plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=140, explode=(0.1, 0, 0), shadow=True)
        plt.title("DMARC Analysis: Email Authentication Results")
        plt.legend(loc="upper left", title="Legend")
        plt.savefig("pie_chart.png")
        plt.close()

        # Bar chart for domains causing failures
        domains = [r['Domain'] for r in unauthorized_sources]
        domain_counts = {domain: sum(r['Count'] for r in reports if r['Domain'] == domain) for domain in set(domains)}

        if domain_counts:
            plt.figure(figsize=(10, 6))
            plt.bar(domain_counts.keys(), domain_counts.values(), color="skyblue")
            plt.title("Domains Causing DMARC Failures")
            plt.xlabel("Domains")
            plt.ylabel("Failed Email Count")
            plt.xticks(rotation=45, ha="right")
            plt.tight_layout()
            plt.savefig("bar_chart.png")
            plt.close()

    except Exception as e:
        print(f"Error generating visualizations: {e}")

def export_to_pdf(analysis):
    """Creates a PDF report with the analysis and charts."""
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Add analysis text
        pdf.cell(200, 10, txt="DMARC Analysis Report", ln=True, align='C')
        pdf.ln(10)

        for key, value in analysis.items():
            if key == "Domains with Failures":
                value = ', '.join(value) if value else 'None'
            pdf.multi_cell(0, 10, txt=f"{key}: {value}")

        pdf.ln(10)

        # Add pie chart
        pdf.add_page()
        pdf.cell(200, 10, txt="Pie Chart: SPF/DKIM Pass Rates", ln=True, align='C')
        pdf.image("pie_chart.png", x=10, y=30, w=190)

        # Add bar chart
        pdf.add_page()
        pdf.cell(200, 10, txt="Bar Chart: Domains Causing Failures", ln=True, align='C')
        pdf.image("bar_chart.png", x=10, y=30, w=190)

        # Save PDF
        pdf.output("DMARC_Analysis_Report.pdf")
        print("PDF report generated: DMARC_Analysis_Report.pdf")

    except Exception as e:
        print(f"Error generating PDF: {e}")

def select_reports(folder_path):
    """Presents the user with a numbered list of XML files to select."""
    try:
        files = [f for f in os.listdir(folder_path) if f.endswith('.xml')]
        if not files:
            print("No XML files found in the folder.")
            return []

        print("\nAvailable DMARC XML reports:")
        for i, file in enumerate(files, 1):
            print(f"{i}. {file}")

        print("\nEnter the numbers of the files you want to analyze, separated by commas (e.g., 1,3,5):")
        choices = input("Your choice: ")
        selected_files = []
        for choice in choices.split(','):
            try:
                index = int(choice.strip()) - 1
                if 0 <= index < len(files):
                    selected_files.append(os.path.join(folder_path, files[index]))
                else:
                    print(f"Invalid choice: {choice}")
            except ValueError:
                print(f"Invalid input: {choice}")

        return selected_files[:100]
    except Exception as e:
        print(f"Error selecting reports: {e}")
        return []

def main():
    print("DMARC Report Analysis Tool")

    folder_path = input("Enter the path to the folder containing DMARC XML reports: ")

    if not os.path.exists(folder_path):
        print("Folder not found. Please check the path and try again.")
        return

    # Allow user to select reports
    report_files = select_reports(folder_path)

    if not report_files:
        print("No reports selected for analysis.")
        return

    print(f"Selected {len(report_files)} reports. Parsing...")

    all_reports = []
    for file_path in report_files:
        reports = parse_dmarc_report(file_path)
        all_reports.extend(reports)

    if not all_reports:
        print("No data parsed from the reports.")
        return

    print("Analyzing data...")
    analysis = analyze_data(all_reports)

    print("\n--- Detailed Analysis Summary ---")
    for key, value in analysis.items():
        if key == "Domains with Failures":
            print(f"{key}: {', '.join(value) if value else 'None'}")
        else:
            print(f"{key}: {value}")

    print("\nGenerating visualizations...")
    generate_visualizations(all_reports)

    print("\nExporting to PDF...")
    export_to_pdf(analysis)

if __name__ == "__main__":
    main()
