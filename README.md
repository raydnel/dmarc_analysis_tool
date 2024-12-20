# DMARC Analysis Tool

## Overview
The DMARC Analysis Tool is a Python-based solution designed to analyze DMARC XML reports, generate detailed insights, and produce a consolidated PDF report containing:

1. A detailed text analysis of email authentication results.
2. A pie chart summarizing SPF/DKIM pass rates.
3. A bar chart displaying domains responsible for DMARC failures.

This tool is ideal for organizations evaluating whether to adjust their DMARC policy (e.g., moving from `none` to `quarantine` or `reject`).

---

## Features
- Parses multiple DMARC XML reports.
- Provides detailed analysis, including pass/fail rates and unauthorized email counts.
- Generates visualizations (pie and bar charts).
- Exports all data and charts into a comprehensive PDF report.

---

## Prerequisites

### Python Version
- Python 3.6+

### Required Libraries
The following libraries are required to run the tool:

- `matplotlib`
- `fpdf`

Install them with:
```bash
pip install matplotlib fpdf
```

---

## Installation
1. Clone the repository:
```bash
git clone https://github.com/raydnel/dmarc_analysis_tool.git
```
2. Navigate to the project directory:
```bash
cd dmarc-analysis-tool
```
3. Install required dependencies:
```bash
pip install -r requirements.txt
```

---

## Usage
1. Place your DMARC XML files in a folder.
2. Run the tool:
```bash
python dmarc_analysis_tool.py
```
3. Follow the prompts to select XML files for analysis.
4. After analysis, the tool generates:
   - Charts saved as images.
   - A PDF report named `DMARC_Analysis_Report.pdf`.

---

## Output
The tool produces:
- **PDF Report**: A comprehensive file containing analysis and visualizations.
- **Images**: Saved pie and bar charts.

Example:
- `pie_chart.png`
- `bar_chart.png`
- `DMARC_Analysis_Report.pdf`

---

## Project Structure
```
.
├── dmarc_analysis_tool.py    # Main script
├── README.md                 # Documentation
├── pie_chart.png             # Generated pie chart (example)
├── bar_chart.png             # Generated bar chart (example)
├── DMARC_Analysis_Report.pdf # Generated report (example)
```


