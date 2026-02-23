import os
import re
import markdown2
from weasyprint import HTML, CSS
from utils.Agentschema import VAPTState

def generate_vapt_report(state : VAPTState)-> VAPTState:

    directory_path=state['node_results']
    output_path=state['final_report']

    files = [f for f in os.listdir(directory_path) if f.startswith("rv") and f.endswith(".md")]
    files.sort(key=lambda x: int(re.search(r'\d+', x).group()))

    report_css = """
        @page {
            size: A4;
            margin: 2cm;
            @bottom-right {
                content: "Page " counter(page);
                font-size: 9pt;
                color: #666;
            }
            @bottom-left {
                content: "Confidential - VAPT Report";
                font-size: 9pt;
                color: #d32f2f;
            }
        }
        body {
            font-family: 'Helvetica', 'Arial', sans-serif;
            line-height: 1.6;
            color: #333;
        }
        h1 { color: #1a237e; border-bottom: 2px solid #1a237e; padding-bottom: 10px; }
        h2 { color: #283593; margin-top: 30px; border-left: 5px solid #1a237e; padding-left: 10px; }
        h3 { color: #d32f2f; } /* Highlighting vulnerabilities in red */
        
        pre, code {
            background-color: #f4f4f4;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            display: block;
            border: 1px solid #ddd;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        th { background-color: #1a237e; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        
        .page-break { page-break-before: always; }
        
        .cover-page {
            text-align: center;
            margin-top: 200px;
        }
        .cover-title { font-size: 32pt; color: #1a237e; font-weight: bold; }
        .cover-subtitle { font-size: 18pt; color: #666; margin-top: 20px; }
    """

    full_html = f"""
    <div class="cover-page">
        <div class="cover-title">Vulnerability Assessment & <br>Penetration Testing Report</div>
        <div class="cover-subtitle">Consolidated Security Findings (RV1 - RV10)</div>
        <p style="margin-top: 100px;"><strong>Status:</strong> Confidential</p>
        <p><strong>Generated on:</strong> 2023-10-27</p>
    </div>
    <div class="page-break"></div>
    """

    for filename in files:
        file_path = os.path.join(directory_path, filename)
        with open(file_path, "r", encoding="utf-8") as f:
            md_content = f.read()
            html_content = markdown2.markdown(md_content, extras=["tables", "fenced-code-blocks", "break-on-newline"])
            
            full_html += f"""
            <section class="report-section">
                <p style="color: #999;">Source: {filename}</p>
                {html_content}
            </section>
            <div class="page-break"></div>
            """

    print(f"Creating professional PDF: {output_path}...")
    HTML(string=full_html).write_pdf(
        output_path, 
        stylesheets=[CSS(string=report_css)]
    )
    print("Report successfully generated!")

    return state

# --- Execute ---
# generate_vapt_report('Node_results')