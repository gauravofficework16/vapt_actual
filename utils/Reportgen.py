import os
import re
from datetime import datetime
import markdown2
from weasyprint import HTML, CSS
from utils.Agentschema import VAPTState

def generate_vapt_report(state: VAPTState) -> VAPTState:
    """
    Generate a professional VAPT report PDF with OWASP Top 10:2025 findings.
    Uses Alizarin Crimson (#EC1E2F) and Chablis (#FFF5F5) color scheme.
    """
    directory_path = state['node_results']
    output_path = state['final_report']
    repo_url = state.get('repo_url', 'N/A')
    
    # Get all report files
    files = [f for f in os.listdir(directory_path) if f.startswith("rv") and f.endswith(".md")]
    files.sort(key=lambda x: int(re.search(r'\d+', x).group()))
    
    # Professional VAPT Report CSS with specified color scheme
    report_css = """
        @page {
            size: A4;
            margin: 2.5cm 2cm 3cm 2cm;
            
            @top-right {
                content: "VAPT Report - " string(chapter);
                font-size: 9pt;
                color: #666;
                font-family: 'Arial', sans-serif;
            }
            
            @bottom-left {
                content: "⚠ CONFIDENTIAL - Not for Distribution";
                font-size: 8pt;
                color: #EC1E2F;
                font-weight: bold;
                font-family: 'Arial', sans-serif;
            }
            
            @bottom-center {
                content: "OWASP Top 10:2025";
                font-size: 8pt;
                color: #666;
                font-family: 'Arial', sans-serif;
            }
            
            @bottom-right {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 8pt;
                color: #666;
                font-family: 'Arial', sans-serif;
            }
        }
        
        @page:first {
            @top-right { content: none; }
            @bottom-left { content: none; }
            @bottom-center { content: none; }
            @bottom-right { content: none; }
        }
        
        /* Base Styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', 'Arial', sans-serif;
            font-size: 11pt;
            line-height: 1.7;
            color: #2C2C2C;
            background-color: #FFFFFF;
        }
        
        /* Cover Page */
        .cover-page {
            text-align: center;
            padding: 0;
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            background: linear-gradient(135deg, #FFF5F5 0%, #FFFFFF 100%);
            border: 3px solid #EC1E2F;
            page-break-after: always;
        }
        
        .cover-header {
            background-color: #EC1E2F;
            color: white;
            padding: 40px 20px;
            margin: -2.5cm -2cm 0 -2cm;
            margin-bottom: 60px;
        }
        
        .cover-title {
            font-size: 36pt;
            font-weight: 700;
            color: white;
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-bottom: 15px;
        }
        
        .cover-subtitle {
            font-size: 16pt;
            color: #FFF5F5;
            font-weight: 300;
            margin-top: 10px;
        }
        
        .cover-body {
            padding: 40px;
        }
        
        .cover-owasp {
            font-size: 18pt;
            color: #EC1E2F;
            font-weight: 600;
            margin: 40px 0 20px 0;
            padding: 15px;
            background-color: #FFF5F5;
            border-left: 5px solid #EC1E2F;
        }
        
        .cover-meta {
            margin-top: 60px;
            text-align: left;
            display: inline-block;
            background-color: #FFF5F5;
            padding: 30px;
            border-radius: 8px;
            border: 1px solid #EC1E2F;
        }
        
        .cover-meta-item {
            font-size: 11pt;
            margin: 12px 0;
            color: #2C2C2C;
        }
        
        .cover-meta-label {
            color: #EC1E2F;
            font-weight: 600;
            display: inline-block;
            width: 150px;
        }
        
        .cover-footer {
            position: absolute;
            bottom: 40px;
            width: 100%;
            text-align: center;
            color: #666;
            font-size: 9pt;
        }
        
        /* Table of Contents */
        .toc-page {
            page-break-after: always;
            padding: 20px 0;
        }
        
        .toc-title {
            font-size: 24pt;
            color: #EC1E2F;
            font-weight: 700;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 3px solid #EC1E2F;
        }
        
        .toc-item {
            margin: 15px 0;
            padding: 12px;
            background-color: #FFF5F5;
            border-left: 4px solid #EC1E2F;
            font-size: 11pt;
        }
        
        .toc-number {
            color: #EC1E2F;
            font-weight: 700;
            display: inline-block;
            width: 50px;
        }
        
        .toc-name {
            color: #2C2C2C;
            font-weight: 500;
        }
        
        /* Headers */
        h1 {
            font-size: 22pt;
            color: #EC1E2F;
            font-weight: 700;
            margin: 30px 0 20px 0;
            padding: 15px 20px;
            background: linear-gradient(90deg, #FFF5F5 0%, #FFFFFF 100%);
            border-left: 6px solid #EC1E2F;
            page-break-after: avoid;
            string-set: chapter content();
        }
        
        h2 {
            font-size: 16pt;
            color: #EC1E2F;
            font-weight: 600;
            margin: 25px 0 15px 0;
            padding-bottom: 8px;
            border-bottom: 2px solid #FFF5F5;
            page-break-after: avoid;
        }
        
        h3 {
            font-size: 13pt;
            color: #2C2C2C;
            font-weight: 600;
            margin: 20px 0 12px 0;
            padding-left: 15px;
            border-left: 3px solid #EC1E2F;
            page-break-after: avoid;
        }
        
        h4 {
            font-size: 11pt;
            color: #EC1E2F;
            font-weight: 600;
            margin: 15px 0 10px 0;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        /* Paragraphs */
        p {
            margin: 10px 0;
            text-align: justify;
        }
        
        /* Lists */
        ul, ol {
            margin: 15px 0 15px 25px;
        }
        
        li {
            margin: 8px 0;
            line-height: 1.6;
        }
        
        /* Code Blocks */
        pre {
            background-color: #2C2C2C;
            color: #F5F5F5;
            padding: 18px;
            border-radius: 6px;
            border-left: 4px solid #EC1E2F;
            overflow-x: auto;
            margin: 20px 0;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 9pt;
            line-height: 1.5;
            page-break-inside: avoid;
        }
        
        code {
            background-color: #FFF5F5;
            color: #EC1E2F;
            padding: 3px 8px;
            border-radius: 3px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 10pt;
            border: 1px solid #FFD5D5;
        }
        
        pre code {
            background-color: transparent;
            color: #F5F5F5;
            padding: 0;
            border: none;
            font-size: 9pt;
        }
        
        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background-color: white;
            box-shadow: 0 2px 4px rgba(236, 30, 47, 0.1);
            page-break-inside: avoid;
        }
        
        thead {
            background-color: #EC1E2F;
            color: white;
        }
        
        th {
            padding: 14px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 10pt;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border: none;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #FFF5F5;
            font-size: 10pt;
        }
        
        tr:nth-child(even) {
            background-color: #FFF5F5;
        }
        
        tr:hover {
            background-color: #FFE8E8;
        }
        
        /* Severity Badges */
        .severity-critical {
            background-color: #DC143C;
            color: white;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 9pt;
            text-transform: uppercase;
            display: inline-block;
        }
        
        .severity-high {
            background-color: #EC1E2F;
            color: white;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 9pt;
            text-transform: uppercase;
            display: inline-block;
        }
        
        .severity-medium {
            background-color: #FF8C00;
            color: white;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 9pt;
            text-transform: uppercase;
            display: inline-block;
        }
        
        .severity-low {
            background-color: #FFD700;
            color: #2C2C2C;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 9pt;
            text-transform: uppercase;
            display: inline-block;
        }
        
        /* Alert Boxes */
        .alert-box {
            padding: 18px 20px;
            margin: 20px 0;
            border-radius: 6px;
            border-left: 5px solid;
            page-break-inside: avoid;
        }
        
        .alert-critical {
            background-color: #FFE5E5;
            border-left-color: #DC143C;
            color: #2C2C2C;
        }
        
        .alert-warning {
            background-color: #FFF5E5;
            border-left-color: #FF8C00;
            color: #2C2C2C;
        }
        
        .alert-info {
            background-color: #E5F5FF;
            border-left-color: #1E88E5;
            color: #2C2C2C;
        }
        
        .alert-success {
            background-color: #E5FFE5;
            border-left-color: #43A047;
            color: #2C2C2C;
        }
        
        /* Report Section */
        .report-section {
            margin: 30px 0;
            page-break-inside: avoid;
        }
        
        .report-source {
            font-size: 9pt;
            color: #999;
            font-style: italic;
            margin-bottom: 15px;
            padding: 8px 12px;
            background-color: #F5F5F5;
            border-radius: 4px;
        }
        
        /* Finding Box */
        .finding-box {
            background-color: #FFF5F5;
            border: 2px solid #EC1E2F;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            page-break-inside: avoid;
        }
        
        .finding-title {
            color: #EC1E2F;
            font-size: 14pt;
            font-weight: 700;
            margin-bottom: 15px;
        }
        
        /* Statistics Box */
        .stats-box {
            background: linear-gradient(135deg, #FFF5F5 0%, #FFFFFF 100%);
            border: 2px solid #EC1E2F;
            border-radius: 8px;
            padding: 20px;
            margin: 25px 0;
            page-break-inside: avoid;
        }
        
        .stats-title {
            color: #EC1E2F;
            font-size: 13pt;
            font-weight: 700;
            margin-bottom: 15px;
            text-align: center;
        }
        
        /* Page Breaks */
        .page-break {
            page-break-before: always;
        }
        
        .page-break-after {
            page-break-after: always;
        }
        
        /* Links */
        a {
            color: #EC1E2F;
            text-decoration: none;
            font-weight: 500;
        }
        
        a:hover {
            text-decoration: underline;
        }
        
        /* Strong/Bold */
        strong, b {
            color: #EC1E2F;
            font-weight: 600;
        }
        
        /* Blockquotes */
        blockquote {
            border-left: 4px solid #EC1E2F;
            padding-left: 20px;
            margin: 20px 0;
            font-style: italic;
            color: #666;
            background-color: #FFF5F5;
            padding: 15px 20px;
            border-radius: 4px;
        }
        
        /* HR */
        hr {
            border: none;
            border-top: 2px solid #FFF5F5;
            margin: 30px 0;
        }
    """
    
    # OWASP Top 10:2025 categories for TOC
    owasp_categories = [
        "A01:2025 - Broken Access Control",
        "A02:2025 - Security Misconfiguration",
        "A03:2025 - Software Supply Chain Failures",
        "A04:2025 - Cryptographic Failures",
        "A05:2025 - Injection",
        "A06:2025 - Insecure Design",
        "A07:2025 - Authentication Failures",
        "A08:2025 - Software or Data Integrity Failures",
        "A09:2025 - Security Logging and Alerting Failures",
        "A10:2025 - Mishandling of Exceptional Conditions"
    ]
    
    # Generate current date
    current_date = datetime.now().strftime("%B %d, %Y at %H:%M")
    
    # Build HTML content
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>VAPT Report - OWASP Top 10:2025</title>
    </head>
    <body>
        <!-- Cover Page -->
        <div class="cover-page">
            <div class="cover-header">
                <div class="cover-title">Vulnerability Assessment &<br/>Penetration Testing Report</div>
                <div class="cover-subtitle">Comprehensive Security Analysis</div>
            </div>
            
            <div class="cover-body">
                <div class="cover-owasp">
                    🛡️ OWASP Top 10:2025 Compliance Assessment
                </div>
                
                <div class="cover-meta">
                    <div class="cover-meta-item">
                        <span class="cover-meta-label">Target Repository:</span>
                        <span>{repo_url}</span>
                    </div>
                    <div class="cover-meta-item">
                        <span class="cover-meta-label">Assessment Date:</span>
                        <span>{current_date}</span>
                    </div>
                    <div class="cover-meta-item">
                        <span class="cover-meta-label">Report Version:</span>
                        <span>1.0</span>
                    </div>
                    <div class="cover-meta-item">
                        <span class="cover-meta-label">Classification:</span>
                        <span style="color: #EC1E2F; font-weight: 700;">⚠ CONFIDENTIAL</span>
                    </div>
                    <div class="cover-meta-item">
                        <span class="cover-meta-label">Methodology:</span>
                        <span>AI-Powered Static Analysis + Manual Review</span>
                    </div>
                </div>
            </div>
            
            <div class="cover-footer">
                <p>This report contains sensitive security information.</p>
                <p>Unauthorized distribution or disclosure is strictly prohibited.</p>
            </div>
        </div>
        
        <!-- Table of Contents -->
        <div class="toc-page">
            <h1 class="toc-title">📋 Table of Contents</h1>
            
            <div style="margin-top: 30px;">
                <h3 style="border: none; padding: 0; margin-bottom: 20px;">OWASP Top 10:2025 Vulnerability Categories</h3>
    """
    
    # Add TOC items
    for i, category in enumerate(owasp_categories, 1):
        full_html += f"""
                <div class="toc-item">
                    <span class="toc-number">RV{i}</span>
                    <span class="toc-name">{category}</span>
                </div>
        """
    
    full_html += """
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="page-break"></div>
        <h1>📊 Executive Summary</h1>
        <div class="stats-box">
            <p class="stats-title">Security Assessment Overview</p>
            <p style="text-align: center; margin-top: 15px;">
                This report presents findings from a comprehensive vulnerability assessment 
                conducted against the OWASP Top 10:2025 security risks. The analysis combined 
                AI-powered static code analysis with manual security review to identify potential 
                vulnerabilities across all critical security categories.
            </p>
        </div>
        
        <h2>🎯 Assessment Scope</h2>
        <ul>
            <li><strong>Target Application:</strong> Source code repository analysis</li>
            <li><strong>Assessment Type:</strong> White-box security testing (Static Application Security Testing)</li>
            <li><strong>Coverage:</strong> Complete OWASP Top 10:2025 vulnerability categories</li>
            <li><strong>Analysis Engine:</strong> LLM-powered code analysis with anti-hallucination measures</li>
        </ul>
        
        <h2>⚠️ Key Findings Summary</h2>
        <p>
            Each of the following sections (RV1 through RV10) provides detailed analysis for a specific 
            OWASP Top 10:2025 category. Findings include vulnerability descriptions, affected code locations, 
            risk assessments, and recommended remediation strategies.
        </p>
        
        <div class="alert-box alert-info">
            <strong>Note:</strong> This is an automated assessment. All findings should be validated 
            by security professionals before implementation of fixes. False positives may occur and 
            require expert review.
        </div>
        
        <!-- Vulnerability Findings -->
        <div class="page-break"></div>
    """
    
    # Add all vulnerability reports
    for i, filename in enumerate(files, 1):
        file_path = os.path.join(directory_path, filename)
        
        # Read markdown content
        with open(file_path, "r", encoding="utf-8") as f:
            md_content = f.read()
        
        # Convert markdown to HTML
        html_content = markdown2.markdown(
            md_content,
            extras=["tables", "fenced-code-blocks", "break-on-newline", "header-ids"]
        )
        
        # Add section with metadata
        full_html += f"""
        <div class="report-section">
            <div class="report-source">
                📄 Source File: {filename} | Category: {owasp_categories[i-1] if i <= len(owasp_categories) else 'Additional Finding'}
            </div>
            {html_content}
        </div>
        """
        
        # Add page break between major sections (except last one)
        if i < len(files):
            full_html += '<div class="page-break"></div>\n'
    
    # Add footer/conclusion
    full_html += f"""
        
        <!-- Report Footer -->
        <div class="page-break"></div>
        <h1>📝 Report Conclusion</h1>
        
        <div class="stats-box">
            <p class="stats-title">Assessment Completion</p>
            <p style="text-align: center; margin-top: 15px;">
                This vulnerability assessment report has analyzed <strong>{len(files)} OWASP Top 10:2025 categories</strong>.
                <br/><br/>
                All findings documented in this report require careful review and prioritization 
                based on your organization's risk appetite and business context.
            </p>
        </div>
        
        <h2>🔒 Recommended Next Steps</h2>
        <ol>
            <li><strong>Validate Findings:</strong> Have security experts review all identified vulnerabilities</li>
            <li><strong>Prioritize Remediation:</strong> Focus on Critical and High severity issues first</li>
            <li><strong>Implement Fixes:</strong> Apply recommended security controls and patches</li>
            <li><strong>Verify Fixes:</strong> Conduct re-testing after remediation</li>
            <li><strong>Continuous Monitoring:</strong> Integrate security testing into CI/CD pipeline</li>
        </ol>
        
        <h2>📚 References</h2>
        <ul>
            <li><a href="https://owasp.org/Top10/2025/">OWASP Top 10:2025 Official Documentation</a></li>
            <li><a href="https://owasp.org/">OWASP Foundation</a></li>
            <li><a href="https://cwe.mitre.org/">CWE - Common Weakness Enumeration</a></li>
        </ul>
        
        <div class="alert-box alert-warning" style="margin-top: 40px;">
            <strong>⚠️ Confidentiality Notice:</strong><br/>
            This report contains confidential security information. It is intended solely for the use 
            of the individual or entity to whom it is addressed. Unauthorized disclosure, copying, 
            distribution, or use of this report is strictly prohibited and may be unlawful.
        </div>
        
        <hr style="margin: 40px 0;"/>
        <p style="text-align: center; color: #999; font-size: 9pt;">
            <strong>Report Generated:</strong> {current_date}<br/>
            <strong>VAPT Pipeline Version:</strong> 1.0.0 | <strong>OWASP Top 10:2025 Compliant</strong>
        </p>
        
    </body>
    </html>
    """
    
    # Generate PDF
    print(f"📄 Creating professional VAPT report: {output_path}...")
    print(f"   Using color scheme: Alizarin Crimson (#EC1E2F) + Chablis (#FFF5F5)")
    print(f"   Processing {len(files)} vulnerability reports...")
    
    HTML(string=full_html).write_pdf(
        output_path,
        stylesheets=[CSS(string=report_css)]
    )
    
    print(f"✅ Report successfully generated!")
    print(f"   📍 Location: {output_path}")
    print(f"   📊 Sections: Cover + TOC + Executive Summary + {len(files)} Findings")

    return state