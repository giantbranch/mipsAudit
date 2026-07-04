# -*- coding: utf-8 -*-
"""
Enhanced Report Export Module

Generates detailed vulnerability reports with:
- Complete proof chains
- Risk scoring (CVSS-like)
- Remediation suggestions
- Code snippets
- Data flow visualization

Author: giantbranch
Version: 3.1
"""

import json
import csv
from datetime import datetime
import os
import idc


class VulnerabilityReport:
    """Represents a single vulnerability finding"""
    
    def __init__(self, vuln_type, risk_level, address, function):
        self.type = vuln_type
        self.risk = risk_level
        self.address = address
        self.function = function
        self.timestamp = datetime.now().isoformat()
        self.proof_chain = []  # List of addresses showing the vulnerability
        self.code_snippets = []  # Code context
        self.remediation = None
        self.cvss_score = 0.0
        self.related_functions = []
        self.data_flow_path = []
        self.metadata = {}
    
    def add_proof_step(self, addr, instruction, description):
        """Add step to proof chain"""
        self.proof_chain.append({
            'address': f"0x{addr:x}",
            'instruction': instruction,
            'description': description
        })
    
    def add_code_snippet(self, start_addr, end_addr, source_code=None):
        """Add code snippet for visualization"""
        snippet = {
            'start': f"0x{start_addr:x}",
            'end': f"0x{end_addr:x}",
            'disasm': []
        }
        
        addr = start_addr
        while addr <= end_addr and addr != idc.BADADDR:
            disasm = idc.GetDisasm(addr)
            snippet['disasm'].append({
                'addr': f"0x{addr:x}",
                'instruction': disasm
            })
            addr = idc.next_head(addr, end_addr)
        
        self.code_snippets.append(snippet)
    
    def set_remediation(self, suggestion, priority='MEDIUM'):
        """Set remediation suggestion"""
        self.remediation = {
            'suggestion': suggestion,
            'priority': priority,
            'timestamp': datetime.now().isoformat()
        }
    
    def calculate_cvss_score(self):
        """
        Calculate simplified CVSS score (0.0-10.0)
        """
        base_scores = {
            'use_after_free': 8.2,
            'buffer_overflow': 8.6,
            'command_injection': 9.8,
            'format_string': 8.2,
            'integer_underflow': 7.5,
            'toctou': 7.0,
            'off_by_one': 6.5,
            'race_condition': 7.8,
            'double_free': 8.1,
        }
        
        base = base_scores.get(self.type, 5.0)
        
        # Adjustments based on context
        if len(self.proof_chain) > 3:  # Deep call chain = higher confidence
            base += 0.5
        
        # Risk level adjustments
        if self.risk == 'HIGH':
            self.cvss_score = min(10.0, base + 1.0)
        elif self.risk == 'MEDIUM':
            self.cvss_score = min(10.0, base)
        else:
            self.cvss_score = max(3.0, base - 2.0)
        
        return self.cvss_score
    
    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'type': self.type,
            'risk': self.risk,
            'address': self.address,
            'function': self.function,
            'timestamp': self.timestamp,
            'proof_chain': self.proof_chain,
            'code_snippets': self.code_snippets,
            'remediation': self.remediation,
            'cvss_score': self.calculate_cvss_score(),
            'related_functions': self.related_functions,
            'data_flow_path': self.data_flow_path,
            'metadata': self.metadata
        }


class EnhancedReportExporter:
    """Export vulnerability reports in multiple formats"""
    
    # Remediation suggestions by vulnerability type
    REMEDIATION_DB = {
        'buffer_overflow': {
            'suggestion': 'Use bounded string functions (strncpy, strncat, snprintf) or validate buffer sizes at runtime',
            'priority': 'CRITICAL'
        },
        'command_injection': {
            'suggestion': 'Avoid shell functions (system, popen). Use execve with explicit argument array. Validate/sanitize all inputs.',
            'priority': 'CRITICAL'
        },
        'format_string': {
            'suggestion': 'Never use user input as format string. Use printf("%s", user_input) instead of printf(user_input)',
            'priority': 'HIGH'
        },
        'use_after_free': {
            'suggestion': 'Ensure pointers are nullified after free(). Use static analysis tools to detect UAF patterns.',
            'priority': 'CRITICAL'
        },
        'double_free': {
            'suggestion': 'Track allocation/deallocation properly. Consider using memory pools or reference counting.',
            'priority': 'CRITICAL'
        },
        'integer_underflow': {
            'suggestion': 'Use signed integer arithmetic and check for negative results. Validate size parameters before use.',
            'priority': 'HIGH'
        },
        'toctou': {
            'suggestion': 'Use atomic operations or file locking. Verify file properties immediately before access.',
            'priority': 'MEDIUM'
        },
        'off_by_one': {
            'suggestion': 'Carefully review loop bounds. Use < len instead of <= len. Add bounds checking.',
            'priority': 'MEDIUM'
        }
    }
    
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.reports = []
        self.summary = {
            'total': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_type': {}
        }
    
    def add_report(self, vuln_report):
        """Add vulnerability report"""
        self.reports.append(vuln_report)
        
        # Update summary
        self.summary['total'] += 1
        
        if vuln_report.risk == 'HIGH':
            self.summary['high'] += 1
        elif vuln_report.risk == 'MEDIUM':
            self.summary['medium'] += 1
        else:
            self.summary['low'] += 1
        
        # Count by type
        vuln_type = vuln_report.type
        if vuln_type not in self.summary['by_type']:
            self.summary['by_type'][vuln_type] = 0
        self.summary['by_type'][vuln_type] += 1
    
    def export_html(self, filename=None):
        """
        Export as interactive HTML report
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"mipsAudit_report_{timestamp}.html"
        
        filepath = os.path.join(self.output_dir, filename)
        
        html = self._generate_html()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filepath
    
    def _generate_html(self):
        """
        Generate HTML content
        """
        risk_colors = {
            'HIGH': '#d32f2f',
            'MEDIUM': '#f57c00',
            'LOW': '#388e3c'
        }
        
        html_parts = []
        
        # Header
        html_parts.append(f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MIPS Security Audit Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f5f5f5;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .summary-card.high {{
            border-left-color: {risk_colors['HIGH']};
        }}
        
        .summary-card.medium {{
            border-left-color: {risk_colors['MEDIUM']};
        }}
        
        .summary-card.low {{
            border-left-color: {risk_colors['LOW']};
        }}
        
        .summary-card h3 {{
            font-size: 1.3em;
            margin-bottom: 10px;
            color: #333;
        }}
        
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .summary-card.high .number {{
            color: {risk_colors['HIGH']};
        }}
        
        .summary-card.medium .number {{
            color: {risk_colors['MEDIUM']};
        }}
        
        .summary-card.low .number {{
            color: {risk_colors['LOW']};
        }}
        
        .findings {{
            padding: 30px;
        }}
        
        .finding {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .finding-header {{
            padding: 20px;
            border-left: 4px solid #667eea;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #fafafa;
            transition: background 0.3s;
        }}
        
        .finding-header:hover {{
            background: #f0f0f0;
        }}
        
        .finding.high .finding-header {{
            border-left-color: {risk_colors['HIGH']};
        }}
        
        .finding.medium .finding-header {{
            border-left-color: {risk_colors['MEDIUM']};
        }}
        
        .finding.low .finding-header {{
            border-left-color: {risk_colors['LOW']};
        }}
        
        .finding-title {{
            flex: 1;
        }}
        
        .finding-title h3 {{
            margin-bottom: 5px;
            color: #333;
        }}
        
        .finding-title p {{
            color: #666;
            font-size: 0.9em;
        }}
        
        .risk-badge {{
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            margin-left: 10px;
        }}
        
        .risk-badge.high {{
            background: {risk_colors['HIGH']};
            color: white;
        }}
        
        .risk-badge.medium {{
            background: {risk_colors['MEDIUM']};
            color: white;
        }}
        
        .risk-badge.low {{
            background: {risk_colors['LOW']};
            color: white;
        }}
        
        .finding-content {{
            display: none;
            padding: 20px;
            border-top: 1px solid #e0e0e0;
            background: #fafafa;
        }}
        
        .finding-content.show {{
            display: block;
        }}
        
        .section {{
            margin-bottom: 20px;
        }}
        
        .section h4 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 1.1em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 5px;
        }}
        
        .code-block {{
            background: #282c34;
            color: #abb2bf;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }}
        
        .proof-chain {{
            background: #e8f5e9;
            border-left: 3px solid #4caf50;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        
        .proof-step {{
            margin: 8px 0;
            padding: 5px 0;
        }}
        
        .proof-step .addr {{
            font-family: monospace;
            color: #d32f2f;
            font-weight: bold;
        }}
        
        .cvss-score {{
            background: #fff3e0;
            border-left: 3px solid #f57c00;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }}
        
        .cvss-value {{
            font-size: 1.5em;
            font-weight: bold;
            color: #f57c00;
        }}
        
        .remediation {{
            background: #e3f2fd;
            border-left: 3px solid #2196f3;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }}
        
        .remediation h5 {{
            color: #1976d2;
            margin-bottom: 8px;
        }}
        
        .footer {{
            background: #f5f5f5;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }}
        
        .toggle-btn {{
            cursor: pointer;
            color: #667eea;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 MIPS Security Audit Report</h1>
            <p>Advanced Vulnerability Analysis v3.1</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card high">
                <h3>🔴 HIGH Risk</h3>
                <div class="number">{self.summary['high']}</div>
            </div>
            <div class="summary-card medium">
                <h3>🟠 MEDIUM Risk</h3>
                <div class="number">{self.summary['medium']}</div>
            </div>
            <div class="summary-card low">
                <h3>🟢 LOW Risk</h3>
                <div class="number">{self.summary['low']}</div>
            </div>
            <div class="summary-card">
                <h3>📊 Total</h3>
                <div class="number">{self.summary['total']}</div>
            </div>
        </div>
        
        <div class="findings">
        """)
        
        # Sort reports by risk
        risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        sorted_reports = sorted(self.reports, key=lambda x: risk_order.get(x.risk, 3))
        
        # Generate finding entries
        for idx, report in enumerate(sorted_reports):
            cvss = report.calculate_cvss_score()
            
            html_parts.append(f"""
            <div class="finding {report.risk.lower()}">
                <div class="finding-header" onclick="toggleFinding(this)">
                    <div class="finding-title">
                        <h3>[ {report.type.upper().replace('_', ' ')} ] @ 0x{report.address[-8:]}</h3>
                        <p>Function: <strong>{report.function}</strong></p>
                    </div>
                    <span class="risk-badge {report.risk.lower()}">{report.risk}</span>
                    <span class="toggle-btn">▼</span>
                </div>
                <div class="finding-content">
                    <div class="section">
                        <h4>📌 Details</h4>
                        <p><strong>Address:</strong> <span style="font-family: monospace; color: #d32f2f;">{report.address}</span></p>
                        <p><strong>Function:</strong> {report.function}</p>
                        <p><strong>Type:</strong> {report.type.replace('_', ' ').title()}</p>
                        <p><strong>Risk Level:</strong> {report.risk}</p>
                    </div>
            """)
            
            # Proof chain
            if report.proof_chain:
                html_parts.append('<div class="section"><h4>🔗 Proof Chain</h4><div class="proof-chain">')
                for step in report.proof_chain:
                    html_parts.append(f'''
                    <div class="proof-step">
                        <span class="addr">0x{step['address'][-8:]}</span>: {step['instruction']}
                        <br><span style="color: #666; font-size: 0.9em;">&nbsp;&nbsp;→ {step['description']}</span>
                    </div>
                    ''')
                html_parts.append('</div></div>')
            
            # Code snippets
            if report.code_snippets:
                html_parts.append('<div class="section"><h4>💻 Code Context</h4>')
                for snippet in report.code_snippets:
                    html_parts.append('<div class="code-block">')
                    for line in snippet['disasm'][:10]:  # Show first 10 lines
                        html_parts.append(f"0x{line['addr'][-8:]:>8}: {line['instruction']}<br>")
                    if len(snippet['disasm']) > 10:
                        html_parts.append(f"... (+{len(snippet['disasm'])-10} more lines)<br>")
                    html_parts.append('</div>')
                html_parts.append('</div>')
            
            # CVSS Score
            html_parts.append(f'''
                    <div class="section">
                        <h4>📈 Risk Assessment</h4>
                        <div class="cvss-score">
                            <div>CVSS v3.1 Base Score: <span class="cvss-value">{cvss:.1f}/10.0</span></div>
                            <div style="font-size: 0.9em; color: #666; margin-top: 5px;">
                                {self._get_severity_description(cvss)}
                            </div>
                        </div>
                    </div>
            ''')
            
            # Remediation
            if report.remediation:
                html_parts.append(f'''
                    <div class="section">
                        <h4>🛠️ Remediation</h4>
                        <div class="remediation">
                            <h5>Priority: {report.remediation['priority']}</h5>
                            <p>{report.remediation['suggestion']}</p>
                        </div>
                    </div>
                ''')
            
            html_parts.append('</div></div>')
        
        # Footer
        html_parts.append(f"""
        </div>
        
        <div class="footer">
            <p>🔍 MIPS Audit Tool v3.1 | Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>For details and remediation guidance, consult the Proof Chain and Remediation sections for each finding.</p>
        </div>
    </div>
    
    <script>
        function toggleFinding(header) {{
            const content = header.nextElementSibling;
            content.classList.toggle('show');
            const btn = header.querySelector('.toggle-btn');
            btn.textContent = content.classList.contains('show') ? '▲' : '▼';
        }}
    </script>
</body>
</html>
        """)
        
        return ''.join(html_parts)
    
    def _get_severity_description(self, score):
        """Get severity description based on CVSS score"""
        if score >= 9.0:
            return "Critical - Immediate action required"
        elif score >= 7.0:
            return "High - Should be fixed urgently"
        elif score >= 4.0:
            return "Medium - Should be addressed soon"
        else:
            return "Low - Consider for future patches"
    
    def export_json(self, filename=None):
        """Export as JSON for programmatic processing"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"mipsAudit_results_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        data = {
            'summary': self.summary,
            'timestamp': datetime.now().isoformat(),
            'reports': [r.to_dict() for r in self.reports]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def export_csv(self, filename=None):
        """Export as CSV for spreadsheet analysis"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"mipsAudit_results_{timestamp}.csv"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'type', 'risk', 'address', 'function', 'cvss_score',
                'proof_chain_length', 'remediation', 'timestamp'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for report in self.reports:
                writer.writerow({
                    'type': report.type,
                    'risk': report.risk,
                    'address': report.address,
                    'function': report.function,
                'cvss_score': f"{report.calculate_cvss_score():.1f}",
                    'proof_chain_length': len(report.proof_chain),
                    'remediation': report.remediation['suggestion'] if report.remediation else 'N/A',
                    'timestamp': report.timestamp
                })
        
        return filepath
