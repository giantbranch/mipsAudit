# -*- coding: utf-8 -*-
"""
Integration Module for Enhanced MIPS Audit

Integrates all enhanced analysis modules into the main mipsAudit workflow.

Author: giantbranch
Version: 3.1
"""

import sys
import os

# Import enhanced modules
try:
    from taint_analysis import TaintAnalyzer, TaintType, TaintInfo
    from advanced_vulnerability_detection import (
        UseAfterFreeDetector, TOCTOUDetector, IntegerUnderflowDetector,
        OffByOneDetector, BufferOverflowLoopDetector
    )
    from false_positive_filter import FalsePositiveFilter
    from control_flow_analyzer import ControlFlowAnalyzer
    from enhanced_report_exporter import EnhancedReportExporter, VulnerabilityReport
    ENHANCED_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"[!] Warning: Enhanced modules not fully available: {e}")
    ENHANCED_MODULES_AVAILABLE = False


class EnhancedAuditEngine:
    """Main enhanced audit engine combining all analysis modules"""
    
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.taint_analyzer = TaintAnalyzer() if ENHANCED_MODULES_AVAILABLE else None
        self.uaf_detector = UseAfterFreeDetector() if ENHANCED_MODULES_AVAILABLE else None
        self.toctou_detector = TOCTOUDetector() if ENHANCED_MODULES_AVAILABLE else None
        self.int_underflow_detector = IntegerUnderflowDetector() if ENHANCED_MODULES_AVAILABLE else None
        self.off_by_one_detector = OffByOneDetector() if ENHANCED_MODULES_AVAILABLE else None
        self.buffer_overflow_loop_detector = BufferOverflowLoopDetector() if ENHANCED_MODULES_AVAILABLE else None
        self.false_positive_filter = FalsePositiveFilter() if ENHANCED_MODULES_AVAILABLE else None
        self.cfg_analyzer = ControlFlowAnalyzer() if ENHANCED_MODULES_AVAILABLE else None
        self.report_exporter = EnhancedReportExporter(output_dir) if ENHANCED_MODULES_AVAILABLE else None
        self.findings = []
    
    def run_comprehensive_analysis(self, binary_funcs):
        """
        Run comprehensive vulnerability analysis on binary
        """
        if not ENHANCED_MODULES_AVAILABLE:
            print("[!] Enhanced modules not available - using basic mode")
            return []
        
        print("\n" + "="*60)
        print("  PHASE 1: Taint Analysis")
        print("="*60)
        
        # Collect external input sources
        self.taint_analyzer.identify_external_inputs()
        self.taint_analyzer.build_call_graph()
        
        print("\n" + "="*60)
        print("  PHASE 2: Advanced Vulnerability Detection")
        print("="*60)
        
        all_findings = []
        
        for func_addr in binary_funcs:
            print(f"[*] Analyzing function @ 0x{func_addr:x}")
            
            # Build CFG
            self.cfg_analyzer.build_cfg(func_addr)
            self.cfg_analyzer.detect_loops(func_addr)
            
            # Detect various vulnerability types
            all_findings.extend(self.uaf_detector.analyze_function(func_addr))
            all_findings.extend(self.toctou_detector.detect_in_function(func_addr))
            all_findings.extend(self.int_underflow_detector.detect_in_function(func_addr))
            all_findings.extend(self.off_by_one_detector.detect_in_function(func_addr))
            all_findings.extend(self.buffer_overflow_loop_detector.detect_in_function(func_addr))
        
        print(f"\n[*] Found {len(all_findings)} potential vulnerabilities before filtering")
        
        print("\n" + "="*60)
        print("  PHASE 3: False Positive Filtering")
        print("="*60)
        
        # Apply false positive filter
        filtered_findings, removed_count = self.false_positive_filter.apply_filters(all_findings)
        print(f"[*] Filtered out {removed_count} false positives")
        print(f"[*] {len(filtered_findings)} findings remain after filtering")
        
        print("\n" + "="*60)
        print("  PHASE 4: Report Generation")
        print("="*60)
        
        # Create and export reports
        for finding in filtered_findings:
            report = self._create_vulnerability_report(finding)
            if report:
                self.report_exporter.add_report(report)
        
        # Export reports
        html_path = self.report_exporter.export_html()
        json_path = self.report_exporter.export_json()
        csv_path = self.report_exporter.export_csv()
        
        print(f"\n[✓] Reports generated:")
        print(f"    HTML: {os.path.basename(html_path)}")
        print(f"    JSON: {os.path.basename(json_path)}")
        print(f"    CSV:  {os.path.basename(csv_path)}")
        
        return filtered_findings
    
    def _create_vulnerability_report(self, finding):
        """
        Convert finding to detailed vulnerability report
        """
        if not finding:
            return None
        
        vuln_type = finding.get('type', 'unknown')
        risk = finding.get('risk', 'MEDIUM')
        addr = finding.get('address', finding.get('addr', '0x0'))
        func = finding.get('function', finding.get('use_func', 'unknown'))
        
        # Create report
        report = VulnerabilityReport(vuln_type, risk, addr, func)
        
        # Add metadata from finding
        report.metadata = {k: v for k, v in finding.items() 
                          if k not in ['type', 'risk', 'address', 'function']}
        
        # Add remediation suggestion
        remediation_db = EnhancedReportExporter.REMEDIATION_DB
        if vuln_type in remediation_db:
            suggestion = remediation_db[vuln_type]['suggestion']
            priority = remediation_db[vuln_type]['priority']
            report.set_remediation(suggestion, priority)
        
        return report


def integrate_enhanced_analysis_into_main():
    """
    Instructions for integrating enhanced analysis into mipsAudit.py
    """
    integration_guide = """
    Integration Steps for Enhanced Analysis:
    
    1. Add to top of mipsAudit.py:
       from enhanced_audit_engine import EnhancedAuditEngine, ENHANCED_MODULES_AVAILABLE
    
    2. In mipsAudit() function, after PHASE 1, add:
       if ENHANCED_MODULES_AVAILABLE:
           enhanced_engine = EnhancedAuditEngine(get_output_dir())
           binary_funcs = list(idautils.Functions())
           enhanced_findings = enhanced_engine.run_comprehensive_analysis(binary_funcs)
    
    3. Replace PHASE 2-4 with calls to enhanced engine
    
    4. Ensure all modules (.py files) are in same directory as mipsAudit.py
    """
    return integration_guide


if __name__ == '__main__':
    print(integrate_enhanced_analysis_into_main())
