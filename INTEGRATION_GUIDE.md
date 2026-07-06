# Integration Guide - Integrating Enhanced Analysis into mipsAudit.py

## Quick Integration (5 minutes)

### Step 1: Copy Enhanced Modules

Place all these files in the same directory as `mipsAudit.py`:

```
mipsAudit/
├── mipsAudit.py
├── taint_analysis.py              ← NEW
├── advanced_vulnerability_detection.py  ← NEW
├── false_positive_filter.py        ← NEW
├── control_flow_analyzer.py        ← NEW
├── enhanced_report_exporter.py     ← NEW
└── enhanced_audit_engine.py        ← NEW
```

### Step 2: Modify mipsAudit.py

Add this import at the top of the file (after existing imports):

```python
# Add after line 21 (after other imports)
try:
    from enhanced_audit_engine import EnhancedAuditEngine, ENHANCED_MODULES_AVAILABLE
except ImportError:
    print("[!] Enhanced modules not available, using basic mode")
    ENHANCED_MODULES_AVAILABLE = False
```

### Step 3: Update mipsAudit() Function

Find the `mipsAudit()` function and modify the PHASE 2-4 section.

**Before (original code around line 1393-1442):**

```python
print("\n" + "="*60)
print("  PHASE 2: Enhanced Vulnerability Detection")
print("="*60)

print("\n[*] Enhanced analysis: Command Injection Detection")
for func_name in command_execution_function:
    auditEnhanced(func_name)

# ... more phases ...
```

**After (with enhanced analysis):**

```python
if ENHANCED_MODULES_AVAILABLE:
    print("\n" + "="*60)
    print("  PHASE 2-5: Enhanced Analysis (New!)")
    print("="*60)
    
    try:
        # Collect all functions to analyze
        binary_funcs = list(set(idautils.Functions()))
        print(f"[*] Analyzing {len(binary_funcs)} functions...")
        
        # Run enhanced engine
        enhanced_engine = EnhancedAuditEngine(get_output_dir())
        enhanced_findings = enhanced_engine.run_comprehensive_analysis(binary_funcs)
        
        # Merge with existing audit results
        audit_results.extend([f for f in enhanced_findings if isinstance(f, dict)])
        
    except Exception as e:
        print(f"[!] Enhanced analysis error: {e}")
        print("[*] Continuing with basic analysis...")
else:
    # Fallback to original analysis
    print("\n" + "="*60)
    print("  PHASE 2: Enhanced Vulnerability Detection")
    print("="*60)
    
    print("\n[*] Enhanced analysis: Command Injection Detection")
    for func_name in command_execution_function:
        auditEnhanced(func_name)
    
    # ... rest of original code ...
```

### Step 4: Test Integration

In IDA Pro:
```
File → Script file → mipsAudit.py
```

You should see:
```
PHASE 1: Basic Function Audit
...
PHASE 2-5: Enhanced Analysis (New!)
[*] Identifying external input sources...
[*] Building call graph...
[*] Analyzing 234 functions...
[*] Reports generated:
    HTML: mipsAudit_report_20260704_032945.html
    JSON: mipsAudit_results_20260704_032945.json
    CSV:  mipsAudit_results_20260704_032945.csv
```

## Advanced Integration

### Option A: Selective Enhancement

Enable only specific detectors:

```python
# In enhanced_audit_engine.py, modify run_comprehensive_analysis():

def run_comprehensive_analysis(self, binary_funcs, 
                               enable_taint=True,
                               enable_uaf=True,
                               enable_toctou=True,
                               enable_int_underflow=True,
                               enable_off_by_one=True,
                               enable_loop_analysis=True):
    
    if enable_taint:
        print("[*] Running taint analysis...")
        # Taint analysis
    
    if enable_uaf:
        print("[*] Running UAF detection...")
        # UAF detection
    
    # ... etc ...
```

### Option B: Parallel Processing

For large binaries, process functions in parallel:

```python
from multiprocessing import Pool

def analyze_function_parallel(func_addr):
    uaf = UseAfterFreeDetector().analyze_function(func_addr)
    toctou = TOCTOUDetector().detect_in_function(func_addr)
    return uaf + toctou

def run_parallel_analysis(binary_funcs):
    with Pool(4) as pool:
        results = pool.map(analyze_function_parallel, binary_funcs)
    return [item for sublist in results for item in sublist]
```

### Option C: Streaming Results

For real-time feedback on large binaries:

```python
def stream_analysis_results(binary_funcs):
    for i, func_addr in enumerate(binary_funcs):
        findings = analyze_function(func_addr)
        if findings:
            yield findings
        
        # Progress indicator every 50 functions
        if (i + 1) % 50 == 0:
            print(f"[*] Processed {i+1}/{len(binary_funcs)} functions")
```

## Troubleshooting

### Error: "No module named 'taint_analysis'"

**Cause**: Files not in same directory

**Fix**:
```bash
# Verify files are in IDA's script directory
ls -la ~/.idapro/plugins/
# Or copy to IDA installation
cp *.py "C:\Program Files\IDA Pro 7.6\plugins\"
```

### Error: "IDA API not available in enhanced modules"

**Cause**: Enhanced modules imported before IDA API initialized

**Fix**: Delay import to inside mipsAudit() function:
```python
def mipsAudit():
    # Import enhanced modules here, not at top level
    from enhanced_audit_engine import EnhancedAuditEngine
    # ... rest of code ...
```

### Performance Issue: "Audit takes too long"

**Solutions**:

1. Reduce analysis depth:
```json
{
    "max_taint_depth": 10,  // Reduce from 20
    "cfg_max_blocks": 1000
}
```

2. Disable expensive detectors:
```python
enhanced_engine.uaf_detector = None  # Skip UAF
enhanced_engine.cfg_analyzer = None  # Skip CFG
```

3. Analyze specific functions:
```python
# Instead of all functions
binary_funcs = [0x401000, 0x402000]  # Only analyze these
findings = engine.run_comprehensive_analysis(binary_funcs)
```

## Verification Checklist

- [ ] All 7 `.py` files copied to script directory
- [ ] Import added to mipsAudit.py
- [ ] mipsAudit() function updated
- [ ] Test run completes without errors
- [ ] HTML report generated successfully
- [ ] JSON and CSV files created
- [ ] Enhanced findings included in report
- [ ] No "module not found" errors

## Performance Metrics

Expected analysis times (on 2GHz CPU, 100 functions):

| Phase | Time |
|-------|------|
| PHASE 1 (Basic Audit) | 1-2 min |
| PHASE 2 (Taint Analysis) | 1-2 min |
| PHASE 3 (Advanced Detection) | 2-3 min |
| PHASE 4 (CFG Analysis) | 1-2 min |
| PHASE 5 (Filtering) | 30-60 sec |
| PHASE 6 (Report) | 10-30 sec |
| **Total** | **6-10 min** |

## Migration Path

### Step 1: Parallel Deployment

Keep original `mipsAudit.py` and create `mipsAudit_v3.1.py`:

```python
# mipsAudit_v3.1.py
from mipsAudit import *  # Import all original code
from enhanced_audit_engine import EnhancedAuditEngine

def mipsAudit():
    # Enhanced version
    enhanced_engine = EnhancedAuditEngine(get_output_dir())
    # ...
```

### Step 2: A/B Testing

Run both versions and compare results:

```bash
# Run original
python mipsAudit.py input.bin > v3.0_report.txt

# Run enhanced
python mipsAudit_v3.1.py input.bin > v3.1_report.txt

# Compare
diff v3.0_report.txt v3.1_report.txt
```

### Step 3: Production Rollout

Once validated, replace original with enhanced version.

## Support

For integration issues:
1. Check error messages in IDA output window
2. Verify Python version: `python --version` (should be 3.6+)
3. Test individual modules in IDA Python console
4. Review ENHANCEMENT_GUIDE_CN.md for detailed info

---

**Need help?** Add your question as a GitHub Issue.
