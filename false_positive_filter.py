# -*- coding: utf-8 -*-
"""
False Positive Filter Module

Reduces false positives through:
- Validation check detection
- Safe wrapper identification
- Library code filtering
- Dead code detection
- Modern defense recognition

Author: giantbranch
Version: 3.1
"""

import idc
import idaapi
import idautils
from collections import defaultdict

BADADDR = idaapi.BADADDR


class FalsePositiveFilter:
    """Filter out false positive vulnerability reports"""
    
    def __init__(self):
        self.safe_wrappers = {}  # Function name -> wrapper info
        self.library_functions = set()
        self.validated_ptrs = {}  # addr -> validation info
        self.protected_regions = {}  # addr range -> protection type
    
    def is_safe_wrapper(self, func_addr):
        """
        Check if function is a safe wrapper (e.g., safe_strcpy)
        Returns: (is_wrapper, wrapper_type, protection)
        """
        func_name = idc.get_func_name(func_addr)
        
        if not func_name:
            return (False, None, None)
        
        # Check naming patterns
        safe_patterns = [
            'safe_', '_safe', 'secure_', '_secure',
            'checked_', '_checked', 'validated_', '_validated',
            'bounded_', '_bounded', 'limited_', '_limited'
        ]
        
        for pattern in safe_patterns:
            if pattern in func_name.lower():
                return (True, 'name_pattern', {'pattern': pattern})
        
        # Check if function contains validation logic
        validation_count = 0
        for addr in idautils.FuncItems(func_addr):
            mnem = idc.print_insn_mnem(addr)
            disasm = idc.GetDisasm(addr).lower()
            
            # Count validation-like operations
            if mnem in ['slt', 'slti', 'sle', 'ble', 'bge', 'bgt', 'bne', 'beq']:
                validation_count += 1
            
            if any(word in disasm for word in ['check', 'validate', 'limit', 'bound', 'size', 'length']):
                validation_count += 1
        
        if validation_count >= 3:
            return (True, 'validation_logic', {'validation_count': validation_count})
        
        return (False, None, None)
    
    def has_length_validation(self, addr, lookback=15):
        """
        Check if instruction has preceding length validation
        Returns: (is_validated, validation_type, validation_addr)
        """
        scan_addr = idc.prev_head(addr)
        scan_count = 0
        
        while scan_addr != BADADDR and scan_count < lookback:
            mnem = idc.print_insn_mnem(scan_addr)
            disasm = idc.GetDisasm(scan_addr).lower()
            
            # Pattern 1: Comparison with size/length
            if mnem in ['slt', 'slti', 'sle', 'ble']:
                operands = idc.GetDisasm(scan_addr)
                if any(word in operands for word in ['length', 'size', 'max', 'limit']):
                    return (True, 'length_comparison', scan_addr)
            
            # Pattern 2: Function call to validation function
            if mnem in ['jal', 'jalr']:
                target = idc.print_operand(scan_addr, 0)
                if any(word in target.lower() for word in ['validate', 'check', 'verify', 'safe', 'secure']):
                    return (True, 'validation_call', scan_addr)
            
            # Pattern 3: snprintf/strncpy with size limit
            if mnem in ['jal', 'jalr']:
                target = idc.print_operand(scan_addr, 0)
                if target in ['snprintf', 'strncpy', 'strncat', 'vsnprintf', 'memcpy', 'memmove']:
                    return (True, 'safe_function_call', scan_addr)
            
            # Pattern 4: Explicit bounds check
            if 'bounds' in disasm or 'limit' in disasm or 'max' in disasm:
                return (True, 'bounds_check', scan_addr)
            
            scan_count += 1
            scan_addr = idc.prev_head(scan_addr)
        
        return (False, None, None)
    
    def is_dead_code(self, addr):
        """
        Check if address is in dead code path
        Returns: (is_dead, reason)
        """
        func = idaapi.get_func(addr)
        if not func:
            return (False, None)
        
        # Check if instruction is unreachable
        try:
            flowchart = idaapi.FlowChart(func)
            for block in flowchart:
                if block.start_ea <= addr < block.end_ea:
                    # Found the block containing this address
                    # Check if block has incoming edges
                    if not block.predlist:
                        # No predecessors = unreachable except for function entry
                        if addr != func.start_ea:
                            return (True, 'unreachable_block')
                    return (False, None)
        except:
            pass
        
        return (False, None)
    
    def is_library_code(self, func_addr):
        """
        Check if function is from standard library
        Returns: (is_library, library_name)
        """
        func_name = idc.get_func_name(func_addr)
        
        if not func_name:
            return (False, None)
        
        # Standard library patterns
        libc_patterns = [
            'strcpy', 'strcat', 'sprintf',  # Standard C
            '__libc_', 'libc_', '_lib',     # libc internal
            'malloc', 'free', 'calloc',     # Memory
            'memcpy', 'memmove', 'memset',  # Memory
            'printf', 'fprintf', 'snprintf' # stdio
        ]
        
        for pattern in libc_patterns:
            if pattern in func_name.lower():
                return (True, 'libc')
        
        # Check segment
        seg = idaapi.getseg(func_addr)
        if seg:
            seg_name = idaapi.get_segm_name(seg)
            if seg_name in ['.plt', '.text', '.init', '.fini', '.got']:
                # Library segments
                if func_name.startswith(('__', 'lib', 'sys')):
                    return (True, 'system_segment')
        
        return (False, None)
    
    def has_stack_canary(self, func_addr):
        """
        Detect if function has stack canary protection
        Returns: (has_canary, canary_addr)
        """
        # Look for canary setup at function prologue
        addr = func_addr
        
        for i in range(5):  # Check first few instructions
            if addr == BADADDR:
                break
            
            disasm = idc.GetDisasm(addr).lower()
            
            # Canary patterns
            if any(pattern in disasm for pattern in ['__stack_chk', 'canary', 'guard', '__guard']):
                return (True, addr)
            
            addr = idc.next_head(addr)
        
        return (False, None)
    
    def has_aslr_protection(self):
        """
        Check if binary has ASLR/PIE protection
        Returns: bool
        """
        # Check binary properties
        try:
            info = idaapi.get_inf_structure()
            # In a real scenario, check ELF flags for PIE/ASLR
            return False  # Simplified for MIPS static analysis
        except:
            return False
    
    def filter_finding(self, finding):
        """
        Determine if finding should be filtered out
        Returns: (should_filter, reason, adjusted_risk)
        """
        call_addr = finding.get('address')
        if not call_addr:
            return (False, None, finding.get('risk'))
        
        try:
            addr = int(call_addr, 16) if isinstance(call_addr, str) else call_addr
        except:
            return (False, None, finding.get('risk'))
        
        # Check if dead code
        is_dead, reason = self.is_dead_code(addr)
        if is_dead:
            return (True, f'dead_code:{reason}', None)
        
        # Check if library code
        func = idaapi.get_func(addr)
        if func:
            is_lib, lib_name = self.is_library_code(func.start_ea)
            if is_lib and lib_name != 'libc':
                return (True, f'library_code:{lib_name}', None)
        
        # Check for validation
        if finding.get('issue', '').lower() not in ['use_after_free', 'double_free']:
            has_val, val_type, val_addr = self.has_length_validation(addr)
            if has_val:
                risk = finding.get('risk')
                # Downgrade risk level if validated
                if risk == 'HIGH':
                    return (False, f'has_validation:{val_type}', 'MEDIUM')
                elif risk == 'MEDIUM':
                    return (False, f'has_validation:{val_type}', 'LOW')
        
        # Check if safe wrapper
        if func:
            is_safe, wrapper_type, info = self.is_safe_wrapper(func.start_ea)
            if is_safe:
                return (False, f'safe_wrapper:{wrapper_type}', 'LOW')
        
        # Check for stack canary
        if func:
            has_canary, canary_addr = self.has_stack_canary(func.start_ea)
            if has_canary and finding.get('risk') == 'HIGH':
                # Stack buffer overflow is mitigated
                return (False, 'stack_canary_protection', 'MEDIUM')
        
        return (False, None, finding.get('risk'))
    
    def apply_filters(self, findings):
        """
        Apply all filters to findings list
        Returns: (filtered_findings, removed_count)
        """
        filtered = []
        removed = 0
        
        for finding in findings:
            should_filter, reason, adjusted_risk = self.filter_finding(finding)
            
            if should_filter:
                removed += 1
            else:
                # Apply risk adjustment if any
                if adjusted_risk:
                    finding['risk'] = adjusted_risk
                    finding['filter_reason'] = reason
                
                filtered.append(finding)
        
        return (filtered, removed)
