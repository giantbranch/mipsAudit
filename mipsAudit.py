# -*- coding: utf-8 -*-

# reference
# 《ida pro 权威指南》
# 《python 灰帽子》
# 《家用路由器0day漏洞挖掘》
# https://github.com/wangzery/SearchOverflow/blob/master/SearchOverflow.py

# Updated for IDA 7.x+ API and Python 3
# Enhanced with advanced vulnerability detection v3.0

import idc
import idaapi
import idautils
from prettytable import PrettyTable
from collections import defaultdict
import json
import csv
import os
import re
from datetime import datetime

# IDA 7.x+ uses BADADDR from idaapi
BADADDR = idaapi.BADADDR


DEBUG = True

# ============================================================
# Configuration - Can be overridden by external config file
# ============================================================

CONFIG_FILE = "mipsAudit_config.json"

# Default function lists (can be extended via config file)
dangerous_functions = [
    "strcpy", 
    "strcat",  
    "sprintf",
    "read", 
    "getenv",
    "gets",           # No boundary check - extremely dangerous
    "scanf",          # Format input vulnerability
    "vscanf",
    "realpath",       # Path traversal
    "access",         # TOCTOU race condition
    "stat",           # TOCTOU race condition
    "lstat",
]

attention_function = [
    "memcpy",
    "strncpy",
    "sscanf", 
    "strncat", 
    "snprintf",
    "vprintf", 
    "printf",
    "fprintf",
    "vfprintf",
    "vsprintf",
    "vsnprintf",
    "syslog",
    "memmove",
    "bcopy",
]

command_execution_function = [
    "system", 
    "execve",
    "popen",
    "unlink",
    "execl",
    "execle", 
    "execlp",
    "execv",
    "execvp",
    "dlopen",
    "mmap",           # Memory mapping
    "mprotect",       # Change memory protection
]

# External input source functions (for taint tracking)
external_input_functions = [
    "getenv",
    "read",
    "recv",
    "recvfrom",
    "recvmsg",
    "fgets",
    "fread",
    "fgetc",
    "gets",
    "scanf",
    "fscanf",
    "getchar",
    "getc",
    "fgetws",
    "getwchar",
    "getline",
    "getdelim",
    "socket",
    "accept",
    "gethostbyname",
]

# Memory management functions
memory_alloc_functions = [
    "malloc",
    "calloc",
    "realloc",
    "memalign",
    "valloc",
    "pvalloc",
    "aligned_alloc",
    "mmap",
]

memory_free_functions = [
    "free",
    "cfree",
    "munmap",
]

# Format string functions (for %n detection)
format_string_functions = [
    "printf",
    "fprintf", 
    "sprintf",
    "snprintf",
    "vprintf",
    "vfprintf",
    "vsprintf",
    "vsnprintf",
    "syslog",
]

# describe arg num of function
one_arg_function = [
    "getenv",
    "system",
    "unlink",
    "free",
    "cfree",
    "malloc",
    "gets",
]

two_arg_function = [
    "strcpy", 
    "strcat",
    "popen",
    "calloc",
    "dlopen",
    "fgets",
    "access",
    "stat",
    "lstat",
    "realpath",
    "mprotect",
]

three_arg_function = [
    "strncpy",
    "strncat", 
    "memcpy",
    "memmove",
    "bcopy",
    "execve",
    "read",
    "recv",
    "fread",
    "realloc",
]

format_function_offset_dict = {
    "sprintf": 1,
    "sscanf": 1,
    "snprintf": 2,
    "vprintf": 0,
    "printf": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "vsprintf": 1,
    "vsnprintf": 2,
    "syslog": 1,
    "scanf": 0,
}

# Risk level colors
RISK_HIGH = 0x0000ff    # Red
RISK_MEDIUM = 0x00a5ff  # Orange
RISK_LOW = 0x00ff00     # Green
RISK_INFO = 0xffff00    # Cyan

# ============================================================
# Enhanced Analysis - Data Structures
# ============================================================

# Store function call information for cross-reference analysis
taint_sources = {}      # addr -> function_name (external input sources)
free_calls = defaultdict(list)  # func_addr -> [(call_addr, arg_info), ...]
audit_results = []      # Store all findings for export
wrapper_functions = {}  # Detected wrapper functions
data_flow_graph = defaultdict(list)  # addr -> [(dest_addr, dest_func), ...]

# Progress tracking
total_functions = 0
processed_functions = 0


# ============================================================
# Configuration File Support
# ============================================================

def get_output_dir():
    """Get output directory - uses IDB directory in IDA environment"""
    try:
        idb_path = idc.get_idb_path()
        if idb_path:
            return os.path.dirname(idb_path)
    except:
        pass
    return os.getcwd()


def load_config():
    """Load configuration from external JSON file"""
    global dangerous_functions, attention_function, command_execution_function
    global external_input_functions, memory_alloc_functions, memory_free_functions
    global format_string_functions
    
    config_path = os.path.join(get_output_dir(), CONFIG_FILE)
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Extend function lists from config
            if 'dangerous_functions' in config:
                dangerous_functions.extend(config['dangerous_functions'])
            if 'attention_function' in config:
                attention_function.extend(config['attention_function'])
            if 'command_execution_function' in config:
                command_execution_function.extend(config['command_execution_function'])
            if 'external_input_functions' in config:
                external_input_functions.extend(config['external_input_functions'])
            if 'memory_alloc_functions' in config:
                memory_alloc_functions.extend(config['memory_alloc_functions'])
            if 'memory_free_functions' in config:
                memory_free_functions.extend(config['memory_free_functions'])
            if 'format_string_functions' in config:
                format_string_functions.extend(config['format_string_functions'])
            
            print("[*] Loaded configuration from %s" % config_path)
            return True
        except Exception as e:
            print("[!] Error loading config: %s" % str(e))
    return False


def save_default_config():
    """Save current configuration as default config file"""
    config_path = os.path.join(get_output_dir(), CONFIG_FILE)
    config = {
        "dangerous_functions": [],
        "attention_function": [],
        "command_execution_function": [],
        "external_input_functions": [],
        "memory_alloc_functions": [],
        "memory_free_functions": [],
        "format_string_functions": [],
        "_comment": "Add custom functions to extend the default lists"
    }
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4)
        print("[*] Created default config file: %s" % config_path)
    except Exception as e:
        print("[!] Error saving config: %s" % str(e))


# ============================================================
# Progress Display
# ============================================================

def show_progress(current, total, prefix="Progress"):
    """Display progress bar in IDA output"""
    if total == 0:
        return
    percent = (current * 100) // total
    bar_len = 30
    filled = (current * bar_len) // total
    bar = '=' * filled + '-' * (bar_len - filled)
    print("\r%s: [%s] %d%% (%d/%d)" % (prefix, bar, percent, current, total), end='')
    if current == total:
        print()  # New line when complete


# ============================================================
# Helper Functions
# ============================================================

def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Auditing " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

def getFuncAddr(func_name):
    func_addr = idc.get_name_ea_simple(func_name)
    if func_addr != BADADDR:
        print(printFunc(func_name))
        return func_addr
    return False

def getFormatString(addr):
    op_num = 1
    # idc.get_operand_type Return value
    # o_void        0  // No Operand
    # o_reg         1  // General Register (al, ax, es, ds...) reg
    # o_mem         2  // Direct Memory Reference  (DATA)      addr
    # o_phrase      3  // Memory Ref [Base Reg + Index Reg]    phrase
    # o_displ       4  // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    # o_imm         5  // Immediate Value                      value
    # o_far         6  // Immediate Far Address  (CODE)        addr
    # o_near        7  // Immediate Near Address (CODE)        addr
    # o_idpspec0    8  // IDP specific type
    # o_idpspec1    9  // IDP specific type
    # o_idpspec2   10  // IDP specific type
    # o_idpspec3   11  // IDP specific type
    # o_idpspec4   12  // IDP specific type
    # o_idpspec5   13  // IDP specific type
    if idc.get_operand_type(addr, op_num) != 5:
        op_num = op_num + 1
    if idc.get_operand_type(addr, op_num) != 5:
        return "get fail"
    op_string = idc.print_operand(addr, op_num).split(" ")[0].split("+")[0].split("-")[0].replace("(", "")
    string_addr = idc.get_name_ea_simple(op_string)
    if string_addr == BADADDR:
        return "get fail"
    string_content = idc.get_strlit_contents(string_addr)
    if string_content is None:
        return "get fail"
    if isinstance(string_content, bytes):
        string_content = string_content.decode('utf-8', errors='replace')
    return [string_addr, string_content]


def getArgAddr(start_addr, regNum):
    mipscondition = ["bn", "be" , "bg", "bl"]
    scan_deep = 50
    count = 0
    reg = "$a" + str(regNum)
    # try to get in the next (code references from this address)
    for next_addr in idautils.CodeRefsFrom(start_addr, 0):
        if next_addr != BADADDR and reg == idc.print_operand(next_addr, 0):
            return next_addr
    # try to get before (code references to this address)
    before_addr = start_addr
    for ref_addr in idautils.CodeRefsTo(start_addr, 0):
        before_addr = ref_addr
        break
    if before_addr == start_addr:
        before_addr = idc.prev_head(start_addr)
    
    while before_addr != BADADDR:
        if reg == idc.print_operand(before_addr, 0):
            Mnemonics = idc.print_insn_mnem(before_addr)
            if Mnemonics[0:2] in mipscondition:
                pass
            elif Mnemonics[0:1] == "j":
                pass
            else:
                return before_addr
        count = count + 1
        if count > scan_deep:
            break 
        before_addr = idc.prev_head(before_addr)
    return BADADDR


def getArg(start_addr, regNum):
    mipsmov = ["move", "lw", "li", "lb", "lui", "lhu", "lbu", "la"]
    arg_addr = getArgAddr(start_addr, regNum)
    if arg_addr != BADADDR:
        Mnemonics = idc.print_insn_mnem(arg_addr) 
        if Mnemonics[0:3] == "add":
            if idc.print_operand(arg_addr, 2) == "":
                arg = idc.print_operand(arg_addr, 0) + "+" + idc.print_operand(arg_addr, 1)
            else:
                arg = idc.print_operand(arg_addr, 1) + "+" + idc.print_operand(arg_addr, 2)
        elif Mnemonics[0:3] == "sub":
            if idc.print_operand(arg_addr, 2) == "":
                arg = idc.print_operand(arg_addr, 0) + "-" + idc.print_operand(arg_addr, 1)
            else:
                arg = idc.print_operand(arg_addr, 1) + "-" + idc.print_operand(arg_addr, 2)
        elif Mnemonics in mipsmov:
            arg = idc.print_operand(arg_addr, 1) 
        else:
            arg = idc.GetDisasm(arg_addr).split("#")[0]
        idc.set_cmt(arg_addr, "addr: 0x%x " % start_addr + "-------> arg" + str((int(regNum)+1)) + " : " + arg, 0)
        return arg
    else:
        return "get fail"

def audit(func_name):
    func_addr = getFuncAddr(func_name)  
    if func_addr == False:
        return False

    # get arg num and set table
    if func_name in one_arg_function:
        arg_num = 1
    elif func_name in two_arg_function:
        arg_num = 2
    elif func_name in three_arg_function:
        arg_num = 3
    elif func_name in format_function_offset_dict:
        arg_num = format_function_offset_dict[func_name] + 1
    else:
        print("The %s function didn't write in the describe arg num of function array, please add it to, such as add to `two_arg_function` array" % func_name)
        return
    # mispcall = ["jal", "jalr", "bal", "jr"]
    table_head = ["func_name", "addr"]
    for num in range(0, arg_num):
        table_head.append("arg"+str(num+1))
    if func_name in format_function_offset_dict:
        table_head.append("format&value[string_addr, num of '%', fmt_arg...]")
    table_head.append("local_buf_size")
    table = PrettyTable(table_head)

    # get references to function (xrefs)
    for call_addr in idautils.CodeRefsTo(func_addr, 0):
        # set color - green (red=0x0000ff, blue=0xff0000)
        idc.set_color(call_addr, idc.CIC_ITEM, 0x00ff00)
        # set break point
        # idc.add_bpt(call_addr)
        # idc.del_bpt(call_addr)

        Mnemonics = idc.print_insn_mnem(call_addr)
        if Mnemonics[0:1] == "j" or Mnemonics[0:1] == "b":
            if func_name in format_function_offset_dict:
                info = auditFormat(call_addr, func_name, arg_num)
            else:
                info = auditAddr(call_addr, func_name, arg_num)
            table.add_row(info)
    print(table)
    # data_addr = DfirstB(func_addr)
    # while data_addr != BADADDR:
    #     Mnemonics = GetMnem(data_addr)
    #     if DEBUG:
    #         print "Data Mnemonics : %s" % GetMnem(data_addr)
    #         print "Data addr : 0x %s" % data_addr
    #     data_addr = DnextB(func_addr, data_addr)

def auditAddr(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr, idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR:
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in range(0, arg_num):
        ret_list.append(getArg(call_addr, num)) 
    ret_list.append(local_buf_size)
    return ret_list

def auditFormat(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr, idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR:
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in range(0, arg_num):
        ret_list.append(getArg(call_addr, num)) 
    arg_addr = getArgAddr(call_addr, format_function_offset_dict[func_name])
    string_and_addr = getFormatString(arg_addr)
    format_and_value = []
    if string_and_addr == "get fail":
        ret_list.append("get fail")
    else:
        string_addr = "0x%x" % string_and_addr[0]
        format_and_value.append(string_addr)
        string = string_and_addr[1]
        fmt_num = string.count("%")
        format_and_value.append(fmt_num)
        # mips arg reg is from a0 to a3
        if fmt_num > 3:
            fmt_num = fmt_num - format_function_offset_dict[func_name] - 1
        for num in range(0, fmt_num):
            if arg_num + num > 3:
                break
            format_and_value.append(getArg(call_addr, arg_num + num))
        ret_list.append(format_and_value)
    ret_list.append(local_buf_size)
    return ret_list

# ============================================================
# Enhanced Detection Functions
# ============================================================

def getCallingFunction(addr):
    """Get the function containing the given address"""
    func = idaapi.get_func(addr)
    if func:
        return func.start_ea
    return BADADDR

def traceArgSource(start_addr, regNum, depth=10):
    """
    Trace the source of an argument to detect external input
    Returns: (source_type, source_info)
        source_type: 'external_input', 'static_string', 'stack_var', 'unknown'
    """
    if depth <= 0:
        return ('unknown', None)
    
    mipsmov = ["move", "lw", "li", "lb", "lui", "lhu", "lbu", "la"]
    arg_addr = getArgAddr(start_addr, regNum)
    
    if arg_addr == BADADDR:
        return ('unknown', None)
    
    Mnemonics = idc.print_insn_mnem(arg_addr)
    operand1 = idc.print_operand(arg_addr, 1)
    
    # Check if loading from a static string
    if Mnemonics in ["la", "lui", "li"]:
        str_addr = idc.get_name_ea_simple(operand1.split("+")[0].split("-")[0].replace("(", ""))
        if str_addr != BADADDR:
            str_content = idc.get_strlit_contents(str_addr)
            if str_content:
                if isinstance(str_content, bytes):
                    str_content = str_content.decode('utf-8', errors='replace')
                return ('static_string', {'addr': str_addr, 'value': str_content, 'len': len(str_content)})
    
    # Check if it's a stack variable
    if "sp" in operand1 or "fp" in operand1:
        return ('stack_var', {'operand': operand1})
    
    # Check if moved from another register - trace further
    if Mnemonics == "move":
        src_reg = operand1
        if src_reg.startswith("$v"):  # Return value from function call
            # Look for preceding function call
            scan_addr = idc.prev_head(arg_addr)
            scan_count = 0
            while scan_addr != BADADDR and scan_count < 20:
                mnem = idc.print_insn_mnem(scan_addr)
                if mnem in ["jal", "jalr"]:
                    # Get the called function name
                    call_target = idc.print_operand(scan_addr, 0)
                    if call_target in external_input_functions:
                        return ('external_input', {'function': call_target, 'addr': scan_addr})
                    break
                scan_count += 1
                scan_addr = idc.prev_head(scan_addr)
    
    return ('unknown', None)


def checkCommandInjection(call_addr, func_name):
    """
    Check if command execution function has external input as argument
    Returns risk assessment
    """
    results = []
    
    # For system(), popen() - check first argument (command string)
    if func_name in ["system"]:
        source_type, source_info = traceArgSource(call_addr, 0, depth=15)
        if source_type == 'external_input':
            results.append({
                'risk': 'HIGH',
                'issue': 'Command injection - arg from %s()' % source_info['function'],
                'detail': source_info
            })
        elif source_type == 'stack_var':
            results.append({
                'risk': 'MEDIUM', 
                'issue': 'Command from stack variable (needs manual review)',
                'detail': source_info
            })
        elif source_type == 'static_string':
            results.append({
                'risk': 'LOW',
                'issue': 'Static command string',
                'detail': source_info
            })
    
    elif func_name in ["popen"]:
        source_type, source_info = traceArgSource(call_addr, 0, depth=15)
        if source_type == 'external_input':
            results.append({
                'risk': 'HIGH',
                'issue': 'Popen injection - arg from %s()' % source_info['function'],
                'detail': source_info
            })
    
    elif func_name in ["execve", "execl", "execle", "execlp", "execv", "execvp"]:
        source_type, source_info = traceArgSource(call_addr, 0, depth=15)
        if source_type == 'external_input':
            results.append({
                'risk': 'HIGH',
                'issue': 'Exec injection - arg from %s()' % source_info['function'],
                'detail': source_info
            })
    
    return results


def checkStackOverflow(call_addr, func_name):
    """
    Check for potential stack buffer overflow
    Compares destination buffer size with source length
    """
    results = []
    local_buf_size = idc.get_func_attr(call_addr, idc.FUNCATTR_FRSIZE)
    
    if func_name in ["strcpy", "strcat"]:
        # Check source (arg1) for static string length
        source_type, source_info = traceArgSource(call_addr, 1, depth=15)
        if source_type == 'static_string' and source_info:
            src_len = source_info.get('len', 0)
            if local_buf_size != BADADDR and src_len > 0:
                if src_len > local_buf_size:
                    results.append({
                        'risk': 'HIGH',
                        'issue': 'Buffer overflow: src_len(%d) > frame_size(0x%x)' % (src_len, local_buf_size),
                        'detail': source_info
                    })
                elif src_len > local_buf_size // 2:
                    results.append({
                        'risk': 'MEDIUM',
                        'issue': 'Potential overflow: src_len(%d) close to frame_size(0x%x)' % (src_len, local_buf_size),
                        'detail': source_info
                    })
        elif source_type == 'external_input':
            results.append({
                'risk': 'HIGH',
                'issue': '%s with external input from %s()' % (func_name, source_info['function']),
                'detail': source_info
            })
    
    elif func_name in ["sprintf"]:
        # Check format string for potential overflow
        arg_addr = getArgAddr(call_addr, 1)  # format string is arg1
        fmt_info = getFormatString(arg_addr)
        if fmt_info != "get fail":
            fmt_str = fmt_info[1]
            # Check for %s without width limit
            if '%s' in fmt_str:
                results.append({
                    'risk': 'MEDIUM',
                    'issue': 'sprintf with %%s (unbounded string copy)',
                    'detail': {'format': fmt_str}
                })
    
    elif func_name in ["memcpy", "strncpy", "strncat"]:
        # Check size parameter (arg2)
        source_type, source_info = traceArgSource(call_addr, 2, depth=15)
        if source_type == 'external_input':
            results.append({
                'risk': 'HIGH',
                'issue': '%s size from external input %s()' % (func_name, source_info['function']),
                'detail': source_info
            })
    
    return results


def checkIntegerOverflow(call_addr, func_name):
    """
    Check for potential integer overflow in memory allocation
    """
    results = []
    
    if func_name in ["malloc", "calloc", "realloc", "memalign"]:
        # Check size argument
        size_arg_idx = 0 if func_name == "malloc" else 1
        if func_name == "calloc":
            # calloc(count, size) - check both arguments
            for idx in [0, 1]:
                source_type, source_info = traceArgSource(call_addr, idx, depth=15)
                if source_type == 'external_input':
                    results.append({
                        'risk': 'HIGH',
                        'issue': 'calloc arg%d from external input %s()' % (idx, source_info['function']),
                        'detail': source_info
                    })
        else:
            source_type, source_info = traceArgSource(call_addr, size_arg_idx, depth=15)
            if source_type == 'external_input':
                results.append({
                    'risk': 'HIGH',
                    'issue': '%s size from external input %s()' % (func_name, source_info['function']),
                    'detail': source_info
                })
        
        # Check for arithmetic operations on size (potential integer overflow)
        arg_addr = getArgAddr(call_addr, size_arg_idx)
        if arg_addr != BADADDR:
            # Scan backward for arithmetic operations
            scan_addr = arg_addr
            scan_count = 0
            while scan_addr != BADADDR and scan_count < 10:
                mnem = idc.print_insn_mnem(scan_addr)
                if mnem in ["mul", "mult", "sll", "add", "addu", "addi", "addiu"]:
                    results.append({
                        'risk': 'MEDIUM',
                        'issue': 'Arithmetic (%s) before %s - check for integer overflow' % (mnem, func_name),
                        'detail': {'addr': "0x%x" % scan_addr, 'instruction': idc.GetDisasm(scan_addr)}
                    })
                    break
                scan_count += 1
                scan_addr = idc.prev_head(scan_addr)
    
    return results


def auditFreeCall(func_name):
    """
    Audit free() calls for potential double-free vulnerabilities
    """
    func_addr = idc.get_name_ea_simple(func_name)
    if func_addr == BADADDR:
        return
    
    print(printFunc(func_name + " (Double-Free Analysis)"))
    
    # Group by containing function
    calls_by_func = defaultdict(list)
    
    for call_addr in idautils.CodeRefsTo(func_addr, 0):
        Mnemonics = idc.print_insn_mnem(call_addr)
        if Mnemonics[0:1] == "j" or Mnemonics[0:1] == "b":
            containing_func = getCallingFunction(call_addr)
            arg_info = getArg(call_addr, 0)  # First argument to free
            calls_by_func[containing_func].append({
                'addr': call_addr,
                'arg': arg_info
            })
    
    # Analyze each function for potential double-free
    table = PrettyTable(["function", "free_count", "addresses", "args", "risk"])
    
    for func_start, calls in calls_by_func.items():
        func_name_str = idc.get_func_name(func_start) or ("0x%x" % func_start)
        addrs = [("0x%x" % c['addr']) for c in calls]
        args = [c['arg'] for c in calls]
        
        # Risk assessment
        risk = "LOW"
        if len(calls) > 1:
            # Check if same argument pattern appears multiple times
            arg_counts = defaultdict(int)
            for arg in args:
                arg_counts[arg] += 1
            
            for arg, count in arg_counts.items():
                if count > 1 and arg != "get fail":
                    risk = "HIGH"
                    idc.set_color(calls[0]['addr'], idc.CIC_ITEM, RISK_HIGH)
                    break
            else:
                if len(calls) > 2:
                    risk = "MEDIUM"
        
        table.add_row([func_name_str, len(calls), ", ".join(addrs), ", ".join(args), risk])
    
    print(table)


def auditEnhanced(func_name):
    """
    Enhanced audit with additional vulnerability checks
    """
    global audit_results
    
    func_addr = idc.get_name_ea_simple(func_name)
    if func_addr == BADADDR:
        return False
    
    print(printFunc(func_name + " (Enhanced Analysis)"))
    
    # Determine check type based on function
    check_cmd_injection = func_name in command_execution_function
    check_overflow = func_name in dangerous_functions + attention_function
    check_int_overflow = func_name in memory_alloc_functions
    check_format_string = func_name in format_string_functions
    
    table = PrettyTable(["addr", "risk", "issue", "detail"])
    
    for call_addr in idautils.CodeRefsTo(func_addr, 0):
        Mnemonics = idc.print_insn_mnem(call_addr)
        if Mnemonics[0:1] == "j" or Mnemonics[0:1] == "b":
            findings = []
            
            if check_cmd_injection:
                findings.extend(checkCommandInjection(call_addr, func_name))
            
            if check_overflow:
                findings.extend(checkStackOverflow(call_addr, func_name))
            
            if check_int_overflow:
                findings.extend(checkIntegerOverflow(call_addr, func_name))
            
            if check_format_string:
                findings.extend(checkFormatStringVuln(call_addr, func_name))
            
            # Add findings to table and global results
            for finding in findings:
                risk = finding['risk']
                # Set color based on risk
                if risk == 'HIGH':
                    idc.set_color(call_addr, idc.CIC_ITEM, RISK_HIGH)
                elif risk == 'MEDIUM':
                    idc.set_color(call_addr, idc.CIC_ITEM, RISK_MEDIUM)
                else:
                    idc.set_color(call_addr, idc.CIC_ITEM, RISK_LOW)
                
                detail_str = str(finding.get('detail', ''))[:50]
                table.add_row(["0x%x" % call_addr, risk, finding['issue'], detail_str])
                
                # Add to global results for export
                finding['address'] = "0x%x" % call_addr
                finding['function'] = func_name
                audit_results.append(finding)
    
    if table.rowcount > 0:
        print(table)
    else:
        print("  No enhanced findings for %s" % func_name)


def collectTaintSources():
    """
    Collect all external input sources in the binary for taint analysis
    """
    global taint_sources
    taint_sources = {}
    
    print("\n[*] Collecting external input sources...")
    
    for func_name in external_input_functions:
        func_addr = idc.get_name_ea_simple(func_name)
        if func_addr == BADADDR:
            continue
        
        for call_addr in idautils.CodeRefsTo(func_addr, 0):
            Mnemonics = idc.print_insn_mnem(call_addr)
            if Mnemonics[0:1] == "j" or Mnemonics[0:1] == "b":
                taint_sources[call_addr] = func_name
    
    print("  Found %d external input call sites" % len(taint_sources))
    return taint_sources


# ============================================================
# Basic Block Analysis (Fix cross-block issues)
# ============================================================

def getBasicBlockBounds(addr):
    """Get the basic block boundaries containing the address"""
    func = idaapi.get_func(addr)
    if not func:
        return (BADADDR, BADADDR)
    
    try:
        flowchart = idaapi.FlowChart(func)
        for block in flowchart:
            if block.start_ea <= addr < block.end_ea:
                return (block.start_ea, block.end_ea)
    except:
        pass
    return (BADADDR, BADADDR)


def getArgAddrInBlock(start_addr, regNum):
    """
    Improved argument address detection within basic block boundaries
    Avoids crossing basic block boundaries which could lead to false positives
    """
    mipscondition = ["bn", "be", "bg", "bl"]
    scan_deep = 50
    count = 0
    reg = "$a" + str(regNum)
    
    # Get basic block bounds
    block_start, block_end = getBasicBlockBounds(start_addr)
    
    # try to get in the next (code references from this address)
    for next_addr in idautils.CodeRefsFrom(start_addr, 0):
        if next_addr != BADADDR and reg == idc.print_operand(next_addr, 0):
            return next_addr
    
    # try to get before (within same basic block)
    before_addr = idc.prev_head(start_addr)
    
    while before_addr != BADADDR:
        # Stop if we cross basic block boundary
        if block_start != BADADDR and before_addr < block_start:
            break
            
        if reg == idc.print_operand(before_addr, 0):
            Mnemonics = idc.print_insn_mnem(before_addr)
            if Mnemonics[0:2] in mipscondition:
                pass
            elif Mnemonics[0:1] == "j":
                pass
            else:
                return before_addr
        count = count + 1
        if count > scan_deep:
            break 
        before_addr = idc.prev_head(before_addr)
    return BADADDR


# ============================================================
# Format String Vulnerability Detection
# ============================================================

def checkFormatStringVuln(call_addr, func_name):
    """
    Enhanced format string vulnerability detection
    - Detects %n format specifier (write primitive)
    - Detects user-controlled format string
    """
    results = []
    
    if func_name not in format_function_offset_dict:
        return results
    
    fmt_arg_idx = format_function_offset_dict[func_name]
    arg_addr = getArgAddrInBlock(call_addr, fmt_arg_idx)
    
    if arg_addr == BADADDR:
        return results
    
    # Try to get the format string
    fmt_info = getFormatString(arg_addr)
    
    if fmt_info != "get fail":
        fmt_str = fmt_info[1]
        
        # Check for %n (write primitive - HIGH risk)
        if '%n' in fmt_str or '%hn' in fmt_str or '%hhn' in fmt_str or '%ln' in fmt_str:
            results.append({
                'risk': 'HIGH',
                'issue': 'Format string with %%n write primitive',
                'detail': {'format': fmt_str, 'addr': "0x%x" % fmt_info[0]},
                'type': 'format_string'
            })
        
        # Check for multiple format specifiers (potential overflow)
        fmt_count = len(re.findall(r'%[^%]', fmt_str))
        if fmt_count > 10:
            results.append({
                'risk': 'MEDIUM',
                'issue': 'Format string with many specifiers (%d)' % fmt_count,
                'detail': {'format': fmt_str[:50] + '...', 'count': fmt_count},
                'type': 'format_string'
            })
    else:
        # Format string is not static - check if user controlled
        source_type, source_info = traceArgSource(call_addr, fmt_arg_idx, depth=15)
        
        if source_type == 'external_input':
            results.append({
                'risk': 'HIGH',
                'issue': 'User-controlled format string from %s()' % source_info['function'],
                'detail': source_info,
                'type': 'format_string'
            })
        elif source_type == 'stack_var':
            results.append({
                'risk': 'MEDIUM',
                'issue': 'Format string from stack variable (needs review)',
                'detail': source_info,
                'type': 'format_string'
            })
    
    return results


# ============================================================
# Data Flow Analysis - Forward Tracking
# ============================================================

def traceDataFlowForward(start_addr, src_func, max_depth=5):
    """
    Trace where data from external input flows to
    Tracks return values from read/recv etc. to dangerous sinks
    """
    results = []
    
    if max_depth <= 0:
        return results
    
    # Get the function containing this call
    func = idaapi.get_func(start_addr)
    if not func:
        return results
    
    # For read/recv, the buffer is arg1 ($a1)
    # Track where this buffer is used
    buffer_arg_idx = 1 if src_func in ["read", "recv", "recvfrom", "fread"] else 0
    buffer_operand = getArg(start_addr, buffer_arg_idx)
    
    if buffer_operand == "get fail":
        return results
    
    # Scan forward in the function to find uses of this buffer
    current_addr = idc.next_head(start_addr)
    func_end = func.end_ea
    scan_count = 0
    max_scan = 100
    
    while current_addr < func_end and current_addr != BADADDR and scan_count < max_scan:
        mnem = idc.print_insn_mnem(current_addr)
        
        # Check if this is a function call
        if mnem in ["jal", "jalr"]:
            call_target = idc.print_operand(current_addr, 0)
            
            # Check if any dangerous function is called with our tainted buffer
            all_dangerous = dangerous_functions + command_execution_function + format_string_functions
            if call_target in all_dangerous:
                # Check if our buffer is passed as an argument
                for arg_idx in range(4):  # MIPS uses $a0-$a3
                    arg_operand = getArg(current_addr, arg_idx)
                    if buffer_operand in arg_operand or arg_operand in buffer_operand:
                        risk = 'HIGH' if call_target in command_execution_function else 'MEDIUM'
                        results.append({
                            'risk': risk,
                            'issue': 'Tainted data from %s() flows to %s()' % (src_func, call_target),
                            'detail': {
                                'source': "0x%x" % start_addr,
                                'sink': "0x%x" % current_addr,
                                'sink_func': call_target,
                                'buffer': buffer_operand
                            },
                            'type': 'data_flow'
                        })
                        break
        
        current_addr = idc.next_head(current_addr)
        scan_count += 1
    
    return results


def analyzeDataFlow():
    """
    Perform data flow analysis from external inputs to dangerous sinks
    """
    global data_flow_graph
    results = []
    
    print("\n[*] Analyzing data flow from external inputs...")
    
    for call_addr, func_name in taint_sources.items():
        if func_name in ["read", "recv", "recvfrom", "fread", "fgets", "gets"]:
            flow_results = traceDataFlowForward(call_addr, func_name)
            results.extend(flow_results)
            
            # Store in graph for visualization
            for r in flow_results:
                if 'detail' in r and 'sink' in r['detail']:
                    data_flow_graph[call_addr].append((r['detail']['sink'], r['detail']['sink_func']))
    
    print("  Found %d data flow issues" % len(results))
    return results


# ============================================================
# Wrapper Function Detection
# ============================================================

def detectWrapperFunctions():
    """
    Detect wrapper functions that call dangerous functions
    e.g., my_strcpy that internally calls strcpy
    """
    global wrapper_functions
    wrapper_functions = {}
    
    print("\n[*] Detecting wrapper functions...")
    
    all_dangerous = dangerous_functions + command_execution_function
    
    for dangerous_func in all_dangerous:
        func_addr = idc.get_name_ea_simple(dangerous_func)
        if func_addr == BADADDR:
            continue
        
        # Find all callers of this dangerous function
        for call_addr in idautils.CodeRefsTo(func_addr, 0):
            mnem = idc.print_insn_mnem(call_addr)
            if mnem[0:1] != "j" and mnem[0:1] != "b":
                continue
            
            # Get the function containing this call
            caller_func = idaapi.get_func(call_addr)
            if not caller_func:
                continue
            
            caller_name = idc.get_func_name(caller_func.start_ea)
            if not caller_name:
                continue
            
            # Heuristics for wrapper detection:
            # 1. Function name contains common wrapper patterns
            # 2. Function is small (likely just a wrapper)
            # 3. Function forwards arguments directly
            
            is_wrapper = False
            wrapper_type = None
            
            # Check name patterns
            wrapper_patterns = ['my_', 'safe_', 'wrap_', '_wrapper', '_safe', 'do_', 'internal_']
            for pattern in wrapper_patterns:
                if pattern in caller_name.lower():
                    is_wrapper = True
                    wrapper_type = 'name_match'
                    break
            
            # Check function size (small functions are likely wrappers)
            func_size = caller_func.end_ea - caller_func.start_ea
            if func_size < 100 and not is_wrapper:  # Less than ~25 instructions
                # Count how many other calls this function makes
                call_count = 0
                for addr in idautils.FuncItems(caller_func.start_ea):
                    m = idc.print_insn_mnem(addr)
                    if m in ["jal", "jalr"]:
                        call_count += 1
                
                if call_count <= 2:  # Mostly just calls the dangerous function
                    is_wrapper = True
                    wrapper_type = 'small_func'
            
            if is_wrapper:
                if caller_func.start_ea not in wrapper_functions:
                    wrapper_functions[caller_func.start_ea] = {
                        'name': caller_name,
                        'wraps': [],
                        'type': wrapper_type
                    }
                wrapper_functions[caller_func.start_ea]['wraps'].append(dangerous_func)
    
    print("  Found %d potential wrapper functions" % len(wrapper_functions))
    return wrapper_functions


def auditWrapperFunctions():
    """
    Audit detected wrapper functions
    """
    if not wrapper_functions:
        detectWrapperFunctions()
    
    if not wrapper_functions:
        print("  No wrapper functions detected")
        return
    
    print(printFunc("Wrapper Functions"))
    
    table = PrettyTable(["wrapper_name", "address", "wraps", "detection_type"])
    
    for func_addr, info in wrapper_functions.items():
        idc.set_color(func_addr, idc.CIC_FUNC, RISK_MEDIUM)
        table.add_row([
            info['name'],
            "0x%x" % func_addr,
            ", ".join(info['wraps']),
            info['type']
        ])
    
    print(table)
    
    # Also audit calls to wrapper functions
    print("\n  Calls to wrapper functions:")
    wrapper_table = PrettyTable(["wrapper", "call_addr", "caller_func"])
    
    for func_addr, info in wrapper_functions.items():
        for call_addr in idautils.CodeRefsTo(func_addr, 0):
            mnem = idc.print_insn_mnem(call_addr)
            if mnem[0:1] == "j" or mnem[0:1] == "b":
                caller_func = idc.get_func_name(call_addr)
                idc.set_color(call_addr, idc.CIC_ITEM, RISK_MEDIUM)
                wrapper_table.add_row([info['name'], "0x%x" % call_addr, caller_func or "unknown"])
    
    if wrapper_table.rowcount > 0:
        print(wrapper_table)


# ============================================================
# Result Export Functions
# ============================================================

def addFinding(finding):
    """Add a finding to the global results list"""
    global audit_results
    audit_results.append(finding)


def exportResultsJSON(filename):
    """Export audit results to JSON file"""
    try:
        output_path = os.path.join(get_output_dir(), filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(audit_results, f, indent=2, ensure_ascii=False)
        print("[*] Results exported to: %s" % output_path)
        return True
    except Exception as e:
        print("[!] Error exporting JSON: %s" % str(e))
        return False


def exportResultsCSV(filename):
    """Export audit results to CSV file"""
    try:
        output_path = os.path.join(get_output_dir(), filename)
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            if audit_results:
                writer = csv.DictWriter(f, fieldnames=['risk', 'issue', 'type', 'address', 'function', 'detail'])
                writer.writeheader()
                for result in audit_results:
                    row = {
                        'risk': result.get('risk', ''),
                        'issue': result.get('issue', ''),
                        'type': result.get('type', ''),
                        'address': result.get('address', ''),
                        'function': result.get('function', ''),
                        'detail': str(result.get('detail', ''))[:100]
                    }
                    writer.writerow(row)
        print("[*] Results exported to: %s" % output_path)
        return True
    except Exception as e:
        print("[!] Error exporting CSV: %s" % str(e))
        return False


def exportResultsHTML(filename):
    """Export audit results to HTML file"""
    try:
        output_path = os.path.join(get_output_dir(), filename)
        
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>MIPS Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .HIGH { background-color: #ffcccc; }
        .MEDIUM { background-color: #ffe6cc; }
        .LOW { background-color: #ccffcc; }
        .summary { margin: 20px 0; padding: 10px; background: #f0f0f0; }
    </style>
</head>
<body>
    <h1>MIPS Security Audit Report</h1>
    <div class="summary">
        <strong>Total Findings:</strong> %d |
        <strong>HIGH:</strong> %d |
        <strong>MEDIUM:</strong> %d |
        <strong>LOW:</strong> %d
    </div>
    <table>
        <tr>
            <th>Risk</th>
            <th>Issue</th>
            <th>Type</th>
            <th>Address</th>
            <th>Function</th>
            <th>Detail</th>
        </tr>
""" % (
            len(audit_results),
            len([r for r in audit_results if r.get('risk') == 'HIGH']),
            len([r for r in audit_results if r.get('risk') == 'MEDIUM']),
            len([r for r in audit_results if r.get('risk') == 'LOW'])
        )
        
        for result in audit_results:
            risk = result.get('risk', '')
            html_content += """        <tr class="%s">
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
        </tr>
""" % (
                risk,
                risk,
                result.get('issue', ''),
                result.get('type', ''),
                result.get('address', ''),
                result.get('function', ''),
                str(result.get('detail', ''))[:100]
            )
        
        html_content += """    </table>
</body>
</html>"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print("[*] Results exported to: %s" % output_path)
        return True
    except Exception as e:
        print("[!] Error exporting HTML: %s" % str(e))
        return False


def exportResults(base_filename="mipsAudit_results"):
    """Export results as HTML with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = "%s_%s.html" % (base_filename, timestamp)
    exportResultsHTML(filename)
    return filename

def mipsAudit():
    """Main audit function with all enhanced features"""
    global audit_results, total_functions, processed_functions
    
    # Reset global state
    audit_results = []
    
    # the word create with figlet
    start = '''
           _              _             _ _ _   
 _ __ ___ (_)_ __  ___   / \  _   _  __| (_) |_ 
| '_ ` _ \| | '_ \/ __| / _ \| | | |/ _` | | __|
| | | | | | | |_) \__ \/ ___ \ |_| | (_| | | |_ 
|_| |_| |_|_| .__/|___/_/   \_\__,_|\__,_|_|\__|
            |_|                                 
                    code by giantbranch 2018.05
                    updated for IDA 7.x+ & Python 3
                    enhanced detection v3.0  20260129
    '''
    print(start)
    
    # Load external configuration if available
    load_config()
    
    # Calculate total functions for progress display
    all_functions = (dangerous_functions + attention_function + 
                    command_execution_function + memory_alloc_functions + 
                    memory_free_functions + format_string_functions)
    total_functions = len(set(all_functions))
    processed_functions = 0
    
    # Collect taint sources first for enhanced analysis
    collectTaintSources()
    
    print("\n" + "=" * 60)
    print("  PHASE 1: Basic Function Audit")
    print("=" * 60)
    
    print("\nAuditing dangerous functions ......")
    for i, func_name in enumerate(dangerous_functions):
        audit(func_name)
        show_progress(i + 1, len(dangerous_functions), "Dangerous funcs")
        
    print("\nAuditing attention function ......")
    for i, func_name in enumerate(attention_function):
        audit(func_name)
        show_progress(i + 1, len(attention_function), "Attention funcs")

    print("\nAuditing command execution function ......")
    for i, func_name in enumerate(command_execution_function):
        audit(func_name)
        show_progress(i + 1, len(command_execution_function), "Cmd exec funcs")
    
    print("\n" + "=" * 60)
    print("  PHASE 2: Enhanced Vulnerability Detection")
    print("=" * 60)
    
    print("\n[*] Enhanced analysis: Command Injection Detection")
    for func_name in command_execution_function:
        auditEnhanced(func_name)
    
    print("\n[*] Enhanced analysis: Stack Overflow Detection")
    for func_name in dangerous_functions:
        auditEnhanced(func_name)
    
    print("\n[*] Enhanced analysis: Integer Overflow Detection")
    for func_name in memory_alloc_functions:
        auditEnhanced(func_name)
    
    print("\n[*] Enhanced analysis: Format String Vulnerability Detection")
    for func_name in format_string_functions:
        auditEnhanced(func_name)
    
    print("\n[*] Enhanced analysis: Double-Free Detection")
    for func_name in memory_free_functions:
        auditFreeCall(func_name)
    
    print("\n" + "=" * 60)
    print("  PHASE 3: Advanced Analysis")
    print("=" * 60)
    
    # Data flow analysis
    flow_results = analyzeDataFlow()
    if flow_results:
        print("\nData Flow Analysis Results:")
        table = PrettyTable(["risk", "issue", "source", "sink"])
        for r in flow_results:
            table.add_row([
                r['risk'],
                r['issue'],
                r['detail'].get('source', ''),
                r['detail'].get('sink', '')
            ])
            audit_results.append(r)
        print(table)
    
    # Wrapper function detection
    print("\n[*] Detecting and auditing wrapper functions...")
    auditWrapperFunctions()
    
    print("\n" + "=" * 60)
    print("  PHASE 4: Results Summary & Export")
    print("=" * 60)
    
    # Summary
    high_count = len([r for r in audit_results if r.get('risk') == 'HIGH'])
    medium_count = len([r for r in audit_results if r.get('risk') == 'MEDIUM'])
    low_count = len([r for r in audit_results if r.get('risk') == 'LOW'])
    
    print("\n[*] Audit Summary:")
    print("    Total findings: %d" % len(audit_results))
    print("    HIGH risk:      %d" % high_count)
    print("    MEDIUM risk:    %d" % medium_count)
    print("    LOW risk:       %d" % low_count)
    
    # Export results
    export_file = None
    if audit_results:
        print("\n[*] Exporting results...")
        export_file = exportResults()
        print("\nExported: %s" % export_file)
        
    print("\n" + "=" * 60)
    print("  Finished! Enjoy the result ~")
    print("=" * 60)
    

# Check processor architecture (may be useful in future)
# info = idaapi.get_inf_structure()
#
# if info.is_64bit():
#     bits = 64
# elif info.is_32bit():
#     bits = 32
# else:
#     bits = 16
#
# try:
#     is_be = info.is_be()
# except:
#     is_be = info.mf
# endian = "big" if is_be else "little"
#
# print('Processor: {}, {}bit, {} endian'.format(info.procName, bits, endian))
# # Result: Processor: mipsr, 32bit, big endian

mipsAudit()