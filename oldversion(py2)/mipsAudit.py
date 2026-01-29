# -*- coding: utf-8 -*-

# reference
# 《ida pro 权威指南》
# 《python 灰帽子》
# 《家用路由器0day漏洞挖掘》
# https://github.com/wangzery/SearchOverflow/blob/master/SearchOverflow.py

from idaapi import *
from prettytable import PrettyTable


DEBUG = True

# fgetc,fgets,fread,fprintf,
# vspritnf

# set function_name
dangerous_functions = [
    "strcpy", 
    "strcat",  
    "sprintf",
    "read", 
    "getenv"    
]

attention_function = [
    "memcpy",
    "strncpy",
    "sscanf", 
    "strncat", 
    "snprintf",
    "vprintf", 
    "printf"
]

command_execution_function = [
    "system", 
    "execve",
    "popen",
    "unlink"
]

# describe arg num of function

one_arg_function = [
    "getenv",
    "system",
    "unlink"
]

two_arg_function = [
    "strcpy", 
    "strcat",
    "popen"
]

three_arg_function = [
    "strncpy",
    "strncat", 
    "memcpy",
    "execve",
    "read"
]

format_function_offset_dict = {
    "sprintf":1,
    "sscanf":1,
    "snprintf":2,
    "vprintf":0,
    "printf":0
}

def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Aduiting " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

def getFuncAddr(func_name):
    func_addr = LocByName(func_name)
    if func_addr != BADADDR:
        print printFunc(func_name)
        # print func_name + " Addr : 0x %x" % func_addr
        return func_addr
    return False

def getFormatString(addr):
    op_num = 1
    # GetOpType Return value
    #define o_void        0  // No Operand                           ----------
    #define o_reg         1  // General Register (al, ax, es, ds...) reg
    #define o_mem         2  // Direct Memory Reference  (DATA)      addr
    #define o_phrase      3  // Memory Ref [Base Reg + Index Reg]    phrase
    #define o_displ       4  // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    #define o_imm         5  // Immediate Value                      value
    #define o_far         6  // Immediate Far Address  (CODE)        addr
    #define o_near        7  // Immediate Near Address (CODE)        addr
    #define o_idpspec0    8  // IDP specific type
    #define o_idpspec1    9  // IDP specific type
    #define o_idpspec2   10  // IDP specific type
    #define o_idpspec3   11  // IDP specific type
    #define o_idpspec4   12  // IDP specific type
    #define o_idpspec5   13  // IDP specific type
    # 如果第二个不是立即数则下一个
    if(GetOpType(addr ,op_num) != 5):
        op_num = op_num + 1
    if GetOpType(addr ,op_num) != 5:
        return "get fail"
    op_string = GetOpnd(addr, op_num).split(" ")[0].split("+")[0].split("-")[0].replace("(", "")
    string_addr = LocByName(op_string)
    if string_addr == BADADDR:
        return "get fail"
    string = str(GetString(string_addr))
    return [string_addr, string]


def getArgAddr(start_addr, regNum):
    mipscondition = ["bn", "be" , "bg", "bl"]
    scan_deep = 50
    count = 0
    reg = "$a" + str(regNum)
    # try to get in the next 
    next_addr = Rfirst(start_addr)
    if next_addr != BADADDR and  reg == GetOpnd(next_addr, 0):
        return next_addr
    # try to get before
    before_addr = RfirstB(start_addr)
    while before_addr != BADADDR:
        if reg == GetOpnd(before_addr, 0):
            Mnemonics = GetMnem(before_addr)
            if Mnemonics[0:2] in mipscondition:
                pass
            elif Mnemonics[0:1] == "j":
                pass
            else:
                return before_addr
        count = count + 1
        if count > scan_deep:
            break 
        before_addr = RfirstB(before_addr)
    return BADADDR


def getArg(start_addr, regNum):
    mipsmov = ["move", "lw", "li", "lb", "lui", "lhu", "lbu", "la"]
    arg_addr = getArgAddr(start_addr, regNum)
    if arg_addr != BADADDR:
        Mnemonics = GetMnem(arg_addr) 
        if Mnemonics[0:3] == "add":
            if GetOpnd(arg_addr, 2) == "":
                arg = GetOpnd(arg_addr, 0) + "+" + GetOpnd(arg_addr, 1)
            else:
                arg = GetOpnd(arg_addr, 1) + "+" +  GetOpnd(arg_addr, 2)
        elif Mnemonics[0:3] == "sub":
            if GetOpnd(arg_addr, 2) == "":
                arg = GetOpnd(arg_addr, 0) + "-" + GetOpnd(arg_addr, 1)
            else:
                arg = GetOpnd(arg_addr, 1) + "-" +  GetOpnd(arg_addr, 2)
        elif Mnemonics in mipsmov:
            arg = GetOpnd(arg_addr, 1) 
        else:
            arg = GetDisasm(arg_addr).split("#")[0]
        MakeComm(arg_addr, "addr: 0x%x " % start_addr  + "-------> arg" + str((int(regNum)+1)) + " : " + arg)
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
        print "The %s function didn't write in the describe arg num of function array,please add it to,such as add to `two_arg_function` arary" % func_name
        return
    # mispcall = ["jal", "jalr", "bal", "jr"]
    table_head = ["func_name", "addr"]
    for num in xrange(0,arg_num):
        table_head.append("arg"+str(num+1))
    if func_name in format_function_offset_dict:
        table_head.append("format&value[string_addr, num of '%', fmt_arg...]")
    table_head.append("local_buf_size")
    table = PrettyTable(table_head)

    # get first call
    call_addr = RfirstB(func_addr)
    while call_addr != BADADDR:
        # set color ———— green (red=0x0000ff,blue = 0xff0000)
        SetColor(call_addr, CIC_ITEM, 0x00ff00)
        # set break point
        # AddBpt(call_addr)
        # DelBpt(call_addr)

        # if you want to use condition
        # SetBptCnd(ea, 'strstr(GetString(Dword(esp+4),-1, 0), "SAEXT.DLL") != -1')
        Mnemonics = GetMnem(call_addr)
        # print "Mnemonics : %s" % Mnemonics
        # if Mnemonics in mispcall:
        if Mnemonics[0:1] == "j" or Mnemonics[0:1] == "b":
            # print func + " addr : 0x%x" % call_addr
            if func_name in format_function_offset_dict:
                info = auditFormat(call_addr, func_name, arg_num)
            else:
                info = auditAddr(call_addr, func_name, arg_num)
            table.add_row(info)
        call_addr = RnextB(func_addr, call_addr)
    print table
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
    local_buf_size = GetFunctionAttr(call_addr , FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in xrange(0,arg_num):
        ret_list.append(getArg(call_addr, num)) 
    ret_list.append(local_buf_size)
    return ret_list

def auditFormat(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = GetFunctionAttr(call_addr , FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in xrange(0,arg_num):
        ret_list.append(getArg(call_addr, num)) 
    arg_addr = getArgAddr(call_addr, format_function_offset_dict[func_name])
    string_and_addr =  getFormatString(arg_addr)
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
        for num in xrange(0,fmt_num):
            if arg_num + num > 3:
                break
            format_and_value.append(getArg(call_addr, arg_num + num))
        ret_list.append(format_and_value)
    # format_string = str(getFormatString(arg_addr)[1])

    # print " format String: " + format_string
    # ret_list.append([string_addr])
    ret_list.append(local_buf_size)
    return ret_list

def mipsAudit():
    # the word create with figlet
    start = '''
           _              _             _ _ _   
 _ __ ___ (_)_ __  ___   / \  _   _  __| (_) |_ 
| '_ ` _ \| | '_ \/ __| / _ \| | | |/ _` | | __|
| | | | | | | |_) \__ \/ ___ \ |_| | (_| | | |_ 
|_| |_| |_|_| .__/|___/_/   \_\__,_|\__,_|_|\__|
            |_|                                 
                    code by giantbranch 2018.05
    '''
    print start
    print "Auditing dangerous functions ......"
    for func_name in dangerous_functions:
        audit(func_name)
        
    print "Auditing attention function ......"
    for func_name in attention_function:
        audit(func_name)

    print "Auditing command execution function ......"
    for func_name in command_execution_function:
        audit(func_name)
        
    print "Finished! Enjoy the result ~"

# 判断架构的代码，以后或许用得上
# info = idaapi.get_inf_structure()

# if info.is_64bit():
#     bits = 64
# elif info.is_32bit():
#     bits = 32
# else:
#     bits = 16

# try:
#     is_be = info.is_be()
# except:
#     is_be = info.mf
# endian = "big" if is_be else "little"

# print 'Processor: {}, {}bit, {} endian'.format(info.procName, bits, endian)
# # Result: Processor: mipsr, 32bit, big endian

mipsAudit()