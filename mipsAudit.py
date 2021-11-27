# -*- coding: utf-8 -*-

# reference
# 《ida pro 权威指南》
# 《python 灰帽子》
# 《家用路由器0day漏洞挖掘》
# https://github.com/wangzery/SearchOverflow/blob/master/SearchOverflow.py

from idaapi import *
import idaapi
import idc
from prettytable import PrettyTable

if idaapi.IDA_SDK_VERSION > 700:
    import ida_search
    from idc import (
        print_operand
    )
    from ida_bytes import (
        get_strlit_contents
    )
else:
    from idc import (
        GetOpnd as print_operand,
        GetString
    )
    def get_strlit_contents(*args): return GetString(args[0])

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


try:
    class MipsAudit_Menu_Context(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            if ctx.form_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_WIDGET
            return idaapi.AST_DISABLE_FOR_WIDGET

    class MIPS_Searcher(MipsAudit_Menu_Context):
        def activate(self, ctx):
            self.plugin.run()
            return 1

except:
    pass


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
    if(idc.get_operand_type(addr ,op_num) != 5):
        op_num = op_num + 1
    if idc.get_operand_type(addr ,op_num) != 5:
        return "get fail"
    op_string = print_operand(addr, op_num).split(" ")[0].split("+")[0].split("-")[0].replace("(", "")
    string_addr = idc.get_name_ea_simple(op_string)
    if string_addr == BADADDR:
        return "get fail"
    string = str(get_strlit_contents(string_addr, -1, STRTYPE_TERMCHR))
    return [string_addr, string]


def getArgAddr(start_addr, regNum):
    mipscondition = ["bn", "be" , "bg", "bl"]
    scan_deep = 50
    count = 0
    reg = "$a" + str(regNum)
    # try to get in the next 
    next_addr = get_first_cref_from(start_addr)
    if next_addr != BADADDR and  reg == print_operand(next_addr, 0):
        return next_addr
    # try to get before
    before_addr = get_first_cref_to(start_addr)
    while before_addr != BADADDR:
        if reg == print_operand(before_addr, 0):
            Mnemonics = print_insn_mnem(before_addr)
            if Mnemonics[0:2] in mipscondition:
                pass
            elif Mnemonics[0:1] == "j":
                pass
            else:
                return before_addr
        count = count + 1
        if count > scan_deep:
            break 
        before_addr = get_first_cref_to(before_addr)
    return BADADDR


def getArg(start_addr, regNum):
    mipsmov = ["move", "lw", "li", "lb", "lui", "lhu", "lbu", "la"]
    arg_addr = getArgAddr(start_addr, regNum)
    if arg_addr != BADADDR:
        Mnemonics = print_insn_mnem(arg_addr) 
        if Mnemonics[0:3] == "add":
            if print_operand(arg_addr, 2) == "":
                arg = print_operand(arg_addr, 0) + "+" + print_operand(arg_addr, 1)
            else:
                arg = print_operand(arg_addr, 1) + "+" +  print_operand(arg_addr, 2)
        elif Mnemonics[0:3] == "sub":
            if print_operand(arg_addr, 2) == "":
                arg = print_operand(arg_addr, 0) + "-" + print_operand(arg_addr, 1)
            else:
                arg = print_operand(arg_addr, 1) + "-" +  print_operand(arg_addr, 2)
        elif Mnemonics in mipsmov:
            arg = print_operand(arg_addr, 1) 
        else:
            arg = GetDisasm(arg_addr).split("#")[0]
        set_cmt(arg_addr, "addr: 0x%x " % start_addr  + "-------> arg" + str((int(regNum)+1)) + " : " + arg, 0)
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
        print("The %s function didn't write in the describe arg num of function array,please add it to,such as add to `two_arg_function` arary" % func_name)
        return
    table_head = ["func_name", "addr"]
    for num in range(0,arg_num):
        table_head.append("arg"+str(num+1))
    if func_name in format_function_offset_dict:
        table_head.append("format&value[string_addr, num of '%', fmt_arg...]")
    table_head.append("local_buf_size")
    table = PrettyTable(table_head)

    # get first call
    call_addr = get_first_cref_to(func_addr)
    while call_addr != BADADDR:
        idc.set_color(call_addr, idc.CIC_ITEM, 0x00ff00)
        Mnemonics = print_insn_mnem(call_addr)
        if Mnemonics[0:1] == "j" or Mnemonics[0:1] == "b":
            if func_name in format_function_offset_dict:
                info = auditFormat(call_addr, func_name, arg_num)
            else:
                info = auditAddr(call_addr, func_name, arg_num)
            table.add_row(info)
        call_addr = get_next_cref_to(func_addr, call_addr)
    print(table)

def auditAddr(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr , idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        print("debug 236")
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in range(0,arg_num):
        ret_list.append(getArg(call_addr, num)) 
    ret_list.append(local_buf_size)
    return ret_list

def auditFormat(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr , idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        print("debug 252")
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in range(0,arg_num):
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
        for num in range(0,fmt_num):
            if arg_num + num > 3:
                break
            format_and_value.append(getArg(call_addr, arg_num + num))
        ret_list.append(format_and_value)
    ret_list.append(local_buf_size)
    return ret_list

def mipsAudit():
    # the word create with figlet
    print("Auditing dangerous functions ......")
    for func_name in dangerous_functions:
        audit(func_name)
        
    print("Auditing attention function ......")
    for func_name in attention_function:
        audit(func_name)

    print("Auditing command execution function ......")
    for func_name in command_execution_function:
        audit(func_name)
        
    print("Finished! Enjoy the result ~")

m_initialized = False

class MipsAudit_Plugin_t(idaapi.plugin_t):
    comment = "MIPS Audit plugin for IDA Pro"
    help = "todo"
    wanted_name = "mipsAudit"
    wanted_hotkey = "Ctrl-Alt-M"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global m_initialized

        # register popup menu handlers
        try:
            MIPS_Searcher.register(self, "mipsAudit")
        except:
            pass

        if m_initialized is False:
            m_initialized = True
            idaapi.register_action(idaapi.action_desc_t(
                "mipsAudit",
                "Find MIPS Audit func",
                MIPS_Searcher(),
                None,
                None,
                0))
            idaapi.attach_action_to_menu("Search", "mipsAudit", idaapi.SETMENU_APP)
            print("=" * 80)
            start = '''
                   _              _             _ _ _   
         _ __ ___ (_)_ __  ___   / \  _   _  __| (_) |_ 
        | '_ ` _ \| | '_ \/ __| / _ \| | | |/ _` | | __|
        | | | | | | | |_) \__ \/ ___ \ |_| | (_| | | |_ 
        |_| |_| |_|_| .__/|___/_/   \_\__,_|\__,_|_|\__|
                    |_|                                 
                            code by giantbranch 2018.05
                            edit by t3ls        2020.12
            '''
            print(start)
            print("=" * 80)

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        info = idaapi.get_inf_structure()
        if 'mips' in info.procName:
            mipsAudit()
        else:
            print('mipsAudit is not supported on the current arch')

def PLUGIN_ENTRY():
    return MipsAudit_Plugin_t()

if __name__ == '__main__':
    mipsAudit()