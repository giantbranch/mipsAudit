# -*- coding: utf-8 -*-
"""
Control Flow Graph Analysis Module

Improved analysis of control flow for better accuracy:
- Build complete CFG
- Detect loops and their bounds
- Analyze basic block dependencies
- Track conditional branches
- Detect unreachable code

Author: giantbranch
Version: 3.1
"""

import idc
import idaapi
import idautils
from collections import defaultdict, deque

BADADDR = idaapi.BADADDR


class ControlFlowAnalyzer:
    """Analyze control flow in MIPS binary"""
    
    def __init__(self):
        self.cfg = {}  # func_addr -> CFG object
        self.loops = defaultdict(list)  # func_addr -> [loop_info]
        self.dominators = {}  # func_addr -> dominator tree
        self.reachability = {}  # (addr1, addr2) -> bool
    
    def build_cfg(self, func_addr):
        """
        Build Control Flow Graph for function
        Returns: CFG as dict of blocks
        """
        try:
            func = idaapi.get_func(func_addr)
            if not func:
                return None
            
            flowchart = idaapi.FlowChart(func)
            cfg = {}
            
            for block in flowchart:
                block_info = {
                    'start': block.start_ea,
                    'end': block.end_ea,
                    'size': block.end_ea - block.start_ea,
                    'predecessors': [],
                    'successors': [],
                    'instructions': [],
                    'type': self._classify_block(block)
                }
                
                # Store instructions in block
                addr = block.start_ea
                while addr < block.end_ea and addr != BADADDR:
                    block_info['instructions'].append(addr)
                    addr = idc.next_head(addr, block.end_ea)
                
                cfg[block.start_ea] = block_info
            
            # Build edge list
            for block in flowchart:
                block_info = cfg[block.start_ea]
                
                # Get predecessors
                for pred in block.predlist:
                    block_info['predecessors'].append(pred.start_ea)
                
                # Get successors
                for succ in block.succlist:
                    block_info['successors'].append(succ.start_ea)
            
            self.cfg[func_addr] = cfg
            return cfg
        
        except Exception as e:
            print(f"[!] Error building CFG: {e}")
            return None
    
    def _classify_block(self, block):
        """
        Classify block type
        """
        if block.start_ea == block.end_ea:
            return 'empty'
        
        # Get last instruction
        last_addr = idc.prev_head(block.end_ea)
        if last_addr == BADADDR:
            return 'normal'
        
        last_mnem = idc.print_insn_mnem(last_addr)
        
        if last_mnem in ['j', 'jr']:
            return 'unconditional_jump'
        elif last_mnem in ['beq', 'bne', 'blt', 'ble', 'bgt', 'bge']:
            return 'conditional_branch'
        elif last_mnem in ['jal', 'jalr']:
            return 'call'
        else:
            return 'normal'
    
    def detect_loops(self, func_addr):
        """
        Detect loops in function
        Returns: list of loop info dicts
        """
        cfg = self.cfg.get(func_addr)
        if not cfg:
            cfg = self.build_cfg(func_addr)
        
        loops = []
        visited = set()
        
        # Find back edges (edges where target < source = loop)
        for block_addr, block_info in cfg.items():
            for succ in block_info['successors']:
                if succ < block_addr:  # Back edge
                    loop_info = {
                        'header': succ,
                        'back_edge': block_addr,
                        'blocks': self._find_loop_blocks(cfg, succ, block_addr),
                        'type': self._classify_loop(cfg, succ)
                    }
                    loops.append(loop_info)
        
        self.loops[func_addr] = loops
        return loops
    
    def _find_loop_blocks(self, cfg, header, back_edge):
        """
        Find all blocks in a loop
        """
        blocks = set()
        work_list = deque([back_edge])
        
        while work_list:
            block_addr = work_list.popleft()
            
            if block_addr in blocks:
                continue
            
            blocks.add(block_addr)
            
            if block_addr not in cfg:
                continue
            
            # Add predecessors
            for pred in cfg[block_addr]['predecessors']:
                if pred not in blocks:
                    work_list.append(pred)
        
        return sorted(list(blocks))
    
    def _classify_loop(self, cfg, header):
        """
        Classify loop type (for/while/do-while)
        """
        if header not in cfg:
            return 'unknown'
        
        block_info = cfg[header]
        last_insn_addr = block_info['instructions'][-1] if block_info['instructions'] else BADADDR
        
        if last_insn_addr == BADADDR:
            return 'unknown'
        
        last_mnem = idc.print_insn_mnem(last_insn_addr)
        
        # Simple heuristic
        if last_mnem in ['beq', 'bne', 'blt', 'ble']:
            return 'while_loop'
        
        return 'unknown'
    
    def is_reachable(self, func_addr, from_addr, to_addr):
        """
        Check if to_addr is reachable from from_addr
        """
        key = (from_addr, to_addr)
        if key in self.reachability:
            return self.reachability[key]
        
        cfg = self.cfg.get(func_addr)
        if not cfg:
            cfg = self.build_cfg(func_addr)
        
        # BFS to find path
        visited = set()
        work_list = deque([from_addr])
        
        while work_list:
            curr = work_list.popleft()
            
            if curr == to_addr:
                self.reachability[key] = True
                return True
            
            if curr in visited:
                continue
            
            visited.add(curr)
            
            # Find block containing curr
            for block_addr, block_info in cfg.items():
                if block_addr <= curr < block_info['end']:
                    # Add successors
                    for succ in block_info['successors']:
                        if succ not in visited:
                            work_list.append(succ)
                    break
        
        self.reachability[key] = False
        return False
    
    def analyze_loop_bounds(self, func_addr, loop_info):
        """
        Analyze loop bounds (count, conditions)
        Returns: bounds info
        """
        header_addr = loop_info['header']
        block_info = self.cfg[func_addr].get(header_addr)
        
        if not block_info:
            return None
        
        bounds = {
            'header': header_addr,
            'condition': None,
            'counter': None,
            'initial_value': None,
            'limit': None,
            'is_bounded': False
        }
        
        # Analyze the header block for loop condition
        for addr in block_info['instructions']:
            mnem = idc.print_insn_mnem(addr)
            disasm = idc.GetDisasm(addr)
            
            # Look for comparison
            if mnem in ['slt', 'slti', 'sle', 'blt', 'ble', 'bne', 'beq']:
                bounds['condition'] = disasm
                
                # Extract operands
                op1 = idc.print_operand(addr, 0)
                op2 = idc.print_operand(addr, 1)
                
                bounds['counter'] = op1
                
                # Try to extract limit value
                try:
                    bounds['limit'] = int(op2, 0)
                    bounds['is_bounded'] = True
                except:
                    if not op2.startswith('$'):
                        bounds['limit'] = op2
        
        return bounds
    
    def get_function_complexity(self, func_addr):
        """
        Calculate cyclomatic complexity
        """
        cfg = self.cfg.get(func_addr)
        if not cfg:
            cfg = self.build_cfg(func_addr)
        
        if not cfg:
            return 0
        
        # Cyclomatic complexity = edges - nodes + 2
        edges = 0
        nodes = len(cfg)
        
        for block_info in cfg.values():
            edges += len(block_info['successors'])
        
        complexity = edges - nodes + 2
        return max(1, complexity)
