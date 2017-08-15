from idc import *
from idaapi import *
from idautils import *
from math import ceil
from sys import exit
import traverse_ast
import helper


class GuardAnalyze:

    def __init__(self):
        self.taint_sources_all_instances = []       # Methods affecting the guard condition for all method and log message combinations
        self.taint_source_per_instance = []         # Methods affecting the guard condition for this method and log message combination
        self.get_architecture()
        self.fptr_arg_cnt_map = {}


    def get_architecture(self):
        info = get_inf_structure()

        if info.is_64bit():
            self.bits = 64
        elif info.is_32bit():
            self.bits = 32
        else:
            self.bits = 16


    def collect_all_taint_sources(self):
        for taint_source_instance in self.taint_source_per_instance:
            is_already_added = False
            for taint_source_all in self.taint_sources_all_instances:
                if taint_source_instance == taint_source_all:
                    is_already_added = True
                    break
            if not is_already_added:
                self.taint_sources_all_instances.append(taint_source_instance)


    def analyze_function_ptr(self, call_expr, call_expr_addr):
        if call_expr.op == cot_var:
            self.taint_source_per_instance.append(("FPTR_GUARD_0x%X" % call_expr_addr, call_expr_addr, call_expr_addr, self.log_message_xref_addr, self.log_message_addr))
            return True
        if call_expr.x is not None:
            return self.analyze_function_ptr(call_expr.x, call_expr_addr)
        if call_expr.y is not None:
            return self.analyze_function_ptr(call_expr.y, call_expr_addr)
        return False


    def analyze_if_expression(self, if_expr):
        if if_expr.op == cot_var:
            var = if_expr.v.idx
            def_var = self.use_def_map.get(var)
            if def_var is None:
                print "[INFO]: No def found for variable v%d" % var
            else:
                self.taint_source_per_instance.append(def_var + (self.log_message_xref_addr, self.log_message_addr))
            return
        if if_expr.op == cot_call:
            if self.analyze_function_ptr(if_expr, if_expr.ea):
                arg_cnt = 0
                for arg in if_expr.a:
                    arg_cnt += 1
                self.fptr_arg_cnt_map[if_expr.ea] = arg_cnt
            else:
                self.taint_source_per_instance.append((helper.get_function_name(if_expr.x.obj_ea), if_expr.x.obj_ea, if_expr.ea, self.log_message_xref_addr, self.log_message_addr))
            return
        if if_expr.x is not None:
            self.analyze_if_expression(if_expr.x)
        if if_expr.y is not None:
            self.analyze_if_expression(if_expr.y)
        return


    def analyze_if_statement(self, if_stmt):
        print "[INFO]: if guard detected at 0x%X" % if_stmt.ea
        self.analyze_if_expression(if_stmt.cif.expr)
        return


    def analyze_block_statement(self, block_stmt):
        print "[INFO]: block detected at 0x%X" % block_stmt.ea
        for node in block_stmt.cblock:
            if node.op == cit_if:
                self.analyze_if_statement(node)
                return True
        return False


    def analyze_guard_condition(self, ast_visitor):
        if ast_visitor.node_chain is None:
            print "[INFO]: No call trace found in pass %d" % self.ast_pass
            return

        for node in reversed(ast_visitor.node_chain):
            if node.op == cit_if:
                self.analyze_if_statement(node)
                break
            else:
                if node.op == cit_block:
                    is_if_found = self.analyze_block_statement(node)
                    if is_if_found:
                        break


    def map_var_to_function_arg(self, log_message_addr):
        for function in self.function_args_map:
            method_name, expr_addr = function
            arg_vars = self.function_args_map[function][0]
            for arg_var in arg_vars:
                str_addrs = self.var_str_map.get(arg_var)
                if str_addrs is not None:
                    for str_addr in str_addrs:
                        if str_addr[0] == log_message_addr:
                            return (method_name, expr_addr)


    def show_taint_source_per_instance(self):
        if len(self.taint_source_per_instance) > 0:
            print "\n------------------------\nProbable taint sources\n------------------------"
            for taint_source in self.taint_source_per_instance:
                method_name, method_address, taint_addr, log_message_xref_addr, log_message_addr = taint_source
                print "%s[0x%X]: 0x%X, 0x%X, 0x%X" % (method_name, method_address, taint_addr, log_message_xref_addr, log_message_addr)
        else:
            print "[ERROR]: No taint source found"


    def show_function_args_map(self):
        print "\n------------------------\nMethod arguments\n------------------------"
        for function in self.function_args_map:
            method_name, expr_addr = function
            args = self.function_args_map[function][0]
            if len(args) > 0:
                print "%s[0x%X]: " % (method_name, expr_addr),
                print args


    def show_var_str_map(self):
        if len(self.var_str_map) > 0:
            print "\n---------------------------\nVariable string assignments\n---------------------------"
            for var in self.var_str_map:
                print "v%d: " % var, map(lambda x: (hex(x[0]), hex(x[1])), self.var_str_map[var])


    def is_argument_register(self, register_name):
        arm_arg_regs = { 64 : ['X0', 'X1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7'],
                         32 : ['R0', 'R1', 'R2', 'R3'] }
        if register_name in arm_arg_regs[self.bits]:
            return True
        else:
            return False


    def forward_trace_to_argument_register(self, log_message_xref_addr):
        cur_addr = log_message_xref_addr
        dest_reg = GetOpnd(cur_addr, 0)
        if self.is_argument_register(dest_reg):
            return cur_addr
        else:
            last_reg = dest_reg
        for instr_cnt in xrange(10):
            cur_addr = NextHead(cur_addr)
            if 'MOV' in GetDisasm(cur_addr):
                src_reg = GetOpnd(cur_addr, 1)
                dest_reg = GetOpnd(cur_addr, 0)
                if src_reg == last_reg:
                    if self.is_argument_register(dest_reg):
                        return cur_addr
                    else:
                        last_reg = dest_reg


    def to_bytes(self, n, length, endianess = 'little'):
        h = '%x' % n
        s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
        return s if endianess == 'big' else s[::-1]


    def get_function_args_count(self, func_addr):
        arg_cnt = self.fptr_arg_cnt_map.get(func_addr)
        if arg_cnt is None:
            arg_cnt = helper.get_function_args_count(func_addr)

        return arg_cnt


    def get_non_string_args(self, func_addr):
        str_args_idx = set()
        non_str_args_idx = []
        xref_addrs = [xref_addr for xref_addr in CodeRefsTo(func_addr, 0)]
        arg_cnt = self.get_function_args_count(func_addr)

        for xref_addr in xref_addrs:
            function = get_func(xref_addr)
            if function is None:
                print "[ERROR]: No method found at 0x%X" % xref_addr
                continue

            try:
                function_ctree = decompile(function)
                ast_visitor = traverse_ast.AstVisitor(None)
                self.ast_pass = 3
                print "[INFO]: Following call at 0x%X to identify string arguments" % xref_addr
                ast_visitor.walk_ast(function_ctree.body, self.ast_pass, xref_addr, cot_call)

                if hasattr(ast_visitor, 'required_node'):
                    args = ast_visitor.required_node.a

                    for (arg_idx, arg) in enumerate(args):
                        if arg.op == cot_num:
                            arg_val = arg.n._value
                            arg_str = self.to_bytes(arg_val, 4)
                            if (arg_str.isalnum() and not ceil(arg_val.bit_length() / 8.0) == 8) or (arg_val == 0):
                                str_args_idx.add(arg_idx)

            except DecompilationFailure as hf:
                pass

        for arg_idx in xrange(arg_cnt):
            is_found = False
            for str_arg_idx in str_args_idx:
                if arg_idx == str_arg_idx:
                    is_found = True
                    break
            if not is_found:
                non_str_args_idx.append(arg_idx)

        return non_str_args_idx


    def traverse(self, func_addr, log_message_xref_addr, log_message_addr):
        self.log_message_xref_addr = log_message_xref_addr
        self.log_message_addr = log_message_addr
        print "\n" + "=" * 100 + "\n[INFO]: Analyzing method at 0x%X referencing string 0x%X at 0x%X\n" % (func_addr, log_message_addr, log_message_xref_addr)
        self.taint_source_per_instance = []
        function = get_func(func_addr)
        if function is None:
            print "[ERROR]: No method found at 0x%X" % func_addr
            return 1

        function_ctree = decompile(function)
        log_message_arg_addr = self.forward_trace_to_argument_register(log_message_xref_addr)
        ast_visitor = traverse_ast.AstVisitor(log_message_arg_addr)

        self.ast_pass = 1
        print "[INFO]: Attempting pass 1"
        ast_visitor.walk_ast(function_ctree.body)
        self.use_def_map = ast_visitor.use_def_map
        self.function_args_map = ast_visitor.function_args_map
        self.var_str_map = ast_visitor.var_str_map

        ast_visitor.show_use_def_map()
        ast_visitor.list_parents()
        self.analyze_guard_condition(ast_visitor)

        if len(self.taint_source_per_instance) == 0:
            self.ast_pass = 2
            print "[INFO]: Attempting pass 2"
            ast_visitor.walk_ast(function_ctree.body, self.ast_pass, log_message_xref_addr, cot_asg)
            self.use_def_map = ast_visitor.use_def_map

            ast_visitor.show_use_def_map()
            ast_visitor.list_parents()
            self.analyze_guard_condition(ast_visitor)

        self.fptr_arg_cnt_map.update(ast_visitor.fptr_arg_cnt_map)
        self.show_taint_source_per_instance()
        self.collect_all_taint_sources()
        self.show_function_args_map()
        self.show_var_str_map()


if __name__ == "__main__":
    guard_analyze = GuardAnalyze()

    # Huawei p8 - ondevice
    # guard_analyze.traverse(0x70032D4, 0x7003400)           # Transitive assignment to guard variable
    # guard_analyze.traverse(0x7002EB8, 0x7002EE4)
    # guard_analyze.traverse(0x7003CA8, 0x7003E44, 0x70902E8)  # Log message assigned to a variable which is passed as an argument
    # guard_analyze.traverse(0x70532EC, 0x7053498, 0x70A2AD8)
    # guard_analyze.get_non_string_args(0x7002D00)
    # guard_analyze.get_non_string_args(0x7052D68)

    # Huawei p8 - fastboot
    # guard_analyze.traverse(0x703E414, 0x703E5D0, 0x70A06B0)     # Arguments of function pointer
    # guard_analyze.traverse(0x702797C, 0x7027CC0, 0x7099458)

    # QC
    # guard_analyze.traverse(0x8F62635C, 0x8F626570)         # Function call in guard condition