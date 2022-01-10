from sys import exit
from idc import *
from idaapi import *
from idautils import *
import helper


class AstVisitor(ctree_visitor_t):

    def __init__(self, log_message_xref_addr, ast_pass = 1):
        ctree_visitor_t.__init__(self, CV_PARENTS)
        # Holds tuples of the form <variable : method> where the
        # return value of the 'method' is assigned to the 'variable'
        self.use_def_map = {}
        self.function_args_map = {}
        self.var_str_map = {}
        self.log_message_xref_addr = log_message_xref_addr
        self.found = False
        self.node_chain = None
        self.ast_pass = ast_pass
        self.fptr_arg_cnt_map = {}
        return


    def list_parents(self):
        for parent in self.parents:
            if parent is not None:
                print("      |--- 0x%X [%d]" % (parent.ea, parent.op))


    def show_use_def_map(self):
        print("\n----------------------\nUse-def map\n----------------------")
        for variable, method_info in self.use_def_map.items():
            method_name, method_address, expr_addr = method_info
            print("%3s = %s[0x%X] at 0x%X" % ("v" + str(variable), method_name, method_address, expr_addr))
        print()


    def cast_node_type(self, node):
        if node.is_expr():
            node = node.cexpr
        else:
            node = node.cinsn

        return node


    def get_parent(self, index):
        length = self.parents.size()
        parent = self.parents[length + index]

        if parent is not None:
            parent = self.cast_node_type(parent)
        else:
            print("[ERROR]: parent is None")
            exit(1)

        return parent


    def analyze_function_ptr(self, call_expr):
        if call_expr.op == cot_var:
            return True
        if call_expr.x is not None:
            return self.analyze_function_ptr(call_expr.x)
        if call_expr.y is not None:
            return self.analyze_function_ptr(call_expr.y)
        return False


    def track_variable_assignment(self, expr_assignment):
        expr_lhs = expr_assignment.x
        expr_rhs = expr_assignment.y
        expr_addr = expr_assignment.ea

        if expr_lhs.v is not None:
            var_lhs_idx = expr_lhs.v.idx

            if expr_rhs.op == cot_call:
                if self.analyze_function_ptr(expr_rhs):
                    method_name = "FPTR_VAR_0x%X" % expr_rhs.ea
                    method_address = expr_rhs.ea
                    arg_cnt = 0
                    for arg in expr_rhs.a:
                        arg_cnt += 1
                    self.fptr_arg_cnt_map[expr_rhs.ea] = arg_cnt
                else:
                    method_name = helper.get_function_name(expr_rhs.x.obj_ea)
                    method_address = expr_rhs.x.obj_ea

                # For reasons beyond understanding of mortal souls, IDA AST looks like this:
                # expr_addr == expr_rhs.ea; both contain the  address of the branch instruction
                #                           if cot_call is a real function call
                # expr_addr - expr_rhs.ea == 4; expr_rhs.ea contains the address of the branch instruction
                #                           if cot_call is a call made via function pointer
                expr_addr = expr_rhs.ea

            elif expr_rhs.op == cot_var:
                var_rhs_idx = expr_rhs.v.idx
                method_info = self.use_def_map.get(var_rhs_idx)
                if method_info is None:
                    print("[INFO]: No def found for variable v%d at 0x%X" % (var_rhs_idx, expr_addr))
                    return
                else:
                    method_name, method_address, expr_addr = method_info

            elif expr_rhs.op == cot_obj:
                var_to_str = self.var_str_map.get(var_lhs_idx)
                if var_to_str is None:
                    self.var_str_map[var_lhs_idx] = [(expr_rhs.obj_ea, expr_addr)]
                else:
                    var_to_str.append((expr_rhs.obj_ea, expr_addr))
                return

            else:
                return

            self.use_def_map[var_lhs_idx] = (method_name, method_address, expr_addr)


    def copy_call_trace(self):
        self.node_chain = []
        for parent in self.parents:
            if parent is not None:
                self.node_chain.append(self.cast_node_type(parent))


    def show_call_trace(self):
        for node in self.node_chain:
            print("      |--- 0x%X [%d]" % (node.ea, node.op))
        print()


    def find_node(self, root, node_type):
        if root.op == node_type:
            return root
        elif root.x is not None:
            return self.find_node(root.x, node_type)
        elif root.y is not None:
            return self.find_node(root.y, node_type)
        else:
            return None


    def construct_node_chain(self, function_ctree_body, child_node):
        self.node_chain = []
        while child_node.ea != function_ctree_body.ea:
            parent_node = function_ctree_body.find_parent_of(child_node)
            if parent_node is not None:
                self.node_chain.append(parent_node)
                child_node = parent_node

        self.node_chain = list(reversed(self.node_chain))


    def visit_expr(self, expr):
        if self.found:
            return 0

        if self.ast_pass == 1:
            if expr.op == cot_asg:
                if expr.x.op == cot_var:
                    if expr.x.obj_ea == self.log_message_xref_addr:
                        self.found = True
                        self.list_parents()
                        self.copy_call_trace()

                self.track_variable_assignment(expr)

            if expr.op == cot_call:
                method_name = helper.get_function_name(expr.x.obj_ea)

                if expr.a.size() > 0:
                    args = expr.a
                    function_args = []

                    for arg in args:
                        var = self.find_node(arg, cot_var)
                        if var is not None:
                            function_args.append(var.v.idx)
                        if arg.ea == self.log_message_xref_addr:
                            print("\n---------------------------------------\nFound log message string as a method argument\n---------------------------------------")
                            print("[*] %s [0x%X]" % (method_name, expr.ea))
                            self.found = True
                            self.list_parents()
                            self.copy_call_trace()
                            break

                    self.function_args_map[(method_name, expr.ea)] = (function_args, expr)

        if self.ast_pass == 2:
            if expr.ea == self.node_addr and expr.op == self.node_type:
                print("\n---------------------------------------\nFound log message string as a variable assignment\n---------------------------------------")
                print("[*] v%d [0x%X]" % (expr.x.v.idx, expr.ea))
                self.found = True
                self.list_parents()
                self.copy_call_trace()

            if expr.op == cot_asg:
                if expr.x.op == cot_var:
                    self.track_variable_assignment(expr)

        if self.ast_pass == 3:
            if expr.ea == self.node_addr and expr.op == self.node_type:
                print("[INFO]: Found node at 0x%X of type %d" % (self.node_addr, self.node_type))
                self.found = True
                self.required_node = expr

        return 0


    def walk_ast(self, ctree, ast_pass = 1, node_addr = None, node_type = None):
        self.found = False
        self.ast_pass = ast_pass
        self.node_addr = node_addr
        self.node_type = node_type
        self.use_def_map = {}
        self.apply_to(ctree, None)