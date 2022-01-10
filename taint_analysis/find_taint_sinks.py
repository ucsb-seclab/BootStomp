from idc import *
from idaapi import *
from idautils import *
import helper


class GetTaintSink:

    def __init__(self, top_xref_limit = 50, min_arg_cnt = 2, max_arg_cnt = 3, interfunction_level = 1, max_bb_size = 8, max_call_count = 3):
        self.memcpy_like_functions = []
        self.taint_sinks = []
        self.top_xref_limit = top_xref_limit
        self.min_arg_cnt = min_arg_cnt
        self.max_arg_cnt = max_arg_cnt
        self.interfunction_level = interfunction_level
        self.max_bb_size = max_bb_size
        self.max_call_count = max_call_count


    # Pretty print the list of candidate methods
    def display_methods(self, method_list = 0, max_method_index = 0):
        global functions_info

        if method_list == 0:
            print("\nPotential memcpy():\n")
            for function_index, function_info in enumerate(self.memcpy_like_functions):
                print('{}. {}({}, {}) => {}'.format(function_index + 1, function_info.name, hex(function_info.address), function_info.arg_cnt, function_info.xrefs))

        elif method_list == 1:
            print("\nSorted by Xref:\n")
            for function_index, function_info in enumerate(helper.functions_info):
                print('{}. {}({}, {}) => {}'.format(function_index + 1, function_info.name, hex(function_info.address), function_info.arg_cnt, function_info.xrefs))

        elif method_list == 2:
            print("\nSorted by Xref until %d:\n" % max_method_index)
            for function_index in range(max_method_index):
                function_info = helper.functions_info[function_index]
                print('{}. {}({}, {}) => {}, {}, {}'.format(function_index + 1, function_info.name, hex(function_info.address), function_info.arg_cnt, function_info.xrefs, function_info.isPotentialMemcpy, function_info.isMemcpy))

        elif method_list == 3:
            print("\nPotential memcpy()\n")
            for function_index, function_info in enumerate(helper.functions_info):
                if function_info.isPotentialMemcpy:
                    print('{}. {}({}, {}) => {}'.format(function_index + 1, function_info.name, hex(function_info.address), function_info.arg_cnt, function_info.xrefs))
        else:
            print("\nmemcpy()\n")
            for function_index, function_info in enumerate(helper.functions_info):
                if function_info.isMemcpy:
                    print('{}. {}({}, {}) => {}'.format(function_index + 1, function_info.name, hex(function_info.address), function_info.arg_cnt, function_info.xrefs))


    def render_taint_sink(self):
        data = "\n# method_name, method_addr, arg_cnt, non_string_args_list\n"
        data += "\nsinks_memcpy:\n"
        
        for taint_sink in self.taint_sinks:
            data += taint_sink.name + ", "
            data += "0x%X" % taint_sink.address + ", "
            data += str(taint_sink.arg_cnt) + ", "
            data += "[" + ','.join(map(str, range(taint_sink.arg_cnt))) + "]"
            data += "\n"

        return data


    def mark_potential_memcpy(self, max_method_index = 0):
        global functions_info

        for function_index in range(max_method_index):
            function_info = helper.functions_info[function_index]
            function_info.arg_cnt = helper.get_function_args_count(function_info.address)
            if function_info.arg_cnt >= self.min_arg_cnt and function_info.arg_cnt <= self.max_arg_cnt:
                function_info.isPotentialMemcpy = True


    def mark_memcpy(self, max_method_index = 0):
        global functions_info

        for function_index in range(max_method_index):
            function_info = helper.functions_info[function_index]
            if function_info.isPotentialMemcpy:
                function_info.isMemcpy = self.is_memcpy_function(function_info.address)


    def list_potential_memcpy(self):
        global functions_info

        for function_index in range(self.top_xref_limit):
            function_info = helper.functions_info[function_index]
            function_info.arg_cnt = helper.get_function_args_count(function_info.address)
            if function_info.arg_cnt >= self.min_arg_cnt and function_info.arg_cnt <= self.max_arg_cnt:
                self.memcpy_like_functions.append(function_info)


    def is_memcpy_block(self, basic_block, external_calls, func_start_addr, func_end_addr, interfunction_level = 0):
        bb_size = 0
        is_bb_memcpy = False
        load_mnemonics = ["LDR", "LDRH", "LDRB"]
        store_mnemonics = ["STR", "STRH", "STRB"]
        branch_mnemonics = ["B", "BL", "BX", "BLX", "BXJ", "BNE", "BGE", "BGT", "BLE", "BLT"]
        registers = ["LR"]
        memcpy_pattern = [load_mnemonics, store_mnemonics]
        opcode_type = 0
        instr_addr = basic_block.start_ea
        bb_start = get_ea_name(basic_block.start_ea)

        while instr_addr < basic_block.end_ea:
            mnemonics = print_insn_mnem(instr_addr)
            bb_size += 1

            if opcode_type < 2:
                if mnemonics in memcpy_pattern[opcode_type]:
                    opcode_type += 1

            if mnemonics in branch_mnemonics:
                branch_tgt = print_operand(instr_addr, 0)
                branch_tgt_addr = get_operand_value(instr_addr, 0)
                if branch_tgt in registers:
                    instr_addr = next_head(instr_addr, 4294967295)
                    continue

                # Intra-procedural jump
                if branch_tgt_addr >= func_start_addr and branch_tgt_addr <= func_end_addr:
                    if not is_bb_memcpy:
                        if bb_start == branch_tgt and opcode_type == 2:
                            is_bb_memcpy = True

                # Inter-procedural jump
                else:
                    if not is_bb_memcpy:
                        if branch_tgt_addr not in external_calls:
                            if self.is_memcpy_function(branch_tgt_addr, interfunction_level + 1):
                                is_bb_memcpy = True

                    if branch_tgt_addr not in external_calls:
                        external_calls.add(branch_tgt_addr)

            instr_addr = next_head(instr_addr, 4294967295)

        if is_bb_memcpy:
            if bb_size > self.max_bb_size:
                print("      |-- BB size(%d) exceeds the threshold(%d), discarding suspicious block at 0x%X" % (bb_size, self.max_bb_size, basic_block.start_ea))
                is_bb_memcpy = False
            else:
                print("      |-- Signature found in basic_block at 0x%X" % basic_block.start_ea)

        return is_bb_memcpy


    def is_memcpy_function(self, instr_addr, interfunction_level = 0):
        if interfunction_level > self.interfunction_level:
            return False

        function = get_func(instr_addr)
        if not function:
            return False

        flow_chart = FlowChart(function)
        call_count_from_function = 0
        is_func_memcpy = False
        external_calls = set()

        for block in flow_chart:
            is_bb_memcpy = self.is_memcpy_block(block, external_calls, function.start_ea, function.end_ea, interfunction_level)
            is_func_memcpy = is_func_memcpy or is_bb_memcpy

        if is_func_memcpy:
            call_count_from_function = len(external_calls)

            if call_count_from_function > self.max_call_count:
                print("      |-- Distinct call count(%d) exceeds the threshold(%d), discarding suspicious function at 0x%X" % (call_count_from_function, self.max_call_count, function.start_ea))
            else:
                print("      |-- Signature found in function at 0x%X" % function.start_ea)
                return True

        return False


    def get_sinks(self):
        helper.heuristic_sort_by_xrefs()
        self.list_potential_memcpy()

        for function_info in self.memcpy_like_functions:
            function_start_addr = function_info.address
            print('[INFO]: Looking for memcpy signture inside function %s[0x%X](%d) => %d' % (function_info.name, function_info.address, function_info.arg_cnt, function_info.xrefs))
            if self.is_memcpy_function(function_start_addr):
                self.taint_sinks.append(function_info)


if __name__ == "__main__":
    helper.populate_method_info_ida()
    get_taint_sink = GetTaintSink()
    get_taint_sink.get_sinks()
    taint_sinks = get_taint_sink.render_taint_sink()
    print(taint_sinks)

    # helper.heuristic_sort_by_xrefs()
    # get_taint_sink.mark_potential_memcpy(500)
    # get_taint_sink.mark_memcpy(500)
    # get_taint_sink.display_methods(4)

    # helper.heuristic_sort_by_xrefs()
    # get_taint_sink.display_methods(2)

    # print get_taint_sink.is_memcpy_function(0x8F61B4FC)