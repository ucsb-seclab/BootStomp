from re import *
from idc import *
from idaapi import *
from idautils import *
import analyze_ast
import helper


class TaintSource:
    log_message_xref_addr = 0
    log_message_addr = 0
    method_name = ''
    method_addr = 0
    caller_name = ''
    caller_addr = ''
    taint_addr = 0
    taint_bb_addr = 0
    arg_cnt = 0
    non_string_args = []


class GetTaintSource:

    def __init__(self, source_or_sink = 0):
        self.source_or_sink = source_or_sink
        # A list of strings relevant to further analysis
        self.candidate_strings = []
        # A two dimensional list. i-th item is a list of caller methods
        # referencing i-th string in the list of 'candidate_strings'
        self.strings_referenced_by_methods = []
        self.taint_sources = []


    # Pretty print the list of candidate methods
    def display_methods(self):
        global methods_identified
        global functions_info

        print "\nMethods identified: %d\n" % methods_identified
        for function_index in xrange(50):
            function_info = functions_info[function_index]
            if function_info.isValid:
                print '{}. {}({}) => {}'.format(function_index + 1, function_info.name, hex(function_info.address), function_info.xrefs)


    def detect_ADRP_n_ADD_as_ADRL(self):
        strings_referenced_by_methods_filtered = []

        for all_callers in self.strings_referenced_by_methods:
            str_ref_cnt = len(all_callers)
            filtered_callers = []
            str_ref_idx = 0

            while str_ref_idx < (str_ref_cnt - 1):
                cur_caller = all_callers[str_ref_idx]
                cur_caller_opcode = GetMnem(cur_caller.call_site)
                cur_caller_opnd1 = GetOpnd(cur_caller.call_site, 0)
                nxt_caller = all_callers[str_ref_idx + 1]
                nxt_caller_opcode = GetMnem(nxt_caller.call_site)
                nxt_caller_opnd1 = GetOpnd(nxt_caller.call_site, 0)
                nxt_caller_opnd2 = GetOpnd(nxt_caller.call_site, 1)

                if cur_caller_opcode == "ADRP" and nxt_caller_opcode == "ADD" and cur_caller_opnd1 == nxt_caller_opnd1 and nxt_caller_opnd1 == nxt_caller_opnd2:
                    filtered_callers.append(nxt_caller)
                    str_ref_idx += 2
                else:
                    filtered_callers.append(cur_caller)
                    str_ref_idx += 1

            strings_referenced_by_methods_filtered.append(filtered_callers)

        return strings_referenced_by_methods_filtered


    def render_taint_source(self):
        if self.source_or_sink == 0:
            data = "base_addr:\n0x%X\n\n" % SegStart(MinEA())
            data += "# method_name, method_addr, caller_name, caller_addr, taint_addr, taint_bb_addr, arg_cnt, non_string_args_list, log_message_xref_addr, log_message_addr\n\n"
            data += "sources:\n"

            for taint_source in self.taint_sources:
                data += taint_source.method_name + ", "
                data += "0x%X" % taint_source.method_addr + ", "
                data += taint_source.caller_name + ", "
                data += "0x%X" % taint_source.caller_addr + ", "
                data += "0x%X" % taint_source.taint_addr + ", "
                data += "0x%X" % taint_source.taint_bb_addr + ", "
                data += str(taint_source.arg_cnt) + ", "
                data += str(taint_source.non_string_args) + ", "
                data += "0x%X" % taint_source.log_message_xref_addr + ", "
                data += "0x%X" % taint_source.log_message_addr
                data += "\n"
        
        else:
            data = "\n# method_name, method_addr, arg_cnt, non_string_args_list\n"
            data += "\nsinks_memwrite:\n"

            for taint_source in self.taint_sources:
                data += taint_source.method_name + ", "
                data += "0x%X" % taint_source.method_addr + ", "
                data += str(taint_source.arg_cnt) + ", "
                data += str(taint_source.non_string_args)
                data += "\n"

        return data


    # Pretty print the list of relevant strings and the methods referencing the same
    def display_strings_and_respective_caller_methods(self):
        guard_analyze = analyze_ast.GuardAnalyze()

        str_refs = self.detect_ADRP_n_ADD_as_ADRL()

        for (str_idx, candidate_string) in enumerate(self.candidate_strings):
            print("{:d} => 0x{:X}: {}".format(str_idx, candidate_string.ea, str(candidate_string).strip()))

            for caller_method in str_refs[str_idx]:
                print("      |-- {} [0x{:X}]: 0x{:X}".format(caller_method.name, caller_method.address, caller_method.call_site))
                if "instr_" not in caller_method.name:
                    guard_analyze.traverse(caller_method.address, caller_method.call_site, candidate_string.ea)

        for taint_source_per_instance in guard_analyze.taint_sources_all_instances:
            method_name, method_addr, taint_addr, log_message_xref_addr, log_message_addr = taint_source_per_instance
            taint_source = TaintSource()
            taint_source.log_message_xref_addr = log_message_xref_addr
            taint_source.log_message_addr = log_message_addr
            taint_source.method_name = method_name
            taint_source.method_addr = method_addr
            taint_source.caller_name = get_func_name(taint_addr)
            taint_source.caller_addr = get_func(taint_addr).startEA
            taint_source.taint_addr = taint_addr
            taint_source.taint_bb_addr = helper.get_basic_block(taint_addr)
            taint_source.arg_cnt = guard_analyze.get_function_args_count(method_addr)
            taint_source.non_string_args = guard_analyze.get_non_string_args(method_addr)
            self.taint_sources.append(taint_source)


    # Useful log messages are abundant in firmware. Why don't we leverage that fact?
    # We search for log messages containing any one of the keywords in each of the
    # sub-categories. In other words, our analysis discards all those messages which
    # do not contain a candidate keyword from each keyword sub-categories.
    def heuristic_search_keywords_in_log_messages(self):
        # In Qualcomm/lk, IDA auto-analysis picks up a large structure
        # as a contiguous block of string, thus throwing out our analysis
        max_log_message_length = 100

        # There must be one keyword present from each sub-category
        if self.source_or_sink == 0:
            keywords = [["mmc", "emmc", "sd",  "flash", "oeminfo", "offset", "index", "kernel", "ramdisk"],
                        ["read", "head", "header"],
                        ["error", "fail", "failed"]]
            banned_keywords = ["write", "memory", "ram"]
        else:
            keywords = [["mmc", "emmc", "sd",  "flash", "oeminfo", "offset", "index", "kernel", "ramdisk", "mbr"],
                        ["write", "head", "header"],
                        ["error", "fail", "failed"]]
            banned_keywords = ["read", "memory", "ram"]

        combined_keywords = [["can", "not"]]
        keyword_count = len(keywords)
        banned_keyword_count = len(banned_keywords)
        combined_keyword_count = len(combined_keywords)
        strings_found = [sc for sc in Strings()]
        string_count = len(strings_found)

        # Pick each of the strings identified by IDA auto-analysis
        for str_index in xrange(string_count):
            match_count = 0                                     # How many keyword sub-categories do match the string?
            log_message = str(strings_found[str_index])
            log_message = sub('[^0-9a-zA-Z]+', ' ', log_message)
            log_words = log_message.lower().split()
            log_words = filter(None, log_words)
            log_words_count = len(log_words)

            # Pick each of the keyword sub-category
            for i in xrange(keyword_count):
                # Pick each of the keyword in a sub-category
                for j in xrange(len(keywords[i])):
                    if str(keywords[i][j]) in log_words:      # Is the keyword found in the string?
                        match_count += 1
                        break

            for i in xrange(combined_keyword_count):
                group_size = len(combined_keywords[i])
                for j in xrange(log_words_count - group_size):
                    is_match = True
                    for k in xrange(group_size):
                        if str(combined_keywords[i][k]) != log_words[j + k]:
                            is_match = False
                            break
                    if is_match:
                        match_count += 1

            for i in xrange(banned_keyword_count):
                if str(banned_keywords[i]) in log_words:
                    match_count = 0
                    break

            # We consider only those strings which match one keyword from each sub-category
            # and no longer than 'max_log_message_length' charcaters
            if match_count == keyword_count and len(log_message) <= max_log_message_length:
                self.candidate_strings.append(strings_found[str_index])  # This is a string of our interest
                str_address = strings_found[str_index].ea           # The address where the string lies at
                str_refs = DataRefsTo(str_address)                  # Enumerate the data references to the string

                # Compute the set of methods those reference this string
                caller_methods = []

                # Iterate over all the data references
                for string_ref in str_refs:
                    function_info = helper.FuncInfo()                              # Initialize structure to hold function information
                    function_info.call_site = string_ref                    # The address of the instruction referencing the string
                    str_ref_by_func = get_func(function_info.call_site)     # The method containing the instruction above

                    # Check if the instruction lies in a function recognized by IDA
                    if str_ref_by_func is not None:
                        function_info.address = str_ref_by_func.startEA                       # Get the starting address of the function
                        function_info.name = get_func_name(function_info.address)             # Get the mnemonic function named by IDA
                    else:
                        function_info.name = "instr_" + str(hex(function_info.call_site))	  # Name the function in the form of "instr_<address>""

                    # Add the caller function details to the list
                    caller_methods.append(function_info)

                # Add the list of caller methods for a particular string to the list
                self.strings_referenced_by_methods.append(caller_methods)

        # Display the list of relevant strings and methods those reference the string
        self.display_strings_and_respective_caller_methods()