import operator
from idaapi import *
from idautils import *


# Globals: risky but friendly peeps to speed up coding
# A CFG constructed by angr CFGFast analysis
cfg = ''
# Count of methods discovered by auto-analysis
methods_identified = 0
# A list of FuncInfo() structures holding information on
# functions identified by auto-analysis
functions_info = []


# The structure holding relevant information on a function
class FuncInfo:
    name = ''
    address = 0
    arg_cnt = 0
    xrefs = 0
    call_site = 0
    isValid = True
    isPotentialMemcpy = False
    isMemcpy = False


def get_function_name(method_address):
    method_name = get_func_name(method_address)
    if method_name is None:
        method_name = "MEMORY_" + hex(method_address)
    return method_name


def get_function_args_count(func_addr):
    try:
        method = decompile(func_addr)
        if method is None:
            arg_cnt = 0
        else:
            arg_cnt = len([arg for arg in method.arguments])

    except DecompilationFailure as hf:
        arg_cnt = 0

    return arg_cnt


def get_basic_block(instr_addr):
    function = get_func(instr_addr)
    if not function:
      return None

    flow_chart = FlowChart(function)

    for block in flow_chart:
      if block.start_ea <= instr_addr:
        if block.end_ea > instr_addr:
          return block.start_ea


# Populate the data structures by filling up information on methods found in the blob
def populate_method_info_angr():
    global cfg
    global methods_identified
    global functions_info

    cfg = ''
    methods_identified = 0
    functions_info = []

    # Get the addresses and count of functions identified by the angr analysis engine
    function_addrs = cfg.functions
    methods_identified = len(function_addrs)

    # Find xrefs in IDA: [hex(x.frm) for x in XrefsTo(<address>, 0)]
    for function_addr in function_addrs:
        function = cfg.functions.function(function_addr)    # Get the method instance
        first_node_of_function = cfg.get_node(function_addr)    # Get the node containing the function entry point
        calling_nodes = cfg.get_predecessors(first_node_of_function)    # Get the nodes containing a call to the function (entry point)

        # Extract relevant information on the method identified
        function_info = FuncInfo()
        function_info.name = function.name
        function_info.address = function_addr
        function_info.xrefs = len(calling_nodes)

        # Populate the list
        functions_info.append(function_info)


# Populate the data structures by filling up information on methods found in the blob
def populate_method_info_ida():
    global methods_identified
    global functions_info

    methods_identified = 0
    functions_info = []

    # Get the addresses and count of functions identified by the angr analysis engine
    function_addrs = Functions()
    methods_identified = 0

    # Find xrefs in IDA: [hex(x.frm) for x in XrefsTo(<address>, 0)]
    for function_addr in function_addrs:
        methods_identified += 1

        # Extract relevant information on the method identified
        function_info = FuncInfo()
        function_info.name = get_func_name(function_addr)
        function_info.address = function_addr
        function_info.xrefs = sum(1 for _ in CodeRefsTo(function_addr, 0))

        # Populate the list
        functions_info.append(function_info)


# The methods reading from and writing to the eMMC card are the primary sources
# of taint. It's highly likely that these methods will be invoked many more times
# over the other ones. The real bummer is when methods like __stack_chk_fail() tops
# in the list :-( To make the situation worse, a bunch of libc functions precede
# mmc_read(). Can we eliminate these by computing symbolic summaries?
def heuristic_sort_by_xrefs():
    functions_info.sort(key = operator.attrgetter('xrefs'), reverse = True)