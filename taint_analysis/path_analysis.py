from idc import *
from idaapi import *
from idautils import *
from re import *


class FuncInfo:
	name = ''
	addr = 0
	size = 0
	cond_stmt = 0
	loop_stmt = 0


class PathAnalyze:

	def __init__(self):
		self.all_func_info = []


	def write_function_info(self):
		with open('function_info.txt', 'w') as finfo:
			finfo.write("# method_name, method_addr, method_size, condition_stmt, loop_stmt\n\nbase_addr:\n0x%X\n\nfunctions:\n" % get_segm_start(inf_get_min_ea()))
			for func_info in self.all_func_info:
				finfo.write(func_info.name + ", " + "0x%X" % func_info.addr + ", " + str(func_info.size) + ", " + str(func_info.cond_stmt) + ", " + str(func_info.loop_stmt) + "\n")


	def count_condition_and_loop_stmt(self, func_info):
		cond_stmt = 0
		loop_stmt = 0
		cond_pattern = compile("if")
		loop_pattern = compile("for|while")

		try:
			func_decompiled = decompile(func_info.addr)
			func_body = func_decompiled.__str__()
			func_info.cond_stmt = len(cond_pattern.findall(func_body))
			func_info.loop_stmt = len(loop_pattern.findall(func_body))

		except DecompilationFailure as hf:
			pass


	def populate_function_info(self):
		functions = Functions()
		for function in functions:
			func_info = FuncInfo()
			func_info.name = get_func_name(function)
			func_info.addr = function
			func_info.size = function
			print("Analyzing %s at 0x%X" % (func_info.name, func_info.addr))
			func = get_func(function)
			func_info.size = func.size()
			self.count_condition_and_loop_stmt(func_info)
			self.all_func_info.append(func_info)


if __name__ == '__main__':
	path_analyze = PathAnalyze()
	path_analyze.populate_function_info()
	path_analyze.write_function_info()
	print("Done!")