import _coretaint
import angr
import claripy
import archinfo
import logging
from itertools import product
import summary_functions import *
import bootloadertaint

l = logging.getLogger("CoverageTest")
l.setLevel("DEBUG")

arch_mapping = {
    'ARMEL': 'r',
    'AARCH64': 'x'
}


class CoverageTest:

    def __init__(self, filename, arch, taint_info_file, function_info_file, thumb=False):
        """
        Initialization function.

        :param filename: bootloader filename
        :param arch: architecture (ARM32 or AARCH64)
        :param taint_info_file: file containing the taint sources and sinks
        """

        bt = bootloadertaint.BootloaderTaint(filename, arch, taint_info_file)

        self._filename = filename
        self._arch = arch
        self._p = angr.Project(filename, load_options={'main_opts': {'arch': arch}})
        self._cfg = None
        self._core = None
        self._taint_buf = "taint_buf"
        self._bogus_return = 0x41414141
        self._taint_info_file = taint_info_file
        self._function_info_file = function_info_file
        self._info_functions = {}
        self._timeout = bt._timeout
        self._thumb = thumb
        self._blocks = set()
        self._functions_touched = set()
        self._base_addr = 0
        self._paths = 0
        self._errored_out = False

    def _parse_taint_info(self):
        """
        Parses the taint info file

        :return:
        """

        callers_poi = {}
        summarized_f = {}
        phase = 'base_addr'
        self._base_addr = 0

        with open(self._taint_info_file, 'r') as fp:
            for line in fp:

                if line.startswith('#') or len(line) <= 2:
                    continue

                if 'base_addr' in line:
                    phase = 'base_addr'
                    continue
                if 'sources' in line:
                    phase = 'sources'
                    continue
                if 'sinks' in line:
                    phase = 'sinks'
                    continue
                if phase == 'base_addr':
                    angr_base_addr = self._p.loader.main_object.min_addr
                    ida_base_addr = int(line.strip(), 16)
                    if angr_base_addr != ida_base_addr:
                        self._base_addr = ida_base_addr
                elif phase == 'sources':
                    line = line.strip('\n')
                    if not line:
                        continue

                    info = line.split(',')

                    source_addr = int(info[1], 16) - self._base_addr
                    func_addr = int(info[3], 16) - self._base_addr
                    ins_call = int(info[4], 16) - self._base_addr
                    params = line.split('[')[-1].split(']')[0].split(', ')

                    # if the function takes no parameters
                    if int(info[6]) == 0:
                        params.append('RETURN')

                    # we do not want to analyze source functions since we summarize them
                    summarized_f[source_addr] = source_dummy
                    for param in params:
                        if not param:
                            continue

                        param = arch_mapping[self._p.arch.name] + param if 'RETURN' != param else param
                        if func_addr not in callers_poi:
                            callers_poi[func_addr] = {}
                            callers_poi[func_addr]['sinks'] = set()
                            callers_poi[func_addr]['sources'] = {(source_addr, ins_call, param)}
                        else:
                            callers_poi[func_addr]['sources'].add((source_addr, ins_call, param))

                elif phase == 'sinks':
                    line = line.strip()
                    line = line.replace(' ', '')
                    info = line.split(',')
                    func_addr = int(info[1], 16) - self._base_addr
                    summarized_f[func_addr] = memcpy

                    id_params = line.split('[')[-1].split(']')[0].split(',')
                    for id_param in id_params:
                        if not id_param:
                            continue
                        param = arch_mapping[self._p.arch.name] + str(id_param)

                        for k in callers_poi:
                            callers_poi[k]['sinks'].add((func_addr, param))

        return callers_poi, summarized_f

    def _preprocess_taint_file(self):

        """
        Preprocesses the input file containing the taint info in the following way:
            * if in a function call some arguments are not considered, it means they have been recognized as strings.
             Such an info is propagated to all the other calls to the same function, by filtering out
             the same argument number.
        """

        def patch_fucking_idapython(line, base_addr):
            call_addr = line.split(', ')[4]
            try:
                bl = self._p.factory.block(int(call_addr, 16) - base_addr)
            except:
                bl = None

            # thumb mode
            if bl is None or bl.vex.jumpkind == 'Ijk_NoDecode':
                bl = self._p.factory.block(int(call_addr, 16) - base_addr, thumb=True)

            if bl.vex.jumpkind != 'Ijk_Call':
                new_addr = int(call_addr, 16) - 4
                assert self._p.factory.block(new_addr - base_addr).vex.jumpkind == 'Ijk_Call', \
                    'workaround for fucking ida did not work'
                splits = line.split(', ')
                splits[4] = hex(new_addr)
                line = ', '.join(splits)
            return line

        lines = open(self._taint_info_file, 'r').readlines()
        start_process = False
        index = 0
        line_sources = 0
        phase = None
        base_addr = 0
        self._taint_info_file += '_post'

        with open(self._taint_info_file, 'w') as fp:
            for line in lines:
                if phase == 'base_addr':
                    try:
                        ida_base_addr = int(line.strip(), 16)
                        angr_base_addr = self._p.loader.main_object.min_addr
                        if angr_base_addr != ida_base_addr:
                            base_addr = ida_base_addr
                    except:
                        pass

                if 'base_addr' in line:
                    phase = 'base_addr'

                if 'sinks' in line:
                    start_process = False

                if start_process and len(line) > 2 and not line.startswith('#'):
                    # sometimes hex-rays simplifies some
                    # variables assignments and as a result
                    # we do not get the correct address for the call
                    # of a source of taint. If IDA's documentation
                    # were at least decent one could have fixed this problem
                    # on their side, but since it sucks big time, we have to do
                    # it here.
                    line = patch_fucking_idapython(line, base_addr)

                    caller_addr = line.split(', ')[3]
                    source_addr = line.split(', ')[1]

                    params = line.split('[')[-1].split(']')[0].split(', ')

                    for line2 in lines[line_sources:]:
                        if len(line2) <= 2:
                            continue
                        if 'sinks' in line2:
                            break

                        if line2.startswith('#') or len(line2) <= 2:
                            continue

                        curr_caller_addr = line2.split(', ')[3]
                        curr_source_addr = line2.split(', ')[1]
                        curr_params = line2.split('[')[-1].split(']')[0].split(', ')
                        if curr_caller_addr == caller_addr and curr_source_addr == source_addr \
                                and curr_params != params:
                            params = list(set(curr_params).intersection(set(params)))

                    # set the new arguments list
                    line = line.split('[')[0] + '[' + ', '.join(params) + ']\r\n'

                if 'sources:' in line:
                    start_process = True
                    line_sources = index + 1
                    phase = None

                index += 1

                if 'MEMORY_' not in line:
                    fp.write(line)

    def _get_run_conf(self, sources_info):
        """
        Return a vector containing the sequence of sources to consider
        in each run of the taint analysis

        :param sources_info: source of taint information: (caller function, source call instruction addr, argument)
        :return: a list
        """

        tmp = {}

        for s in sources_info:
            if s[1] not in tmp:
                tmp[s[1]] = []
            tmp[s[1]].append(s)

        cartesian_prod = product(*iter(tmp.values()))

        # Heuristic: filtering out the configuration which for the same source of taint
        # would taint different parameters.
        filtered = []
        for elems in cartesian_prod:
            for elem in elems:
                if any([e for e in elems if elem[0] == e[0] and elem[2] != e[2]]):
                    break
            else:
                filtered.append(elems)

        return filtered

    def _parse_info_functions(self):
        start = False

        with open(self._function_info_file, 'r') as fp:
            for line in fp:
                if 'functions' in line:
                    start = True
                    continue

                if start:
                    info = line.strip(' ').split(',')
                    self._info_functions[int(info[1], 16)] = {'size': int(info[2]), 'if': int(info[3]), 'loops': int(info[4])}

    def coverage(self, current_path, guards_info, sinks_info=(), sources_info=()):
        try:
            ret = self._core._check_if_sink_or_source(current_path, guards_info, sinks_info, sources_info)
        except Exception as e:
            self._errored_out= True
            raise e

        # save stats
        bl = self._core._get_bb(current_path.addr)
        self._blocks.add((bl.addr, bl.size))
        cp = current_path.copy()

        cp.step()

        # we are in a functions
        if (current_path.addr + self._base_addr) in list(self._info_functions.keys()):
            self._functions_touched.add(current_path.addr + self._base_addr)

        # we have a loop or an if
        if len(cp.successors) > 1:
            self._paths += 1

        return ret

    def run(self):
        """
        Starts the analysis
        :return:
        """
        self._blocks = set()
        self._functions_touched = set()
        self._base_addr = 0
        self._paths = 0

        # first phase: create a tainted buffer and initialize the taint analysis
        self._preprocess_taint_file()
        callers_and_poi, summarized_f = self._parse_taint_info()
        self._parse_info_functions()
        # initialize the core taint module
        name = self._p.filename.split('/')[-1]
        log_path = "CoverageTest_" + name + "_.out"
        self._core = _coretaint._CoreTaint(self._p, interfunction_level=1, log_path=log_path, try_thumb=self._thumb, default_log=False)
        self._core.start_logging()
        self._core._N = 0


        for caller, poi in callers_and_poi.items():
            sinks_info = list(poi['sinks'])
            sources_info = list(poi['sources'])
            l.info("Caller %s" % hex(caller))
            self._core.log("\n------------- Caller %s -------------\n" % (hex(caller)))

            for source_info_i in self._get_run_conf(sources_info):
                self._blocks = set()
                self._functions_touched = set()
                self._paths = 0
                self._errored_out = False

                callsite_and_param = [(x[1], x[2]) for x in source_info_i]
                l.info('Configuration: %s\n' % (str(callsite_and_param)))
                self._core.log('\nConfiguration: %s\n' % (str([(hex(x[0]), x[1]) for x in callsite_and_param])))

                # prepare the under-contrainted-based initial state
                s = self._p.factory.blank_state(
                    # add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC},
                    remove_options={
                        # angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.LAZY_SOLVES
                    }
                )

                # set the state
                s.ip = caller
                if self._p.arch.bits == 64:
                    s.regs.x30 = self._bogus_return
                else:
                    s.regs.lr = self._bogus_return

                # scan for tainted paths
                self._core.set_alarm(self._timeout)
                self._core.run(s, sinks_info, callsite_and_param, summarized_f, check_func=self.coverage)
                self._log_stats()
            self._core.log("\n------------- end %s -------------\n" % (hex(caller)))

        self._core.stop_logging()

    def _log_stats(self):
        total_blocks_bytes = sum([x[1] for x in self._blocks])
        timeout_triggered = self._core._timeout_triggered
        expected_paths = 0
        expected_block_bytes = 0

        try:
            for f in self._functions_touched:
                expected_block_bytes += self._info_functions[f]['size']
                expected_paths += ( self._info_functions[f]['if'] + self._info_functions[f]['loops'])

            self._core.log("\nExpected seen paths: %s\n" % str(expected_paths))
            self._core.log("Seen paths: %s\n" % str(self._paths))
            if expected_paths > 0:
                self._core.log("Perc covered paths: %s\n" % str(self._paths / float(expected_paths) * 100))
            self._core.log("Expected seen bytes: %s\n" % str(expected_block_bytes))
            self._core.log("Seen bytes: %s\n" % str(total_blocks_bytes))

            if expected_block_bytes > 0:
                self._core.log("Perc coverage: %s\n" % str(total_blocks_bytes/float(expected_block_bytes) * 100))

            self._core.log("Timeout: %s\n" % str(timeout_triggered))
            self._core.log("Probable error of decode: %s\n" % str(not timeout_triggered and not self._core._keep_run))
            self._core.log("Probable error due to unconstraint call in path: %s\n" % str(self._errored_out))

        except Exception as e:
            l.exception("'Log stuff errored out:")


if __name__ == "__main__":
    #data = [['../huawei_p8/ale_l23/fastboot.img', 'info.taint.fastboot_real', 'info.functions.fastboot']]
    #data = [['/media/badnack/Documents/Code/bootloader/analysis/nexus_9/hboot.img', 'info.taint.hboot', 'info.functions.hboot']]
    data = [['/media/badnack/Documents/Code/bootloader/analysis/xperia_xa/lk_trim.img', 'info.taint.mediatek', 'info.functions.mediatek']]
    #data = [['/media/badnack/Documents/Code/bootloader/analysis/Evaluation/LK/unpatched/lk_unpatched','info.taint.lk_unpatched', 'info.functions.lk_unpatched']]
    #data = [['/media/badnack/Documents/Code/bootloader/analysis/Evaluation/LK/latest/lk_latest', 'info.taint.lk', 'info.functions.lk']]

    for filename, path, info_functions_file in data:
        thumb = False
        if 'lk' in filename or 'mediatek' in filename:
            arch = archinfo.arch_arm.ArchARM
            thumb = True
        elif 'hboot' in filename:
            arch = archinfo.arch_arm.ArchARM
            thumb = True
        else:
            arch = archinfo.arch_aarch64.ArchAArch64

        bt = CoverageTest(filename, arch, path, info_functions_file, thumb=thumb)
        bt.run()

