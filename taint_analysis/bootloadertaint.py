import _coretaint
import angr
import claripy
import archinfo
import simuvex
import logging
from itertools import product, izip
from summary_functions import *
import datetime
import json
import sys

l = logging.getLogger("BootloaderTaintAnalysis")
l.setLevel("DEBUG")

arch_mapping = {
    'ARMEL': 'r',
    'AARCH64': 'x'
}


class BootloaderTaint:
    """
    Performs a pre-analysis to setup the taint analysis engine and launch the taint analysis itself.

    """
    def __init__(self, filename, arch, taint_info_file, enable_thumb=False, start_with_thumb=False, exit_on_decode_error=True):
        """
        Initialization function.

        :param filename: bootloader filename
        :param arch: architecture (ARM32 or AARCH64)
        :param taint_info_file: file containing the taint sources and sinks
        :enable_thumb: try thumb mode if some decoding errors occur
        :start_with_thumb: starts the analysis in thumb mode
        :exit_on_decode_error: terminate the analysis if some errors occur
        """

        self._filename = filename
        self._arch = arch
        try:
            self._p = angr.Project(filename, load_options={'main_opts': {'custom_arch': arch}})
        except:
            self._p = angr.Project(filename, load_options={'main_opts': {'custom_arch': arch, 'backend': 'blob'}})
        self._cfg = None
        self._core = None
        self._taint_buf = "taint_buf"
        self._bogus_return = 0x41414141
        self._taint_info_file = taint_info_file
        self._timeout = 10 * 60
        self._enable_thumb = enable_thumb
        self._start_with_thumb = start_with_thumb
        self._exit_on_decode_error = exit_on_decode_error

    def _parse_taint_info(self):
        """
        Parses the taint info file

        :return:
        """

        callers_poi = {}
        summarized_f = {}
        phase = 'base_addr'
        base_addr = 0

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
                if 'sinks_memcpy' in line:
                    phase = 'sinks'
                    continue
                if 'sinks_memwrite' in line:
                    phase = None
                    continue
                if phase == 'base_addr':
                    angr_base_addr = self._p.loader.main_bin.get_min_addr()
                    ida_base_addr = int(line.strip(), 16)
                    if angr_base_addr != ida_base_addr:
                        base_addr = ida_base_addr
                elif phase == 'sources':
                    line = line.strip('\n')
                    if not line:
                        continue
                    info = line.split(',')

                    source_addr = int(info[1], 16) - base_addr
                    func_addr = int(info[3], 16) - base_addr
                    ins_call = int(info[4], 16) - base_addr
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
                            callers_poi[func_addr]['sources'] = { (source_addr, ins_call, param)  }
                        else:
                            callers_poi[func_addr]['sources'].add( (source_addr, ins_call, param) )

                elif phase == 'sinks':
                    line = line.strip()
                    line = line.replace(' ', '')
                    info = line.split(',')
                    func_addr = int(info[1], 16) - base_addr
                    summarized_f[func_addr] = memcpy

                    id_params = line.split('[')[-1].split(']')[0].split(',')
                    for id_param in id_params:
                        if not id_param:
                            continue
                        param = arch_mapping[self._p.arch.name] + str(id_param)

                        for k in callers_poi:
                            callers_poi[k]['sinks'].add( (func_addr, param) )

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
                        angr_base_addr = self._p.loader.main_bin.get_min_addr()
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

        cartesian_prod = product(*tmp.itervalues())

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

    def run(self):
        """
        Starts the analysis
        :return:
        """
        # first phase: create a tainted buffer and initialize the taint analysis
        self._preprocess_taint_file()
        callers_and_poi, summarized_f = self._parse_taint_info()

        # initialize the core taint module
        name = self._p.filename.split('/')[-1]
        log_path = "/tmp/BootloaderTaint_" + name + "_.out"
        self._core = _coretaint._CoreTaint(self._p, interfunction_level=1, log_path=log_path, try_thumb=self._enable_thumb, exit_on_decode_error=self._exit_on_decode_error)
        self._core.start_logging()

        for caller, poi in callers_and_poi.iteritems():
            sinks_info = list(poi['sinks'])
            sources_info = list(poi['sources'])
            l.info("Caller %s" % hex(caller))
            self._core.log("\n------------- Caller %s -------------\n" %(hex(caller)))

            callsite_and_param = [(x[1], x[2]) for x in sources_info]
            l.info('Configuration: %s\n' % (str(callsite_and_param)))
            self._core.log(str(datetime.datetime.now().time()) + ': Configuration: %s\n' % (str([(hex(x[0]), x[1]) for x in callsite_and_param])))

            s = self._p.factory.blank_state(
                remove_options={
                                simuvex.o.LAZY_SOLVES
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
            self._core.run(s, sinks_info, callsite_and_param, summarized_f, force_thumb=self._start_with_thumb)
            self._core.log(str(datetime.datetime.now().time()) + ': End Configuration\n')

            self._core.log("\n------------- end %s -------------\n" % (hex(caller)))

        self._core.stop_logging()
        
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: " + sys.argv[0] + " config.file"
        sys.exit(0)

    config_file = sys.argv[1]

    with open(config_file, 'r') as fp:
        config = json.load(fp)

    filename = str(config['bootloader'])
    path = str(config['info_path'])
    enable_thumb = True if config['enable_thumb'] == 'True' else False
    start_with_thumb = True if config['start_with_thumb'] == 'True' else False
    exit_on_decode_error = True if config['exit_on_dec_error'] == 'True' else False
    arch = archinfo.arch_aarch64.ArchAArch64 if config['arch'] == "64" else archinfo.arch_arm.ArchARM
    bt = BootloaderTaint(filename, arch, path, enable_thumb=enable_thumb, start_with_thumb=start_with_thumb,
                         exit_on_decode_error=exit_on_decode_error)
    bt.run()

