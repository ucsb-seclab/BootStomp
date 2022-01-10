import _coretaint
import angr
import claripy
import archinfo
import logging
from itertools import product
from summary_functions import *
import datetime
import sys
import json

l = logging.getLogger("UnlockCheckerAnalysis")
l.setLevel("DEBUG")

arch_mapping = {
    'ARMEL': 'r',
    'AARCH64': 'x'
}

l = logging.getLogger("UnlockChecker")
l.setLevel("DEBUG")


class UnlockChecker:
    """
    Scan a bootloader to find unlocking vulnerabilities. 
    An unlocking vulnerability is present when the phone's unlocking status is written and read from a phone's hard drive.
    """

    def __init__(self, filename, arch, unlock_info_file, enable_thumb=False, force_thumb=False, exit_on_decode_error=True):
        """
        Initialization function.                                                                                                   |
                                                                                                                                   |
        :param filename: bootloader filename                                                                                       |
        :param arch: architecture (ARM32 or AARCH64)                                                                               |
        :param unlock_info_file: file containing the taint sources and sinks                                                        |
        :enable_thumb: try thumb mode if some decoding errors occur                                                                |
        :force_thumb: starts the analysis in thumb mode                                                                       |
        :exit_on_decode_error: terminate the analysis if some errors occur
        """

        self._filename = filename
        self._arch = arch
        try:
            self._p = angr.Project(filename, load_options={'main_opts': {'arch': arch}})
        except:
            self._p = angr.Project(filename, load_options={'main_opts': {'arch': arch, 'backend': 'blob'}})
        self._cfg = None
        self._taint_addr = 0x440
        self._taint_buf = "taint_buf"
        self._bogus_return = 0x41414141
        self._timeout = 10 * 60
        self._core = None
        self._unlock_info_file = unlock_info_file
        self._enable_thumb = enable_thumb
        self._force_thumb = force_thumb
        self._exit_on_decode_error = exit_on_decode_error

    def _parse_unlock_info(self):
        """
        Parses the taint info file

        :return:
        """

        summarized_f = {}
        sinks = set()
        phase = 'base_addr'
        base_addr = 0

        with open(self._unlock_info_file, 'r') as fp:
            for line in fp:
                if line.startswith('#') or len(line) <= 2:
                    continue
                if 'sources' in line:
                    phase = None
                if 'base_addr' in line:
                    phase = 'base_addr'
                    continue
                if 'memwrite' in line:
                    phase = 'memwrite'
                    continue
                if 'memcpy' in line:
                    phase = 'memcpy'
                    continue

                if phase == 'base_addr':
                    angr_base_addr = self._p.loader.main_object.min_addr
                    ida_base_addr = int(line.strip(), 16)
                    if angr_base_addr != ida_base_addr:
                        base_addr = ida_base_addr

                if phase == 'memcpy':
                    line = line.strip()
                    line = line.replace(' ', '')
                    info = line.split(',')
                    func_addr = int(info[1], 16) - base_addr
                    summarized_f[func_addr] = memcpy

                if phase == 'memwrite':
                    line = line.strip()
                    line = line.replace(' ', '')
                    info = line.split(',')
                    func_addr = int(info[1], 16) - base_addr
                    id_params = line.split('[')[-1].split(']')[0].split(',')

                    for id_param in id_params:
                        if not id_param:
                            continue
                        param = arch_mapping[self._p.arch.name] + str(id_param)
                        sinks.add((func_addr, param))

        return summarized_f, sinks

    def _get_param_to_taint(self, caller):
        def check_push(caller):
            bl = self._p.factory.block(caller)
            params = []
            for ins in str(bl.capstone).split('\n'):
                if 'push' in ins:
                    index = ins.find('push')
                    regs = ins[index + 5:]
                    params += regs.split('{')[1].split('}')[0].split(', ')
                elif ('stp' in ins and 'sp' in ins):
                    index_stp = ins.find('stp')
                    index_sp = ins.find('sp')
                    regs = ins[index_stp + 4:index_sp - 1]
                    params += regs.split(', ')
                elif ('str' in ins and 'sp' in ins):
                    index_stp = ins.find('str')
                    index_sp = ins.find('sp')
                    regs = ins[index_stp + 4:index_sp - 1]
                    params += regs.split(', ')
            return params

        def is_param(current_path, guards_info, current_depth, loc_writes=[], data_sec=[], estimated_loc=set()):
            p = self._p
            bl = p.factory.block(current_path.addr)

            for s in bl.vex.statements:
                if s.tag == 'Ist_Put':
                    loc_writes.append(p.arch.register_names[s.offset])
                if s.tag == 'Ist_WrTmp':
                    # there might be a read from memory
                    # or register

                    if s.data.tag == 'Iex_Load' and s.data.constants:
                        addr = s.data.constants[0].value

                        for d in data_sec:
                            if d.min_addr <= addr <= d.max_addr:
                                estimated_loc.add(('addr', addr))
                            if d.name == '.text':
                                possible_addr = self._p.loader.memory.read_addr_at(addr)
                                for d1 in data_sec:
                                    if d1.min_addr <= possible_addr <= d1.max_addr and d1.name != '.text':
                                        estimated_loc.add(('addr', possible_addr))

                    elif s.data.tag == 'Iex_Get':
                        name = p.arch.register_names[s.data.offset]
                        if name not in loc_writes:
                            estimated_loc.add(('reg', name))

        def filter_param_regs(locs):
            tmp = set()
            for type_w, w in locs:
                if type_w != 'reg':
                    tmp.add((type_w, w))
                    continue
                try:
                    n = int(w[1:])
                except:
                    continue

                if self._p.arch.bits == 32 and 0 <= n <= 3:
                    tmp.add((type_w, w))

                if self._p.arch.bits == 64 and 0 <= n <= 7:
                    tmp.add((type_w, w))

            return list(tmp)

        loc_writes = ['sp']
        loc_writes += check_push(caller)
        estimated_loc = set()
        data_sec = [s for s in self._p.sections if s.name in ('.bss', '.data', 'data', '.text')]
        core = _coretaint._CoreTaint(self._p, interfunction_level=0, try_thumb=self._enable_thumb, force_paths=True)

        state = self._p.factory.blank_state(
            remove_options={
                angr.options.LAZY_SOLVES
            }
        )
        state.ip = caller
        if self._p.arch.bits == 64:
            state.regs.x30 = self._bogus_return
        else:
            state.regs.lr = self._bogus_return
        core.flat_explore(state, is_param, [], loc_writes=loc_writes, data_sec=data_sec, estimated_loc=estimated_loc)

        return filter_param_regs(estimated_loc)

    def _check_if_sink(self, current_path, guards_info, current_depth, sinks_info=(), sources_info=()):
        succ = current_path.copy().step()

        # get the successor state
        if not succ:
            # check if it was un unconstrained call.
            # somtimes angr fucks it up
            bl = self._p.factory.block(current_path.addr)
            if bl.vex.jumpkind != 'Ijk_Call':
                return False
            succ = current_path.copy()
            succ.step()
            suc_state = succ.unconstrained_successor_states[0]
            succ.state = suc_state
            succ = [succ]

        suc_state = succ[0].state

        # SINKS:
        # look for sinks (only if we have successors. A sink is a function!):
        current_addr = current_path.addr
        bl = self._p.factory.block(current_addr)

        for sink, reg_sink in sinks_info:
            if suc_state.ip.args[0] == sink or sink in [x.addr for x in bl.vex.statements if x.tag == 'Ist_IMark']:
                if self._core._check_taint(suc_state, reg_sink, guards_info):
                    l.info("HOOOORAY:  Detected a possibly tainted path")
                self._core._save_sink_info(succ[0], reg_sink, current_addr)#, reg_sink, cnt)
                return True

        return False

    def run(self, start_addr, sinks_info=()):

        # pre-analysis: estimate number of arguments and variable in bss
        sources = self._get_param_to_taint(start_addr)
        name = self._p.filename.split('/')[-1]
        summarized_f, sinks_info = self._parse_unlock_info()
        log_path = "UnlockChecker_" + name + "_.out"
        self._core = _coretaint._CoreTaint(self._p, interfunction_level=2, smart_call=False, follow_unsat=True,
                                           log_path=log_path, try_thumb=self._enable_thumb,
                                           exit_on_decode_error=self._exit_on_decode_error, force_paths=True)
        self._core.start_logging()

        l.info("Start address %s" % hex(start_addr))

        # prepare the under-contrainted-based initial state
        s = self._p.factory.blank_state(
            remove_options={
                angr.options.LAZY_SOLVES
            }
        )

        s.ip = start_addr
        self._core.log("Identified parameters: %s\n" %(str(sources)))
        self._core.log(str(datetime.datetime.now().time()) + ": Started\n")

        for type_s, source in sources:

            t = claripy.BVS(self._core._taint_buf, self._core._taint_buf_size).reversed

            if type_s == 'addr':
                s.memory.store(source, t)
            else:
                setattr(s.regs, source, t)

            # set the state
            if self._p.arch.bits == 64:
                s.regs.x30 = self._bogus_return
            else:
                s.regs.lr = self._bogus_return

        # scan for tainted paths
        self._core.set_alarm(self._timeout)

        self._core.run(s, sinks_info, (), summarized_f, force_thumb=self._force_thumb, check_func=self._check_if_sink,
                       init_bss=False)

        self._core.log(str(datetime.datetime.now().time()) + ": Terminated\n")
        self._core.stop_logging()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: " + sys.argv[0] + " config.file")
        sys.exit(0)

    config_file = sys.argv[1]

    with open(config_file, 'r') as fp:
        config = json.load(fp)

    filename = str(config['bootloader'])
    path = str(config['info_path'])
    enable_thumb = True if config['enable_thumb'] == 'True' else False
    start_with_thumb = True if config['start_with_thumb'] == 'True' else False
    exit_on_decode_error = True if config['exit_on_dec_error'] == 'True' else False
    addr = int(config['unlock_addr'], 16)
    arch = archinfo.arch_aarch64.ArchAArch64 if config['arch'] == "64" else archinfo.arch_arm.ArchARM
    uc = UnlockChecker(filename, arch, path, enable_thumb=enable_thumb, force_thumb=start_with_thumb,
                       exit_on_decode_error=exit_on_decode_error)
    uc.run(addr)
