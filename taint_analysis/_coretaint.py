import angr
import claripy
import logging
import random
import capstone
import signal
import os

l = logging.getLogger("_CoreTaint")
l.setLevel("DEBUG")

class MyFileHandler(object):

    def __init__(self, filename, handlerFactory, **kw):
        kw['filename'] = filename
        self._handler = handlerFactory(**kw)

    def __getattr__(self, n):
        if hasattr(self._handler, n):
            return getattr(self._handler, n)
        raise AttributeError(n)


class TimeOutException(Exception):
    def __init__(self, message):
        super(TimeOutException, self).__init__(message)


class _CoreTaint:
    """
    Perform a symbolic-execution-based taint analysis on a given bootloader to find whether
    it exists a tainted path between a source and a sink. 
    """

    def __init__(self, p, interfunction_level=0, log_path='coretaint.out',
                 smart_call=True, follow_unsat=False, try_thumb=False,
                 default_log=True, exit_on_decode_error=True, concretization_strategy=None, force_paths=False):
        """
        Initialialization function

        :param p: angr project
        :param interfunction_level: interfunction level
        :param log_path:  path where the analysis' log is created
        :param smart_call: if True a call is followed only if at least one of its parameters is tainted
        :param follow_unsat: if true unsat successors are also considered during path exploration. In this case
                             the collected constraints up to that point will be dropped.
        :param try_thumb: try to force thumb mode if some decoding error occurred
        :param default_log: log info by default
        :param exit_on_decode_error: terminate the analysis in case of error
        :param concretization_strategy: concretization strategy callback
        :param force_paths: force a path to be followed even when some decode errors were found
        """

        self._count_var = 0
        self._back_jumps = {}
        self._N = 1
        self._keep_run = True
        self._timeout_triggered = False
        self._p = p
        self._taint_buf = "taint_buf"
        self._taint_applied = False
        self._taint_buf_size = 4096 # 1 page
        self._bogus_return = 0x41414141
        self._fully_taint_guard = []

        self._deref_taint_address = False
        self._deref_instruction = None
        self._deref_addr_expr = None
        self._deref = (None, None)
        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr

        self._interfunction_level = interfunction_level
        self._smart_call = smart_call
        self._follow_unsat = follow_unsat

        self._concretizations = {}
        self._summarized_f = {}

        self._fp = open(log_path, 'w')
        self._interesing_path = {'sink': [], 'deref': [], 'loop': []}
        self._try_thumb = try_thumb
        self._force_paths = force_paths

        self._default_log = default_log

        self._exit_on_decode_error = exit_on_decode_error
        self._concretization_strategy = self._default_concretization_strategy if concretization_strategy is None else\
            concretization_strategy

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fileh = MyFileHandler(log_path + '._log', logging.FileHandler)
        fileh.setFormatter(formatter)
        l.addHandler(fileh)

    def handler(self, signum, frame):
        """
        Timeout handler

        :param signum: signal number
        :param frame:  frame
        :return:
        """
        self._keep_run = False
        self._timeout_triggered = True

        raise TimeOutException("Timeout triggered")

    def _get_bb(self, addr):
        try:
            bl = self._p.factory.block(addr)
        except:
            bl = None

        if bl is None or bl.vex.jumpkind == 'Ijk_NoDecode':
            try:
                bl = self._p.factory.block(addr, thumb=True)
            except:
                bl = None

        return bl

    def _save_taint_flag(self):
        """
        Save the tainting related flags

        :return:
        """

        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr

    def _restore_taint_flags(self):
        """
        Restiore the tainting related flags

        :return:
        """

        self._deref = self._old_deref
        self._deref_taint_address = self._old_deref_taint_address
        self._deref_addr_expr = self._old_deref_addr_expr

    @property
    def bogus_return(self):
        return self._bogus_return

    @property
    def taint_buf(self):
        return self._taint_buf

    def _set_deref_bounds(self, ast_node):
        """
        Check an ast node and if  contains a dereferenced address, it sets
        its bounds
        :param ast_node: ast node
        :return: None
        """
        lb = self._deref[0]
        ub = self._deref[1]

        if hasattr(ast_node, 'op') and ast_node.op == 'Extract' \
                and self._taint_buf in str(ast_node.args[2]):
            m = min(ast_node.args[0], ast_node.args[1])
            lb = m if lb is None or m < lb else lb
            m = max(ast_node.args[0], ast_node.args[1])
            ub = m if ub is None or m > ub else ub
            self._deref = (lb, ub)
        elif hasattr(ast_node, 'args'):
            for a in ast_node.args:
                self._set_deref_bounds(a)
        elif self._taint_buf in str(ast_node):
            self._deref = (0, 0)

    def addr_concrete_after(self, state):
        """
        Hook for address concretization
        :param state: Program state
        """

        addr_expr = state.inspect.address_concretization_expr
        state.inspect.address_concretization_result = [self._get_target_concretization(addr_expr, state)]

        # a tainted buffer's location is used as address
        if self._taint_buf in str(addr_expr):
            self._set_deref_bounds(addr_expr)
            self._deref_taint_address = True
            self._deref_addr_expr = addr_expr
            self._deref_instruction = state.ip.args[0]

            if state.inspect.address_concretization_action == 'load':
                name = "cnt_pt_by(" + self._taint_buf + ' [' + str(self._deref[0]) + ', ' + str(self._deref[1]) + ']' + ")"
                bits = state.inspect.mem_read_length
                var = claripy.BVS(name, bits)
                state.memory.store(state.inspect.address_concretization_result[0], var)

    def _check_taint(self, state, reg, history):
        """
        Check whther a path is completely tainted
        :param state: current state
        :param reg: Register used to pass the argument to the sink call
        :return: True if reg has is still tainted before the sink's call, False otherwise
        """

        self._bounds = [None, None]

        def _find_extract_bounds(ast_node):
            if ast_node.op == 'Extract':
                a, b = ast_node.args[0], ast_node.args[1]
                if a < b:
                    return a, b
                return b, a

            for a in ast_node.args:
                if hasattr(a, 'args'):
                    a, b = _find_extract_bounds(a)
                    if self._bounds[0] is None or (a is not None and a <= self._bounds[0]):
                        self._bounds[0] = a
                    if self._bounds[1] is None or (b is not None and b >= self._bounds[1]):
                        self._bounds[1] = b
            return self._bounds[0], self._bounds[1]

        def _find_name(ast_node):
            if type(ast_node) == claripy.ast.bv.BV and \
                            ast_node.op == 'BVS':
                return ast_node.args[0]
            elif hasattr(ast_node, 'args'):
                for a in ast_node.args:
                    name = _find_name(a)
                    if name:
                        return name
            return None

        def _check_guards(tainted_var, history):
            self._bounds = [None, None]
            lb, ub = _find_extract_bounds(tainted_var)
            tainted_buff_name = _find_name(tainted_var)

            for a, g in history:
                if self._taint_buf in str(g):
                    # scan the path's guards and collect those relative to
                    # the tainted portion of memory

                    t_op = g.args[0] if self._taint_buf in str(g.args[0]) else g.args[1]
                    sec_op = g.args[1] if self._taint_buf in str(g.args[0]) else g.args[0]

                    if self._taint_buf not in str(sec_op):
                        name_op = _find_name(t_op)

                        if name_op != tainted_buff_name:
                            # we consider only the conditions relative
                            # to the tainted variable which reached the sink
                            continue

                        # the condition untaints part of the tainted buffer
                        # get the portion of untainted buffer
                        self._bounds = [None, None]
                        lb_op, ub_op = _find_extract_bounds(t_op)

                        if lb_op is None:
                            l.error("The whole buffer seem to be untainted, check me!")
                            return False

                        if lb >= lb_op:
                            lb = lb_op
                        if ub <= ub_op:
                            ub = ub_op

                        if lb >= ub:
                            return False

                    else:
                        # both operands involved in the guard are tainted
                        self._fully_taint_guard.append((a, g))
            return True

        self._fully_taint_guard = []

        if hasattr(state.regs, reg):
            ast = getattr(state.regs, reg)

            if self._taint_buf in str(ast):
                # TODO: check also below part?
                if _check_guards(ast, history):
                    return True

            # save taint flags, the following load may change them
            self._save_taint_flag()

            # the function will dereference the argument
            # resulting in a read from our tainting location
            tmp_s = state.copy()
            try:
                cnt = tmp_s.memory.load(ast, 1)
            except TimeOutException as t:
                raise t
            except:
                l.info("Unable to concretize %s" %hex(ast))
                return False

            # the load might have set some flags, let's restore them
            self._restore_taint_flags()

            if self._taint_buf in str(cnt):
                # the variable reaching the sink is tainted
                return _check_guards(cnt, history)

            return False
        raise Exception("Architecture %s has no register %s" % (self._p.arch.name, reg))

    def _save_sink_info(self, path, reg, sink_address):
        """
        Dump the info about a tainted sink into the log file
        :param path: path found to be tainted
        :param reg: register pointing to the tainted buffer
        :param sink_address: sink address
        :return:
        """

        if not self._default_log:
            return

        f = self._fp
        reg_cnt = getattr(path.state.regs, str(reg))
        mem_cnt = None
        is_addr = False
        tmp_s = path.state.copy()

        if self._taint_buf not in str(reg_cnt):
            is_addr = True
            self._save_taint_flag()
            mem_cnt = tmp_s.memory.load(reg_cnt)
            self._restore_taint_flags()

        key_path = (str(mem_cnt), str(reg_cnt), str(reg))
        if key_path in self._interesing_path['sink']:
            return

        self._interesing_path['sink'].append(key_path)

        f.write("===================== Start Info path =====================\n")
        f.write("Sink address: %s\n" % hex(sink_address))

        if is_addr:
            f.write("\nReason: sink accepts %s which points to the location of memory %s.\n" % (str(reg), reg_cnt))
            f.write("\nContent of %s: %s\n" % (str(reg_cnt), str(mem_cnt)))
        else:
            f.write("\nReason: sink accepts parameter %s which is tainted.\n" % (str(reg)))
            f.write("\nContent of %s: %s\n" % (str(reg), str(reg_cnt)))

        f.write("\n\nPath \n----------------\n")
        path = ' -> '.join([hex(a) for a in path.addr_trace])
        f.write(path + '\n\n')

        f.write("Fully tainted conditions \n----------------\n")
        if not self._fully_taint_guard:
            f.write('None\n')
        else:
            for fc in self._fully_taint_guard:
                f.write(fc[0] + ': ')
                f.write(str(fc[1]) + '\n\n')

        f.write("===================== End Info path =====================\n\n\n")

    def _save_deref_info(self, path, addr_expr):
        """
        Dump the dereference of tainted address information into the log file
        :param path: path found to be tainted
        :return:
        """
        if not self._default_log:
            return

        f = self._fp
        code_addr = path.addr

        key_path = (str(code_addr), str(addr_expr))
        if key_path in self._interesing_path['deref']:
            return

        self._interesing_path['deref'].append(key_path)

        f.write("===================== Start Info path =====================\n")
        f.write("Dereference address at: %s\n" % hex(code_addr))
        f.write("\nReason: at location %s a tainted variable is dereferenced and used as address.\n" % hex(code_addr))
        f.write("\nContent of the tainted variable: %s\n" % str(addr_expr))
        f.write("\n\nTainted Path \n----------------\n")
        path = ' -> '.join([hex(a) for a in path.addr_trace])
        f.write(path + '\n\n')
        f.write("===================== End Info path =====================\n\n\n")

    def _save_loop_info(self, path, addr, cond):
        """
        Dump the info about a tainted variable guarding a loop
        :param path: path found to be tainted
        :return:
        """

        if not self._default_log:
            return

        f = self._fp

        key_path = (str(addr), str(cond))
        if key_path in self._interesing_path['loop']:
            return

        self._interesing_path['loop'].append(key_path)

        f.write("===================== Start Info path =====================\n")
        f.write("Dangerous loop condition at address %s\n" % hex(addr))
        f.write("\nReason: a tainted variable is used in the guard of a loop condition\n")
        f.write("\nCondition: %s\n" % (cond))
        f.write("\n\nTainted Path \n----------------\n")
        path = ' -> '.join([hex(a) for a in path.addr_trace])
        f.write(path + '\n\n')
        f.write("===================== End Info path =====================\n\n\n")

    def _default_concretization_strategy(self, state, cnt):
        concs = state.se.any_n_int(cnt, 50)
        return random.choice(concs)

    def _get_target_concretization(self, var, state):
        """
        Concretization must be done carefully in order to perform
        a precise taint analysis. We concretize according the following
        strategy:
        * every symbolic leaf of an ast node is concretized to unique value, according on its name.

        In this way we obtain the following advantages:
        a = get_pts();
        b = a

        c = a + 2
        d = b + 1 + 1

        d = get_pts()

        conc(a) = conc(b)
        conc(c) = conc(d)
        conc(d) != any other concretizations

        :param var: ast node
        :param state: current state
        :return: concretization value
        """

        # chek if uncontrained
        state_cp = state.copy()
        se = state_cp.se
        leafs = [l for l in var.recursive_leaf_asts]

        if not leafs:
            conc = self._concretization_strategy(state_cp, cnt)

            if not se.solution(var, conc):
                conc = se.any_int(var)
            self._concretizations[str(var)] = conc
            return conc

        for cnt in leafs:
            # concretize all unconstrained children
            if cnt.symbolic:
                # first check whether the value is already constrained
                if str(cnt) in list(self._concretizations.keys()):
                    conc = self._concretizations[str(cnt)]
                    if state_cp.se.solution(cnt, conc):
                        state_cp.add_constraints(cnt == conc)
                        continue

                conc = self._concretization_strategy(state_cp, cnt)
                self._concretizations[str(cnt)] = conc
                state_cp.add_constraints(cnt == conc)

        val = state_cp.se.any_int(var)
        return val

    def _check_if_sink_or_source(self, current_path, guards_info, current_depth, sinks_info=(), sources_info=()):
        """
        Check if a tainted sink is present in the current block of a path
        :param current_path: current path
        :param guards_info: info about the guards in the current path
        :param sinks_info: sinks' information: ((sinks), reg)
        :param source_info: sources' information ((source), reg)
        :return: True if the sink is tainted, false otherwise
        """

        current_cp = current_path.copy()
        succ = current_cp.step()

        # get the successor state
        if not succ:
            # check if it was un unconstrained call.
            # somtimes angr fucks it up
            bl = self._get_bb(current_path.addr)
            if bl.vex.jumpkind != 'Ijk_Call':
                # Heuristic: if not a function call, we do not consider dereference
                # of tainted locations, since it is unlikely to be used as address
                return False
            suc_state = current_cp.unconstrained_successor_states[0]
            current_cp.state = suc_state
            succ = [current_cp]

        suc_state = succ[0].state

        # SOURCES:
        # look for sources:

        for source, reg_source in sources_info:
            bb = self._get_bb(current_path.addr)

            # the bb contains the call to the source
            if any([x for x in bb.vex.statements if x.tag == 'Ist_IMark' and x.addr == source]):
                #  time to taint
                if reg_source == 'RETURN':
                    addr_to_taint = self._get_sym_val(name='reg_x0_ret_', inc=False)
                else:
                    addr_to_taint = getattr(suc_state.regs, reg_source)

                # check whether is tainted first! A tainted address passed to a source
                # might overwrite sensible data.
                if self._taint_buf in str(addr_to_taint):
                    self._save_deref_info(current_path, addr_to_taint)
                t = claripy.BVS(self._taint_buf, self._taint_buf_size).reversed
                self._save_taint_flag()
                current_path.state.memory.store(addr_to_taint, t)
                self._restore_taint_flags()
                self._taint_applied = True

        # SINKS:
        # look for sinks (only if we have successors. A sink is a function!):
        succ_addr = succ[0].addr
        found = False
        for sink, reg_sink in sinks_info:
            if succ_addr == sink:
                if self._check_taint(suc_state, reg_sink, guards_info):
                    l.info("HOOOORAY:  Detected a possibly tainted path")
                    self._save_sink_info(succ[0], reg_sink, sink)
                    found = True
        if found:
            return True

        # or if a tainted address is dereferenced
        if self._deref_taint_address:
            self._deref_taint_address = False

            bl = self._get_bb(self._deref_instruction)
            if bl.vex.jumpkind == 'Ijk_Call':
                l.info("Dereferenced tainted address")
                self._save_deref_info(current_path, self._deref_addr_expr)
                # self._keep_run = False

        # eventually if we are in a loop guarded by a tainted variable
        if len(succ) > 1 and any([a for a in succ if a.addr in [t for t in current_path.addr_trace]]):
            cond_guard = [g for g in succ[0].guards][-1]
            for node in cond_guard.recursive_leaf_asts:
                if self._taint_buf in str(node):
                    self._save_loop_info(current_path, current_path.addr, cond_guard)
                    return True

        return False

    def _get_below_block_addr(self, addr):
        """
        Returns the basic blocks immediately below the current node
        :param no: CFG node
        :return: the basic block position aboce in the assembly of the current one
        """
        tmp_no = None
        tmp_addr = addr
        while not tmp_no:
            tmp_addr = tmp_addr + 4
            tmp_no = self._cfg.get_any_node(tmp_addr)
        return tmp_no.addr

    def _get_sym_val(self, name='x_', bits=None, inc=True):
        if bits is None:
            bits = self._p.arch.bits
        var = claripy.BVS(name=(name + str(self._count_var) + '_' + str(self._p.arch.bits)), size=bits, explicit_name=True)
        if inc:
            self._count_var += 1
        return var

    def _set_fake_ret_succ(self, path, state, addr, ret):
        """
        Create a fake ret successors of a given path.
        :param path: current path
        :param: state: state to set in the new succ
        :param addr: address where the fake ret block will return
        :param ret: return of the current function
        :return: angr path
        """
        new_s = state.copy()
        new_s.scratch.jumpkind = "Ijk_FakeRet"

        if self._p.arch.bits == 32:
            new_s.regs.pc = addr
            new_s.regs.lr = ret
            # set the register used for the return value to be unconstrained
            # TODO: consider also r1, r2 and r3
            new_s.regs.r0 = self._get_sym_val(name='reg_x0_ret_')
        else:
            new_s.regs.pc = addr
            new_s.regs.x30 = ret
            # set the register used for the return value to be unconstrained
            # TODO: consider also x1, x2 .. x8
            new_s.regs.x0 = self._get_sym_val(name='reg_x0_ret_')

        return angr.Path(self._p, new_s, path.copy())

    def _follow_call(self, prev_path, suc_path, current_depth):
        """
        Checks if a call should be followed or not: if any of its parameters is tainted
        and the current depth of transitive closure allows it yes, otherwise no.

        :param prev_path: previous path
        :param suc_path: successive path
        :param current_depth: current depth of transitive closure
        :return: True if call should be followed, false otherwise
        """
        # first check if function is summarized
        addr = suc_path.addr

        # check if call falls within bound binary
        if addr > self._p.loader.main_object.max_addr or addr < self._p.loader.main_object.min_addr:
            return False

        for s_addr in list(self._summarized_f.keys()):
            if addr == s_addr:
                self._summarized_f[s_addr](self, prev_path, suc_path)
                return False

        if current_depth <= 0:
            return False
        
        if not self._smart_call:
            return True
        
        if not self._taint_applied:
            return False

        bl = self._get_bb(prev_path.addr)
        puts = [s for s in bl.vex.statements if s.tag == 'Ist_Put']

        expected = 0
        index = 0
        set_regs = []

        # type of regs we are looking for
        reg_ty = 'r' if self._p.arch.bits == 32 else 'x'

        while True:
            if index >= len(puts):
                break

            p = puts[index]

            if self._p.arch.register_names[p.offset] == reg_ty + str(expected):
                set_regs.append(reg_ty + str(expected))
                expected += 1
                index = 0
                continue

            index += 1

        self._save_taint_flag()

        for r in set_regs:
            reg_cnt = getattr(suc_path.state.regs, r)
            # check if it is pointing to a tainted location
            tmp_s = suc_path.state.copy()
            try:
                mem_cnt = tmp_s.memory.load(reg_cnt, 50)  # FIXME set this N to a meaningful value
            except TimeOutException as t:
                raise t
            except:
                # state is unconstrained
                l.info("Tryed to defererence a non pointer!")
                continue

            # we might have dereferenced wrongly a tainted variable during the tests before
            if (self._taint_buf in str(reg_cnt) or self._taint_buf in str(mem_cnt)) and current_depth > 0:
                self._restore_taint_flags()
                return True

        self._restore_taint_flags()
        return False

    def _follow_back_jump(self, current_path, next_path, guards_info):
        """
        Check if a back jump (probably a loop) should be followed.

        :param current_path:  current path
        :param next_path: next path
        :param guards_info:  guards information
        :return:  true if should back jump, false otherwise
        """
        key = hash(''.join(sorted(list(set([x[0] for x in guards_info])))))
        bj = (key, next_path.addr, current_path.addr)
        if bj not in list(self._back_jumps.keys()):
            self._back_jumps[bj] = 1
        elif self._back_jumps[bj] > self._N:
            # we do not want to follow the same back jump infinite times
            return False
        else:
            self._back_jumps[bj] += 1
        return True

    def _check_sat_state(self, current_path, current_guards):
        # just try to concretize any variable
        cp_state = current_path.state.copy()
        try:
            reg = cp_state.regs.r0 if self._p.arch.bits == 32 else cp_state.regs.x0
            cp_state.se.any_int(reg)
            self.last_sat = (current_path.copy(), current_guards)
        except TimeOutException as t:
            raise t
        except Exception as e:
            return False
        return True

    def _vex_fucked_up(self, current_path, next_path):
        bl = self._get_bb(current_path.addr)
        puts = [p for p in bl.vex.statements if p.tag == 'Ist_Put']

        for p in puts:
            if self._p.arch.register_names[p.offset] in ('lr', 'x30'):
                break
        else:
            return False

        last_ins = bl.instruction_addrs[-1]
        if next_path.addr == last_ins + 4:
            l.warning(" VEX fucked up big time!")
            return True
        return False

    def _flat_explore(self, current_path, check_path_fun, guards_info, current_depth, **kwargs):
        """
        Find a tainted path between a source and a sink
        :param current_path: current path
        :param check_path_fun: function to call for every block in the path
        :param guards_info: current info about the guards in the current path
        :param kwargs: additional arguments to pass to check_path_fun
        :return: the tainted path between the source and the sink, if any
        """

        if not self._keep_run:
            l.info("Backtracking due to stop")
            return
        l.info("Analyzing block %s", hex(current_path.addr))

        if not self._check_sat_state(current_path, guards_info) and not self._timeout_triggered:
            l.error("State got messed up!")
            raise Exception("State became UNSAT")

        # check whether we reached a sink
        try:
            check_path_fun(current_path, guards_info, current_depth, **kwargs)
        except:
            l.exception("'Function check path errored out:")

        succ_sat = current_path.step()

        # try thumb
        if succ_sat and succ_sat[0].errored and self._try_thumb and not self._force_paths:
            succ_sat = current_path.step(thumb=True)

        if succ_sat and succ_sat[0].errored and self._try_thumb and not self._force_paths:
            if self._exit_on_decode_error:
                self._keep_run = False
            return

        succ_unsat = current_path.unsat_successors if self._follow_unsat else []

        if not current_path.next_run:
            l.info("Backtracking from dead path")
            return

        if not succ_sat:
            # check if it was un unconstrained call.
            # sometimes angr fucks it up
            bl = self._get_bb(current_path.addr)
            if bl.vex.jumpkind == 'Ijk_Call':
                # create a fake successors
                # which should have been created
                # before.
                # FIXME: I should use get_below_block
                # but as of now I don;t want to use CFG
                unc_state = current_path.unconstrained_successor_states[0]
                ret_addr = bl.instruction_addrs[-1] + 4
                ret_func = current_path.state.regs.lr if self._p.arch.bits == 32 else current_path.state.regs.x30
                succ_sat = [self._set_fake_ret_succ(current_path, unc_state, ret_addr, ret_func)]

        # register sat and unsat information so that later we can drop the constraints
        for s in succ_sat:
            s.sat = True
        for s in succ_unsat:
            s.sat = False

        # collect and prepare the successors to be analyzed
        succ = succ_sat + succ_unsat
        for next_path in reversed(succ):
            if not next_path.sat:
                # unsat successors, drop the constraints
                next_path.state.release_plugin('solver_engine')
                next_path.state.downsize()

            next_depth = current_depth

            # First, let's see if we can follow the calls
            if next_path.jumpkind == 'Ijk_Call' and not self._vex_fucked_up(current_path, next_path):
                if not self._follow_call(current_path, next_path, current_depth): #not current_depth:
                    # if there is not fake ret we create one
                    if not any(s.jumpkind == "Ijk_FakeRet" for s in succ):
                        state = next_path.state
                        ret_addr = state.regs.lr if self._p.arch.bits == 32 else state.regs.x30
                        ret_func = current_path.state.regs.lr if self._p.arch.bits == 32 else current_path.state.regs.x30
                        next_path = self._set_fake_ret_succ(current_path, state, ret_addr, ret_func)
                    else:
                        # the fake ret is already present, therefore we just skip
                        # the call
                        continue
                else:
                    l.info("Following function call to %s" % hex(next_path.addr))
                    next_depth = current_depth - 1

            if next_path.jumpkind == 'Ijk_Ret':
                next_depth = current_depth + 1

            # we have a back jump
            if next_path.jumpkind == 'Ijk_Boring' and next_path.addr <= current_path.addr and \
                    not self._follow_back_jump(current_path, next_path, guards_info):
                    l.info("breaking loop")
                    continue

            # the successor leads out of the function, we do not want to follow it
            if next_path.addr == self._bogus_return:
                l.info("hit a return")
                continue

            # save the info about the guards of this path
            new_guards_info = list(guards_info)
            current_guards = [g for g in next_path.guards]
            if current_guards and len(new_guards_info) < len(current_guards):
                new_guards_info.append([hex(current_path.addr), current_guards[-1]])

            # next step!
            self._flat_explore(next_path, check_path_fun, new_guards_info, next_depth, **kwargs)
            l.info("Back to block %s", hex(current_path.addr))
        l.info("Backtracking")
        
    def set_project(self, p):
        """
        Set the project
        :param p: angr project
        :return:
        """
        self._p = p

    def stop_run(self):
        """
        Stop the taint analysis
        :return:
        """
        self._keep_run = False

    def flat_explore(self, state, check_path_fun, guards_info, force_thumb=False, **kwargs):
        self._keep_run = True
        initial_path = self._p.factory.path(state)
        current_depth = self._interfunction_level

        if force_thumb:
            #set thumb mode
            initial_path = initial_path.step(thumb=True)[0]
        self._flat_explore(initial_path, check_path_fun, guards_info, current_depth, **kwargs)

    def start_logging(self):
        if not self._default_log:
            return

        self._fp.write("Log Start \n"
                       "Bootloader: " +
                       self._p.filename + '\n'
                       "=================================\n\n")

    def log(self, msg):
        self._fp.write(msg)

    def stop_logging(self):
        if self._default_log:
            l.info("Done.")
            l.info("Results in " + self._fp.name)
        self._fp.close()

    def _init_bss(self, state):
        bss = [s for s in self._p.loader.main_object.sections if s.name == '.bss']
        if not bss:
            return

        bss = bss[0]
        min_addr = bss.min_addr
        max_addr = bss.max_addr

        for a in range(min_addr, max_addr + 1):
            var = self._get_sym_val(name="bss_", bits=8)
            state.memory.store(a, var)

    def set_alarm(self, timer):
        # setup a consistent initial state
        signal.signal(signal.SIGALRM, self.handler)
        signal.alarm(timer)

    def run(self, state, sinks_info, sources_info, summarized_f={}, init_bss=True,
            check_func=None, force_thumb=False, use_smart_concretization=True):

        if use_smart_concretization:
            state.inspect.b(
                'address_concretization',
                angr.BP_AFTER,
                action=self.addr_concrete_after
            )

        self._count_var = 0
        self._back_jumps = {}
        self._keep_run = True
        self._taint_applied = False
        self._fully_taint_guard = []
        self._deref_taint_address = False
        self._deref_addr_expr = None
        self._deref = (None, None)
        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr
        self._concretizations = {}
        self._summarized_f = summarized_f
        self._timeout_triggered = False

        check_func = self._check_if_sink_or_source if check_func is None else check_func

        if init_bss:
            l.info("init .bss")
            self._init_bss(state)


        try:
            self.flat_explore(state,  check_func, [], force_thumb=force_thumb, sinks_info=sinks_info, sources_info=sources_info)
        except TimeOutException as t:
            self.log("\nTimed out...\n")
            l.debug("Timeout triggered")


