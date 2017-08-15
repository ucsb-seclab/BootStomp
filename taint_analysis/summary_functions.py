import _coretaint
import angr
import claripy


def source_dummy(_core, old_path, new_path):
    pass


def memcpy(_core, old_path, new_path):
    # FIXME do taint untaint!
    cp_new_p = new_path.copy()
    try:
        # if the second parameter is tainted (or pointing to a tainted location)
        # or the third is tainted, we taint the first too
        if _core._taint_buf in str(cp_new_p.state.regs.r1) or \
                        _core._taint_buf in str(cp_new_p.state.memory.load(cp_new_p.state.regs.r1)) or \
                        _core._taint_buf in str(cp_new_p.state.regs.r2):
            t = claripy.BVS(_core._taint_buf, _core._taint_buf_size).reversed
            new_path.state.memory.store(new_path.state.regs.r0, t)
    except:
        pass

    # FIXME: do the untaint part!

    return
