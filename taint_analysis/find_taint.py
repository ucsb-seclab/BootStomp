
# Is it being run inside IDA or angr?
is_ida = True
try:
    from idaapi import *
    from idautils import *
    import find_taint_sources
    idaapi.require("find_taint_sinks")
    import helper
except ImportError:
    is_ida = False
    import sys
    import angr
    import archinfo
    import ipdb
    import helper


# The 'main' guy
if is_ida:
    helper.populate_method_info_ida()
    get_taint_source = find_taint_sources.GetTaintSource()
    get_taint_source.heuristic_search_keywords_in_log_messages()

    get_taint_sink_memwrite = find_taint_sources.GetTaintSource(1)
    get_taint_sink_memwrite.heuristic_search_keywords_in_log_messages()

    get_taint_sink_memcpy = find_taint_sinks.GetTaintSink()
    get_taint_sink_memcpy.get_sinks()

    with open('taint_source_sink.txt', 'w') as taint_file:
        taint_sources = get_taint_source.render_taint_source()
        taint_sinks_memwrite = get_taint_sink_memwrite.render_taint_source()
        taint_sinks_memcpy = get_taint_sink_memcpy.render_taint_sink()
        taint_file.write(taint_sources)
        taint_file.write(taint_sinks_memwrite)
        taint_file.write(taint_sinks_memcpy)

    print "\n------------------------\nTaint sources and sinks\n------------------------"
    print taint_sources
    print taint_sinks_memwrite
    print taint_sinks_memcpy

else:
    if __name__ == "__main__":
        filename = sys.argv[1]
        opts = {'main_opts': {'custom_arch': archinfo.arch_arm.ArchARM}}
        project = angr.Project(filename, load_options=opts)
        cfg = project.analyses.CFGFast(resolve_indirect_jumps = True, show_progressbar = True)
        helper.populate_method_info_angr()