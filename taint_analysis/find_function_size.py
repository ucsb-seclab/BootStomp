import angr
import archinfo

if __name__ == "__main__":
    # boot_img = '../huawei_p8/ale_l23/fastboot.img'; func_info_file = '../Evaluation/info_files/info.functions.fastboot.angr'
    # boot_img = '../nexus_9/hboot.img'; func_info_file = '../Evaluation/info_files/info.functions.hboot.angr'
    # boot_img = '../xperia_xa/lk_trim.img'
    boot_img = '../Evaluation/LK/unpatched/lk_unpatched'; func_info_file = '../Evaluation/info_files/info.functions.lk_unpatched.angr'
    # boot_img = '/media/badnack/Documents/Code/bootloader/analysis/Evaluation/LK/latest/lk_latest'

    if 'lk_trim' in boot_img:
        arch = archinfo.arch_arm.ArchARM
    elif 'lk' in boot_img:
        arch = archinfo.arch_arm.ArchARM
    elif 'hboot' in boot_img:
        arch = archinfo.arch_arm.ArchARM
    else:
        arch = archinfo.arch_aarch64.ArchAArch64

    try:
        project = angr.Project(boot_img, load_options={'main_opts': {'arch': arch}})
    except:
        project = angr.Project(boot_img, load_options={'main_opts': {'arch': arch, 'backend': 'blob'}})

    function_size_map = {}
    cfg = project.analyses.CFG()
    entry_points = cfg.functions
    for entry_point in entry_points:
        function = cfg.functions.get(entry_point)
        basic_blocks = function.blocks
        basic_block_sizes = [basic_block.size for basic_block in basic_blocks]
        function_size_map[entry_point] = sum(basic_block_sizes)

    with open(func_info_file, 'w') as fp:
        for addr, size in list(function_size_map.items()):
            fp.write(("0x%X" % addr) + ', ' + str(size) + '\n')
