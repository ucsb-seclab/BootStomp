BootStomp
===================

[![License](https://img.shields.io/github/license/angr/angr.svg)](https://github.com/ucsb-seclab/bootstomp/blob/master/LICENSE)

BootStomp is a boot-loader bug finder. It looks for two different class of bugs: memory corruption and state storage vulnerabilities. For more info please refer to the BootStomp paper at https://seclab.cs.ucsb.edu/academic/publishing/#bootstomp-security-bootloaders-mobile-devices-2017 

To run BootStomp's analyses, please read the following instructions. Note that BootStomp works with boot-loaders compiled for ARM architectures (32 and 64 bits both) and that results might slightly vary depending on angr and Z3's versions. This is because of the time angr takes to analyze basic blocks and to Z3's expression concretization results.


----------

Directory structure
--
* **analysis**: Contains analysis results (Ex: IDA idbs etc)  of boot images of different devices.
* **tools**: Contains tools that can be used to work with various images.

Pre-requisites
--

* angr (http://angr.io/)
>$ pip install angr

* IDA PRO (https://www.hex-rays.com/products/ida/)
* IDA Decompiler (https://www.hex-rays.com/products/decompiler/)

How to run it
--

### Automatic detection of taint sources and sinks

1. Load the boot-loader binary in IDA (we used v6.95). Depending on the CPU architecture of the phone it has been extracted from, 32 bit or 64 bit IDA is needed. 
2. From the menu-bar, run File => Script file => `find_taint.py`
3. Output will appear in the file `taint_source_sink.txt` under the same directory as the boot-loader itself.

### Configuration file
Create a JSON configuration file for the boot-loader binary (see examples in `config/`), where:

* **bootloader**: boot-loader file path
* **info_path**: boot-loader source/sink info file path  (i.e., taint_source_sink.txt )
* **arch**: architecture's number of bits (available options are 32 and 64)
* **enable_thumb**: consider thumb mode (when needed) during the analysis 
* **start_with_thumb**: starts the analysis with thumb mode enabled  
* **exit_on_dec_error**: stop the analysis if some instructions cannot be decoded
* **unlock_addr**: unlocking function address. This field is necessary only for finding insecure state storage vulnerabilities.

### Finding memory corruption vulnerabilities
Run

 > python bootloadertaint.py config-file-path
 
 Results will be stored in `/tmp/BootloaderTaint_[boot-loader].out`, where `[boot-loader]` is the name of the analyzed boot-loader. Note that paths involving loops might appear more than once.

### Finding insecure state storage vulnerability
Run
 > python unlock_checker.py config-file-path

 Results will be stored in `/tmp/UnlockChecker_[boot-loader].out`, where `[boot-loader]` is the name of the analyzed boot-loader. Note that paths involving loops might appear more than once.

### Checking results
To check BootStomp results, use the script `result_pretty_print.py`, as follows:
 > python result_pretty_print.py results_file


Other references
-------------
* [Kernel and lk source for Qualcomm MT65x2](https://github.com/ariafan/MT65x2_kernel_lk)
* [MediaTek details: Partitions and Preloader](https://sturmflut.github.io/mediatek/2015/07/04/mediatek-details-partitions-and-preloader)
* [Reverse Engineering Android's Aboot](http://newandroidbook.com/Articles/aboot.html)
* [(L)ittle (K)ernel based Android bootloader](https://www.codeaurora.org/blogs/little-kernel-based-android-bootloader)
* [Little Kernel Boot Loader Overview by Qualcomm](https://developer.qualcomm.com/qfile/28821/lm80-p0436-1_little_kernel_boot_loader_overview.pdf)
* [android: arm: bootloader: how (L)ittle (K)ernel loads boot.img](https://chengyihe.wordpress.com/2015/09/22/android-arm-bootloader-how-little-kernel-loads-boot-img)
* [BootUnlocker for Nexus Devices](https://github.com/osm0sis/boot-unlocker/blob/wiki/HowItWorks.md)
* [Verifying Boot](https://source.android.com/security/verifiedboot/verified-boot.html)
* [Freeing my tablet (Android hacking, SW and HW)](https://www.thanassis.space/android.html)
* [How to lock the samsung download mode using an undocumented feature of aboot](https://ge0n0sis.github.io/posts/2016/05/how-to-lock-the-samsung-download-mode-using-an-undocumented-feature-of-aboot/)
* [Android Security Internals - An In-Depth Guide to Android’s Security Architecture](http://files.cnblogs.com/files/jiayy/Android_Security_Intern__An_In-Depth_Guide_to_Android_s_Security_Architecture.pdf)
* [BIOS and Secure Boot Attacks Uncovered](http://www.intelsecurity.com/resources/pr-bios-secure-boot-attacks-uncovered.pdf)
* [Apple IOS Security](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)
* [Debugging HTC phone boot-laoders](http://archive.hack.lu/2013/hacklu2013_hbootdbg.pdf)
* [Debugger for HBOOT](https://github.com/sogeti-esec-lab/hbootdbg)
* [Analysing HBOOT](http://tjworld.net/wiki/android/htc/vision/hbootanalysis)

 
