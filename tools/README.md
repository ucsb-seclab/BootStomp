Tools
===================


This folder contains all standalone tools needed to work with boot images.

----------


bootsplitter.py
-------------

This tool used to split the extracted aboot.img into IDA loadable binary, by using techniques in [1]
**Usage:**
```
python bootsplitter.py aboot.img <output_folder>
```
**Example:**
```
$ python bootsplitter.py aboot.img processed_dir
[+] MAGIC:0x5
[+] IMAGE BASE:0xf900000
[+] IMAGE SIZE:0x3e52c
[+] IMAGE BASE + CODE SIZE:0xf93e52c

[+] OUTPUT HEADER STRIPPED IMAGE:processed_dir/aboot_header_stripped

[+] CODE SECTION OF BOOT IMAGE IS AT:processed_dir/aboot_code.img
[$] TRY TO LOAD THE FILE:processed_dir/aboot_code.img IN IDA WITH LOADING ADDRESS:0xf900000
```


  [1]: http://newandroidbook.com/Articles/aboot.html


