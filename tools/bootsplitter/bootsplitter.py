#!/usr/bin/python
import sys
import struct
import os

if len(sys.argv) < 3:
    print "[*] Usage: <tool> <aboot.img> <folder_to_output_splitted_image>\n"
    sys.exit(-1)

boot_img = sys.argv[1]
if not os.path.exists(boot_img):
    print "[!] Provided file:" + boot_img + " does not exist\n"
    sys.exit(-2)
    
output_folder = sys.argv[2]
os.system('mkdir -p ' + output_folder)

fp_boot = open(boot_img, 'rb')
boot_cont = fp_boot.read()
fp_boot.close()

magic_ind = 0*4
img_base_ind = 3*4
img_size_ind = 5*4
code_size_ind = 6*4


magic_num = boot_cont[magic_ind:magic_ind+4]
img_base = boot_cont[img_base_ind:img_base_ind+4]
img_size = boot_cont[img_size_ind:img_size_ind+4]
code_size = boot_cont[code_size_ind:code_size_ind+4]


magic_num = struct.unpack("I", bytearray(magic_num))[0]
img_base = struct.unpack("I", bytearray(img_base))[0]
img_size = struct.unpack("I", bytearray(img_size))[0]
code_size = struct.unpack("I", bytearray(code_size))[0]

print "[+] MAGIC:" + hex(magic_num)
print "[+] IMAGE BASE:" + hex(img_base)
print "[+] IMAGE SIZE:" + hex(img_size)
print "[+] IMAGE BASE + CODE SIZE:" + hex(code_size)

output_img = os.path.join(output_folder, "aboot_header_stripped")

fp = open(output_img, "wb")
fp.write(boot_cont[40:])
fp.close()

print "\n[+] OUTPUT HEADER STRIPPED IMAGE:" + output_img + "\n"
code_cont = boot_cont[40: (40 + img_size)]

output_code_section = os.path.join(output_folder, "aboot_code.img")
fp = open(output_code_section, "wb")
fp.write(code_cont)
fp.close()

print "[+] CODE SECTION OF BOOT IMAGE IS AT:" + output_code_section

print "[$] TRY TO LOAD THE FILE:" + output_code_section + " IN IDA WITH LOADING ADDRESS:" + hex(img_base)


