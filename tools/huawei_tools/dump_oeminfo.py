#!/usr/bin/python
import sys
import struct
import os

p = lambda v: struct.pack("<I", v)
u = lambda v: struct.unpack("<I", v)[0]

KNOWN_INDEXES = { 38: "IMEI (Encrypted)", 60: "PHONE MODEL", 59: "BUILD NUMBER",
                  97: "USR_FASTBOOT_UNLOCK (Encrypted)", 18: "VENDOR_NAME",
                  43: "BOOT LOGO 1", 42: "BOOT LOGO 2", 41: "BOOT LOGO 1", 35: "ROOT TYPE INFO"}


def read_oem_info_record(contents, num_entries_to_read=1):
    """
    Interpret the provided contents as Huawei OEM records and read them.
    :param contents: Content to be parsed.
    :param num_entries_to_read: number of entries to read.
    :return: number of records read successfully
    """
    expected_preamble = "OEM_INFO"
    num_read = 0
    curr_index = 0
    while num_read < num_entries_to_read:
        try:
            preamble_index = contents.index(expected_preamble, curr_index)
            strean_indx = preamble_index + 8 + 4
            info_id = u(contents[strean_indx: strean_indx+4])
            strean_indx += 4
            num_blocks = u(contents[strean_indx: strean_indx + 4])
            strean_indx += 4
            curr_block_num = u(contents[strean_indx: strean_indx + 4])
            strean_indx += 4
            total_entry_len = u(contents[strean_indx: strean_indx + 4])
            index_name = str(info_id)
            if info_id in KNOWN_INDEXES:
                index_name = KNOWN_INDEXES[info_id]
            print "[$] Entry, Index:" + index_name + ", Length:" + str(total_entry_len) + \
                  ", Num Blocks:" + str(num_blocks)
            # This is where data starts
            data_starts = curr_index + 512
            if num_blocks == 1:
                data_cont = contents[data_starts: data_starts + total_entry_len]
                print "[$] Data:" + str(data_cont) + "\n"
            else:
                print "[$] Data too long to display\n"
            curr_index = preamble_index + 0x4000
            num_read += 1
        except Exception as e:
            break

    return curr_index, num_read


def main():
    if len(sys.argv) < 2:
        print "[!] Usage: " + sys.argv[0] + " <oeminfo.img>\n"
        sys.exit(-1)

    oem_img_file = sys.argv[1]
    if not os.path.exists(oem_img_file):
        print "[!] Provided OEM INFO Image:" + oem_img_file + " does not exist."
        sys.exit(-1)

    fp = open(oem_img_file, "rb")
    oem_cont = fp.read()
    fp.close()
    curr_index = 0
    total_records_read = 0
    while curr_index < len(oem_cont):
        record_index, num_read = read_oem_info_record(oem_cont[curr_index:])
        total_records_read += num_read
        curr_index += record_index
        if not num_read:
            print "[!] Ignoring contents that cannot be interpreted as OEM_INFO records"
            break
    print "[*] Successfully read:" + str(total_records_read) + " OEM_INFO records."


if __name__ == "__main__":
    main()

