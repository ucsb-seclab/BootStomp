#!/usr/bin/python
import sys
import struct
import os

p = lambda v: struct.pack("<I", v)
u = lambda v: struct.unpack("<I", v)[0]


def read_nvm_info_record(contents, num_entries_to_read=1):
    """
    Interpret the provided contents as Huawei NVM records and read them.
    :param contents: Content to be parsed.
    :param num_entries_to_read: number of entries to read.
    :return: number of records read successfully
    """
    first_entry = "SWVERSI"
    num_read = 0
    curr_entry_index = 0
    exit_all = False
    while num_read < num_entries_to_read and (not exit_all):
        try:
            start_entry = contents.index(first_entry, curr_entry_index)
            curr_entry_index = start_entry - 4
            prev_record_id = None
            while num_read < num_entries_to_read and (not exit_all):
                record_id = u(contents[curr_entry_index: curr_entry_index + 4])
                strean_indx = curr_entry_index + 4
                record_name = str(contents[strean_indx: strean_indx + 8])
                strean_indx += 8
                # No IDEA, what this means.
                some_num = u(contents[strean_indx: strean_indx + 4])
                strean_indx += 4
                record_len = u(contents[strean_indx: strean_indx + 4])
                strean_indx += 8
                record_contents = str(contents[strean_indx: strean_indx + record_len])
                print "[$] NVME Record, ID=" + str(record_id) + ", Name=" + str(record_name) + ", Length=" + str(record_len) + \
                      ", Contents=" + str(record_contents) + "\n"
                curr_entry_index += 0x80
                num_read += 1
                if prev_record_id is None:
                    if record_id != 0:
                        exit_all = True
                        break
                else:
                    if prev_record_id != (record_id - 1):
                        exit_all = True
                        break
                prev_record_id = record_id
        except Exception as e:
            break

    return curr_entry_index, num_read


def main():
    if len(sys.argv) < 2:
        print "[!] Usage: " + sys.argv[0] + " <nvme.img>\n"
        sys.exit(-1)

    oem_img_file = sys.argv[1]
    if not os.path.exists(oem_img_file):
        print "[!] Provided NVME Image:" + oem_img_file + " does not exist."
        sys.exit(-1)

    fp = open(oem_img_file, "rb")
    oem_cont = fp.read()
    fp.close()
    curr_index = 0
    total_records_read = 0
    while curr_index < len(oem_cont):
        record_index, num_read = read_nvm_info_record(oem_cont[curr_index:], num_entries_to_read=1000000)
        total_records_read += num_read
        curr_index += record_index
        if not num_read:
            print "[!] Ignoring contents that cannot be interpreted as NVME records"
            break
    print "[*] Successfully read:" + str(total_records_read) + " NVME records."


if __name__ == "__main__":
    main()
