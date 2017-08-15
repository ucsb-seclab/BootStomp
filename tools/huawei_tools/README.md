Huawei Tools
===================


This folder contains all tools needed to work with Huawei images.

----------


dump_nvme.py
-------------

This tool used to dump the contents of nvme.img (/dev/block/platform/hi_mci.0/by-name/nvme) from Huawei P8 Lite phones.
**Usage:**
```
python dump_nvme.py nvme.img
```

dump_oeminfo.py
-------------

This tool used to dump the contents of oeminfo.img (/dev/block/platform/hi_mci.0/by-name/oeminfo) from Huawei P8 Lite phones.
**Usage:**
```
python dump_oeminfo.py oeminfo.img
```

oeminfo_exploit.py
-------------

This tool used to create an expoloit oeminfo image for Huawei P8 Lite phones, so that if you flash this back you could perform stack buffer overflow.
**Usage:**
```
python oeminfo_exploit.py oeminfo.img output_exploit_oeminfo.img
```




