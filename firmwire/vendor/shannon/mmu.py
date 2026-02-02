import struct

import firmwire.vendor.shannon.mpu as mpu

AP_STR = {
    0b000: "--", 0b001: "rw", 0b010: "rw", 0b011: "rw",
    0b100: "--", 0b101: "r-", 0b110: "r-", 0b111: "r-"
}

"""
struct MMUEntry {
    // Number of sections with size 0x100000 bytes
	uint32_t num_sections;
	// Virtual start address of this section
	void * virt_addr;
	// Physical start address of this section
	void * phys_addr;
	// Flags as described in https://developer.arm.com/documentation/ddi0406/c/System-Level-Architecture/Virtual-Memory-System-Architecture--VMSA-/Short-descriptor-translation-table-format/Short-descriptor-translation-table-format-descriptors?lang=en
	uint32_t flags;
};
"""
class MMUEntry(mpu.MPUEntry):
    def __init__(self, slot, base, size, flags):
        self.slot = slot
        self.base = base
        self.size = size
        self.flags = flags
        self.prot = extract_prot_from_flags(flags)

        self.executable = True if "x" in self.prot else False
        self.writable = True if "w" in self.prot else False
        self.readable = True if "r" in self.prot else False

    def get_rwx_str(self):
        return self.prot

    def __repr__(self):
        return "<MMUEntry [{:08x}, {:08x}] id={} perm={}>".format(
            self.get_start(), self.get_end(), self.slot, self.prot
        )

"""
struct MMUEntry2 {
	// Virtual start address of this section
	void *virt_addr;
	// Physical start address of this section
	void *phys_addr;
	// Physical end address of this section (exclusive)
	void *end_addr;
	// Flags as described in https://developer.arm.com/documentation/ddi0406/c/System-Level-Architecture/Virtual-Memory-System-Architecture--VMSA-/Short-descriptor-translation-table-format/Short-descriptor-translation-table-format-descriptors?lang=en
	uint32_t flags;
};
"""
class MMUEntry_2(mpu.MPUEntry):
    def __init__(self, slot, base, size, flags):
        self.slot = slot
        self.base = base
        self.size = size
        self.flags = flags
        self.prot = extract_prot_from_flags(flags)

        self.executable = True if "x" in self.prot else False
        self.writable = True if "w" in self.prot else False
        self.readable = True if "r" in self.prot else False

    def get_rwx_str(self):
        return self.prot

    def __repr__(self):
        return "<MMUEntry [{:08x}, {:08x}] id={} perm={}>".format(
            self.get_start(), self.get_end(), self.slot, self.prot
        )


def extract_prot_from_flags(flags):
    ap = ((flags >> 10) & 3) | ((flags >> 13) & 4)
    prot = AP_STR[ap]
    pxn = flags & 1
    xn = flags & (1 << 4)
    if pxn == 1:
        xn = 1
    if prot != "--" and xn == 0:
        prot += "x"
    else:
        prot += "-"
    return prot

"""
struct MMUEntry2 {
	// Virtual start address of this section
	void *virt_addr;
	// Physical start address of this section
	void *phys_addr;
	// Physical end address of this section (exclusive)
	void *end_addr;
	// Flags as described in https://developer.arm.com/documentation/ddi0406/c/System-Level-Architecture/Virtual-Memory-System-Architecture--VMSA-/Short-descriptor-translation-table-format/Short-descriptor-translation-table-format-descriptors?lang=en
	uint32_t flags;
};
"""

def parse_mmu_table(modem_main, address):
    entries = []
    unsafe_regions = []

    data = modem_main.data
    address -= modem_main.load_address

    slot = 0
    while True:
        array = data[address: address + 0x10]
        num_sections, virt_addr, phys_addr, flags = struct.unpack("<IIII", array)
        size = num_sections * 0x100000
        prot = extract_prot_from_flags(flags)

        if num_sections == 0:
            break

        if prot == "rwx":
            unsafe_regions.append((phys_addr, phys_addr + size))

        entry = MMUEntry(slot, phys_addr, size, flags)
        entries += [entry]

        address += 0x10
        slot += 1

    return entries, unsafe_regions

def parse_mmu_table_2(modem_main, address):
    entries = []
    unsafe_regions = []

    data = modem_main.data
    address -= modem_main.load_address
    
    slot = 0
    while True:
        array = data[address: address + 0x10]
        virt_addr, phys_start, phys_end, flags = struct.unpack("<IIII", array)
        size = phys_end - phys_start
        prot = extract_prot_from_flags(flags)

        if num_sections == 0:
            break

        if prot == "rwx": # add check that phys_start + size == phys_end
            unsafe_regions.append((phys_start, phys_start + size))

        entry = MMUEntry(slot, phys_start, size, flags)
        entries += [entry]

        address += 0x10
        slot += 1

    return entries, unsafe_regions
