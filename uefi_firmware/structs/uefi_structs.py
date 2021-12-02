# -*- coding: utf-8 -*-
import ctypes

uint8_t = ctypes.c_ubyte
char = ctypes.c_char
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64
uint16_t = ctypes.c_ushort
guid_t = char * 16

FIRMWARE_VOLUME_GUIDS = {
    "FFS1":        "7a9354d9-0468-444a-81ce-0bf617d890df",
    "FFS2":        "8c8ce578-8a3d-4f1c-9935-896185c32dd3",
    "FFS3":        "5473c07a-3dcb-4dca-bd6f-1e9689e7349a",
    "NVRAM_EVSA":  "fff12b8d-7696-4c8b-a985-2747075b4f50",
    "NVRAM_NVAR":  "cef5b9a3-476d-497f-9fdc-e98143e0422c",
    "NVRAM_EVSA2": "00504624-8a59-4eeb-bd0f-6b36e96128e0",
    "APPLE_BOOT":  "04adeead-61ff-4d31-b6ba-64f8bf901f5a",
    "PFH1":        "16b45da2-7d70-4aea-a58d-760e9ecb841d",
    "PFH2":        "e360bdba-c3ce-46be-8f37-b231e5cb9f35",
    # '08758b38-458d-50e8-56e8-3bffffff83c4'
}

FIRMWARE_CAPSULE_GUIDS = [
    '3b6686bd-0d76-4030-b70e-b5519e2fc5a0',  # EFI Capsule
    '4a3ca68b-7723-48fb-3d80-578cc1fec44d',  # EFI Capsule v2
    '539182b9-abb5-4391-b69a-e3a943f72fcc',  # UEFI Capsule
    '6dcbd5ed-e82d-4c44-bda1-7194199ad92a',  # Firmware Management Capsule
]

FIRMWARE_GUIDED_GUIDS = {
    "LZMA_COMPRESSED":  "ee4e5898-3914-4259-9d6e-dc7bd79403cf",
    "TIANO_COMPRESSED": "a31280ad-481e-41b6-95e8-127f4c984779",
    "FIRMWARE_VOLUME":  "24400798-3807-4a42-b413-a1ecee205dd8",
    # "VOLUME_SECTION":  "367ae684-335d-4671-a16d-899dbfea6b88",
    "STATIC_GUID":      "fc1bcdb0-7d31-49aa-936a-a4600d9dd083"
}

FIRMWARE_FREEFORM_GUIDS = {
    "CHAR_GUID": "059ef06e-c652-4a45-9fbe-5975e369461c"
}

VSS2_TYPE_GUIDS = {
    "NVRAM_VSS2_AUTH_VAR_KEY_DATABASE": "aaf32c78-947b-439a-a180-2e144ec37792",
    "NVRAM_VSS2_STORE_GUID": "ddcf3617-3275-4164-98b6-fe85707ffe7d",
    "NVRAM_FDC_STORE_GUID": "ddcf3616-3275-4164-98b6-fe85707ffe7d"
}


FTW_BLOCK_SIGNATURES = {
    "EDKII_WORKING_BLOCK_SIGNATURE": "9e58292b-7c68-497d-a0ce-6500fd9f1b95",
    # in UEFITool, there is a VSS2_WORKING_BLOCK_SIGNATURE, but I havn't found it in EDK2
}

EFI_FILE_TYPES = {
    # http://wiki.phoenix.com/wiki/index.php/EFI_FV_FILETYPE
    0x00: ("unknown",                    "none",        "0x00"),
    0x01: ("raw",                        "raw",         "RAW"),
    0x02: ("freeform",                   "freeform",    "FREEFORM"),
    0x03: ("security core",              "sec",         "SEC"),
    0x04: ("pei core",                   "pei.core",    "PEI_CORE"),
    0x05: ("dxe core",                   "dxe.core",    "DXE_CORE"),
    0x06: ("pei module",                 "peim",        "PEIM"),
    0x07: ("driver",                     "dxe",         "DRIVER"),
    0x08: ("combined pei module/driver", "peim.dxe",    "COMBO_PEIM_DRIVER"),
    0x09: ("application",                "app",         "APPLICATION"),
    0x0a: ("system management",          "smm",         "SMM"),
    0x0b: ("firmware volume image",      "vol",         "FV_IMAGE"),
    0x0c: ("combined smm/driver",        "smm.dxe",     "COMBO_SMM_DRIVER"),
    0x0d: ("smm core",                   "smm.core",    "SMM_CORE"),
    # 0xc0: ("oem min"),
    # 0xdf: ("oem max"),
    0xf0: ("ffs padding",                "pad",         "0xf0")
}

EFI_SECTION_TYPES = {
    0x01: ("Compression",               "compressed",   None),
    0x02: ("Guid Defined",              "guid",         None),
    0x03: ("Disposable",                "disposable",   None),
    0x10: ("PE32 image",                "pe",           "PE32"),
    0x11: ("PE32+ PIC image",           "pic.pe",       "PIC"),
    0x12: ("Terse executable (TE)",     "te",           "TE"),
    0x13: ("DXE dependency expression", "dxe.depex",    "DXE_DEPEX"),
    # Added from previous code (not in Phoenix spec
    0x14: ("Version section",           "version",      "VERSION"),
    0x15: ("User interface name",       "ui",           "UI"),

    0x16: ("IA-32 16-bit image",        "ia32.16bit",   "COMPAT16"),
    0x17: ("Firmware volume image",     "fv",           "FV_IMAGE"),
    # See FdfParser.py in EDKII's GenFds
    0x18: ("Free-form GUID",            "freeform.guid", "SUBTYPE_GUID"),
    0x19: ("Raw",                       "raw",          "RAW"),
    0x1b: ("PEI dependency expression", "pie.depex",    "PEI_DEPEX"),
    0x1c: ("SMM dependency expression", "smm.depex",    "SMM_DEPEX")
}

EFI_COMPRESSION_TYPES = {
    0x00: "",
    # 0x01: "EFI_STANDARD_COMPRESSION",
    0x01: "PI_STD",
    # 0x02: "EFI_CUSTOMIZED_COMPRESSION"
    0x02: "PI_STD"
}

NVRAM_ATTRIBUTES = {
    "RT":         0x01,
    "DESC_ASCII": 0x02,
    "GUID":       0x04,
    "DATA":       0x08,
    "EXTHDR":     0x10,
    "HER":        0x20,
    "AUTHWD":     0x40,
    "VLD":        0x80,
}

#  VSS variable states
VSS_VARIABLE_STATES = {
    "NVRAM_VSS_VARIABLE_NON_VOLATILE":                          0x00000001,
    "NVRAM_VSS_VARIABLE_BOOTSERVICE_ACCESS":                    0x00000002,
    "NVRAM_VSS_VARIABLE_RUNTIME_ACCESS":                        0x00000004,
    "NVRAM_VSS_VARIABLE_HARDWARE_ERROR_RECORD":                 0x00000008,
    "NVRAM_VSS_VARIABLE_AUTHENTICATED_WRITE_ACCESS":            0x00000010,
    "NVRAM_VSS_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS": 0x00000020,
    "NVRAM_VSS_VARIABLE_APPEND_WRITE":                          0x00000040,
    "NVRAM_VSS_VARIABLE_APPLE_DATA_CHECKSUM":                   0x80000000,
    "NVRAM_VSS_VARIABLE_UNKNOWN_MASK":                          0x7FFFFF80
}

# VSS variable attributes
VSS_VARIABLE_ATTRIBUTES = {
    "NVRAM_VSS_VARIABLE_NON_VOLATILE":                          0x00000001,
    "NVRAM_VSS_VARIABLE_BOOTSERVICE_ACCESS":                    0x00000002,
    "NVRAM_VSS_VARIABLE_RUNTIME_ACCESS":                        0x00000004,
    "NVRAM_VSS_VARIABLE_HARDWARE_ERROR_RECORD":                 0x00000008,
    "NVRAM_VSS_VARIABLE_AUTHENTICATED_WRITE_ACCESS":            0x00000010,
    "NVRAM_VSS_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS": 0x00000020,
    "NVRAM_VSS_VARIABLE_APPEND_WRITE":                          0x00000040,
    "NVRAM_VSS_VARIABLE_APPLE_DATA_CHECKSUM":                   0x80000000,
    "NVRAM_VSS_VARIABLE_UNKNOWN_MASK":                          0x7FFFFF80
}

# The field value of all EVSA struct
EVSA_ENTRY_TYPES = {
    "NVRAM_EVSA_ENTRY_TYPE_STORE":        0xEC,
    "NVRAM_EVSA_ENTRY_TYPE_GUID1":        0xED,
    "NVRAM_EVSA_ENTRY_TYPE_GUID2":        0xE1,
    "NVRAM_EVSA_ENTRY_TYPE_NAME1":        0xEE,
    "NVRAM_EVSA_ENTRY_TYPE_NAME2":        0xE2,
    "NVRAM_EVSA_ENTRY_TYPE_DATA1":        0xEF,
    "NVRAM_EVSA_ENTRY_TYPE_DATA2":        0xE3,
    "NVRAM_EVSA_ENTRY_TYPE_DATA_INVALID": 0x83
}


class UEFIVariableHeaderType(ctypes.LittleEndianStructure):
    _fields_ = [
        ("StartId", uint16_t),
        ("State", uint8_t),
        ("Reserved", uint8_t),
        ("Attributes", uint32_t),
        ("NameSize", uint32_t),
        ("DataSize", uint32_t),
        ("VendorGuid", guid_t),
    ]


class NVARVariableHeaderType(ctypes.LittleEndianStructure):
    _fields_ = [
        ("StartId", char * 4),  # NVAR
        ("TotalSize", uint16_t),
        ("Reserved", char * 3),
        ("Attributes", uint8_t),
    ]


class EFIVariableStoreType(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Signature", uint32_t),
        ("Size", uint32_t),
        ("Format", uint8_t),
        ("State", uint8_t),
        ("Reserved", uint16_t),
        ("Reserved1", uint32_t),
    ]


class VSSHeaderType(ctypes.LittleEndianStructure):
    _fields_ = [
        ("VendorGuid", guid_t),
        ("StartId", uint16_t),
        ("State", uint8_t),
        ("Reserved", uint8_t),
        ("Attributes", uint32_t),
        ("NameSize", uint32_t),
        ("DataSize", uint32_t),
    ]


class VSSNewHeaderType(ctypes.LittleEndianStructure):
    _fields_ = [
        ("VendorGuid", guid_t),
        ("StartId", uint16_t),
        ("State", uint8_t),
        ("Reserved", uint8_t),
        ("Attributes", uint32_t),
        ("Unknown", char * 28),  # ???
        ("NameSize", uint32_t),
        ("DataSize", uint32_t),
    ]


# VSS Header is very rare now, but the VSS2 is common
class VSS2VariableStoreHeader(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Signature", guid_t),   # one of the guid in VSS2_TYPE_GUIDS
        ("Size", uint32_t),      # This value include the size of store header
        ("Format", uint8_t),
        ("State", uint8_t),
        ("Unknown", uint16_t),
        ("Reserved", uint32_t)
    ]


# Variable will in this format if "Signature" is NVRAM_VSS2_AUTH_VAR_KEY_DATABASE
# start from the end of the VSS2VariableStoreHeader
class VSS2AuthVariableHeader(ctypes.LittleEndianStructure):   # 4-bytes aligned
    _pack_ = 4   # without this statement, the struct will aligned for uint64_t(8), causes the error structure_size
    _fields_ = [
        ("StartId", uint16_t),       # '\xaa\x55'
        ("State", uint8_t),
        ("Reserved", uint8_t),
        ("Attributes", uint32_t),
        ("MonotonicCounter", uint64_t),
        ("Timestamp", char * 16),    # A time structure
        ("PubKeyIndex", uint32_t),   # Index in PubKey database
        ("NameSize", uint32_t),      # Size of variable name, utf-16le, contain the '\x00\x00'
        ("DataSize", uint32_t),      # Size of variable data without header and name
        ("VendorGuid", guid_t)
    ]   # after the struct is the variable name


# Variable will in this format if "Signature" is NVRAM_VSS2_STORE_GUID
class VSSVariableHeader(ctypes.LittleEndianStructure):
    _fields_ = [
        ("StartId", uint16_t),  # '\xaa\x55'
        ("State", uint8_t),
        ("Reserved", uint8_t),
        ("Attributes", uint32_t),
        ("NameSize", uint32_t),  # Size of variable name, utf-16le, contain the '\x00\x00'
        ("DataSize", uint32_t),  # Size of variable data without header and name
        ("VendorGuid", guid_t)
        # In apple, there is another field: DataCRC32. It can be identified by the "Attributes"
    ]   # after the struct is the variable name
# I haven't found the "NVRAM_FDC_STORE" structure


class TLVHeaderType(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Tag0", uint8_t),
        ("Tag1", uint8_t),
        ("Size", uint16_t),
    ]


class EVSARecordType(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Signature", char * 4),
        ("Unknown", uint32_t),
        ("Length", uint32_t),
        ("Unknown1", uint32_t),
    ]


# The header of EVSA sturcts
class EVSAEntryHeader(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Type", uint8_t),   # Values in EVSA_ENTRY_TYPES
        ("Checksum", uint8_t),
        ("Size", uint16_t)   # The size contains struct and data
    ]


# All of the EVSA structs
# Header of EVSA region
class EVSAStoreEntry(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Header", EVSAEntryHeader),  # for this type, the size may be unused
        ("Signature", uint32_t),      # "EVSA"
        ("Attributes", uint32_t),
        ("StoreSize", uint32_t),      # The size of the EVSA region, not only this struct
        ("Reserved", uint32_t)
    ]


class EVSAGuidEntry(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Header", EVSAEntryHeader),
        ("GuidId", uint16_t)
        # after the struct, there is a GUID
    ]


class EVSANameEntry(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Header", EVSAEntryHeader),
        ("VarId", uint16_t)
        # after the struct, there is a name string
    ]


class EVSADataEntry(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Header", EVSAEntryHeader),
        ("GuidId", uint16_t),
        ("VarId", uint16_t),
        ("Attributes", uint32_t)   # same as VSS attributes
        # after the struct, there is this variable's data
    ]


class GUIDRecordType(ctypes.LittleEndianStructure):
    _fields_ = [
        ("GuidId", uint16_t),
        ("Guid", guid_t),
    ]


class FirmwareVolumeType(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Reserved",   char * 16),  # Zeros
        ("Guid",       guid_t),  #
        ("Size",       uint64_t),
        ("Magic",      char * 4),
        ("Attributes", uint8_t),
        ("HeaderSize", uint32_t),
        ("Checksum",   uint16_t),
        ("Reserved2",  uint8_t),
        ("Revision",   uint8_t)
    ]


# Some other structs, may not need get their data
# But if not processed, the parsing will be affected
# The fields we need know about All of the following structs are "Signature" and "Size"
class FTWBlock(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Signature", guid_t),     # The value is in FTW_BLOCK_SIGNATURES
        ("Crc", uint32_t),
        ("Reserved", char * 4),
        ("WriteQueueSize", uint64_t)   # without the header
    ]


# Although has "Flash", but it is a UEFI struct
class FlashMap(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Signature", char * 10),    # "_FLASH_MAP"
        ("NumberEntries", uint16_t),   # number of the records
        ("Reserved", uint32_t)
    ]


# the "record" in FlashMap, before the FlashMap is a FlashMapEntry array
class FlashMapEntry(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Guid", guid_t),
        ("DataType", uint16_t),    # volume (0x0000) and data in volume (0x0001)
        ("EntryType", uint16_t),
        ("PhysicalAddress", uint64_t),    # The data this record points to
        ("Size", uint32_t),    # data size, won't affect the size of the struct
        ("Offset", uint32_t)
    ]


# CMDB is a struct about configuration, the size of this struct is a fixed value: 0x100
class CMDBHeader(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Signature", uint32_t),   # "CMDB"
        ("HeaderSize", uint32_t),  # Size of the header
        ("TotalSize", uint32_t),   # Total size of header and chunks
    ]


# SLIC, can be divided into pubkey and marker
class OEMActivationPubkey(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Type", uint32_t),
        ("Size", uint32_t),   # fixed value 0x9c
        ("KeyType", uint8_t),
        ("Version", uint8_t),
        ("Reserved", uint16_t),
        ("Algorithm", uint32_t),
        ("Magic", uint32_t),   # Signature: "RSA1"
        ("BitLength", uint32_t),
        ("Exponent", uint32_t),
        ("Modules", char * 128)
    ]


class OEMActivationMaker(ctypes.LittleEndianStructure):
    _pack_ = 1  # without this statement causes the error structure_size
    _fields_ = [
        ("Type", uint32_t),
        ("Size", uint32_t),  # fixed value 0xB6
        ("Version", uint32_t),
        ("OemId", char * 6),
        ("OemTableId", char * 8),
        ("WindowsFlag", uint64_t),  # Signature: "WINDOWS\x20" (remember little endian)
        ("SlicVersion", uint32_t),
        ("Reserved", char * 16),
        ("Signature", char * 128)
    ]


class CPUMicrocodeHeader(ctypes.LittleEndianStructure):
    _fields_ = [
        ("HeaderVersion", uint32_t),
        ("UpdateRevision", uint32_t),
        ("Date", uint32_t),
        ("ProcessorSignature", uint32_t),
        ("Checksum", uint32_t),
        ("LoaderRevision", uint32_t),
        ("ProcessorFlags", uint32_t),
        ("DataSize", uint32_t),    # The size without header
        ("TotalSize", uint32_t),   # The size contain header
        ("Reserved", char * 12)
    ]


class FDCVolumeHeader(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Signature", uint32_t),   # "_FDC"
        ("Size", uint32_t)         # Size of the whole region
    ]
