from ctypes import Structure, c_long, c_ushort, c_void_p, c_void_p, c_short, c_long, c_ulong, c_uint32, c_void_p, sizeof
from ctypes.wintypes import DWORD, HWND, LONG, LPVOID
from enum import Enum, IntEnum, IntFlag

class BITMAP(Structure):
    _fields_ = [
        ("bmType", LONG),
        ("bmWidth", LONG),
        ("bmHeight", LONG),
        ("bmWidthBytes", LONG),
        ("bmPlanes", c_ushort),
        ("bmBitsPixel", c_ushort),
        ("bmBits", LPVOID)
    ]




class HITI_JOB_PROPERTY_RT(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("hParentWnd", c_void_p ),  # 在Python中，HWND通常是一个整数类型，代表窗口句柄
        ("pReserved1", c_void_p),

        ("dwPaperType", DWORD),
        ("dwPrintMode", DWORD),
        ("shOrientation", c_short),  # 1=Portrait, 2=Landscape
        ("shCopies", c_short),

        ("dwFlags", DWORD),

        ("pReserved2", c_void_p),
        ("pReserved3", c_void_p),
        ("dwIndex", DWORD),

        ("pReserved4", c_void_p),
        ("dwApplyMatte", DWORD),
        ("lReserved1", c_long),

        ("pReserved5", c_void_p),
        ("pReserved6", c_void_p),
    ]
        

class InfoType(Enum):
    MFG_SERIAL = 1
    MODEL_NAME = 2
    FIRMWARE_VERSION = 3
    RIBBON_INFO = 4
    PRINT_COUNT = 5
    CUTTER_COUNT = 6

class RibbonType(Enum):
    TYPE_4X6 = 1
    TYPE_5X7 = 2
    TYPE_6X9 = 3
    TYPE_6X8 = 4
    TYPE_5X3dot5 = 5
    TYPE_6X12 = 6
    TYPE_8X12 = 7

class WM_HITI_PRINTER(IntEnum):
    MSG_JOB_BEGIN = 1
    MSG_PRINT_ONE_PAGE = 3
    MSG_PRINT_ONE_COPY = 4
    MSG_JOB_END = 6
    MSG_DEVICE_STATUS = 7
    MSG_JOB_CANCELED = 12
    MSG_JOB_PRINTED = 24



class HITI_DS(Enum):
    HITI_DS_IDLE = 0x00000000  # Printer is idle
    HITI_DS_BUSY = 0x00080000  # Printer is busy
    HITI_DS_OFFLINE = 0x00000080  # Printer is disconnected or power off
    HITI_DS_PRINTING = 0x00000002  # Printer is printing
    HITI_DS_PROCESSING_DATA = 0x00000005  # Driver is processing print data
    HITI_DS_SENDING_DATA = 0x00000006  # Driver is sending data to printer
    HITI_DS_COVER_OPEN = 0x00050001  # Cover open/Ribbon cassette door open
    HITI_DS_COVER_OPEN2 = 0x00050101  # Cover open/Ribbon cassette door open
    HITI_DS_PAPER_OUT = 0x00008000  # Paper out or feeding error
    HITI_DS_PAPER_LOW = 0x00008001  # Paper low
    HITI_DS_PAPER_JAM = 0x00030000  # Paper jam
    HITI_DS_PAPER_TYPE_MISMATCH = 0x000100FE  # Paper type mismatch
    HITI_DS_PAPER_TRAY_MISMATCH = 0x00008010  # Paper tray mismatch
    HITI_DS_TRAY_MISSING = 0x00008008  # Paper tray missing
    HITI_DS_RIBBON_MISSING = 0x00080004  # Ribbon missing
    HITI_DS_OUT_OF_RIBBON = 0x00080103  # Out of ribbon
    HITI_DS_RIBBON_TYPE_MISMATCH = 0x00080200  # Ribbon type mismatch
    HITI_DS_RIBBON_ERROR = 0x000802FE  # Ribbon error
    HITI_DS_SRAM_ERROR = 0x00030001  # SRAM error
    HITI_DS_SDRAM_ERROR = 0x00030101  # SDRAM error
    HITI_DS_ADC_ERROR = 0x00030201  # ADC error
    HITI_DS_NVRAM_ERROR = 0x00030301  # NVRAM read/write error
    HITI_DS_FW_CHECKSUM_ERROR = 0x00030302  # Check sum error - SDRAM
    HITI_DS_DSP_CHECKSUM_ERROR = 0x00030402  # DSP code check sum error
    HITI_DS_HEAT_PARAMETER_INCOMPATIBLE = 0x000304FE  # Heating parameter table incompatible
    HITI_DS_CAM_PLATEN_ERROR = 0x00030501  # Cam Platen error
    HITI_DS_ADF_ERROR = 0x00030601  # Adf Cam error
    HITI_DS_WRITE_FAIL = 0x0000001F  # Send data to printer fail
    HITI_DS_READ_FAIL = 0x0000002F  # Get data from printer fail

    # Device Error for P720L/P728L/P520L
    HITI_DS_0100_COVER_OPEN = 0x00000100  # 0100 Cover open
    HITI_DS_0101_COVER_OPEN_FAIL = 0x00000101  # 0101 Cover open fail
    HITI_DS_0200_IC_CHIP_MISSING = 0x00000200  # 0200 IC chip missing
    HITI_DS_0201_RIBBON_MISSING = 0x00000201  # 0201 Ribbon missing
    HITI_DS_0202_RIBBON_MISMATCH = 0x00000202  # 0202 Ribbon mismatch 01
    HITI_DS_0203_SECURITY_CHECK_FAIL = 0x00000203  # 0203 Security check fail
    HITI_DS_0204_RIBBON_MISMATCH = 0x00000204  # 0204 Ribbon mismatch 02
    HITI_DS_0205_RIBBON_MISMATCH = 0x00000205  # 0205 Ribbon mismatch 03
    HITI_DS_0300_RIBBON_OUT = 0x00000300  # 0300 Ribbon out 01
    HITI_DS_0301_RIBBON_OUT = 0x00000301  # 0301 Ribbon out 02
    HITI_DS_0302_PRINTING_FAIL = 0x00000302  # 0302 Printing fail
    HITI_DS_0400_PAPER_OUT = 0x00000400  # 0400 Paper out 01
    HITI_DS_0401_PAPER_OUT = 0x00000401  # 0401 Paper out 02
    HITI_DS_0402_PAPER_NOT_READY = 0x00000402  # 0402 Paper not ready
    HITI_DS_0500_PAPER_JAM = 0x00000500  # 0500 Paper jam 01
    HITI_DS_0501_PAPER_JAM = 0x00000501  # 0501 Paper jam 02
    HITI_DS_0502_PAPER_JAM = 0x00000502  # 0502 Paper jam 03
    HITI_DS_0503_PAPER_JAM = 0x00000503  # 0503 Paper jam 04
    HITI_DS_0504_PAPER_JAM = 0x00000504  # 0504 Paper jam 05
    HITI_DS_0505_PAPER_JAM = 0x00000505  # 0505 Paper jam 06
    HITI_DS_0506_PAPER_JAM = 0x00000506  # 0506 Paper jam 07
    HITI_DS_0507_PAPER_JAM = 0x00000507  # 0507 Paper jam 08
    HITI_DS_0508_PAPER_JAM = 0x00000508  # 0508 Paper jam 09
    HITI_DS_0509_PAPER_JAM = 0x00000509  # 0509 Paper jam 10
    HITI_DS_0600_PAPER_JAM = 0x00000600  # 0600 Paper jam 11
    HITI_DS_0601_PAPER_JAM = 0x00000601  # 0601 Paper jam 12
    HITI_DS_0700_SYSTEM_ERROR = 0x00000700  # 0700 System error 01
    HITI_DS_0701_SYSTEM_ERROR = 0x00000701  # 0701 System error 02
    HITI_DS_0702_SYSTEM_ERROR = 0x00000702  # 0702 System error 03
    HITI_DS_0703_SYSTEM_ERROR = 0x00000703  # 0703 System error 04
    HITI_DS_0704_SYSTEM_ERROR = 0x00000704  # 0704 System error 05
    HITI_DS_0705_SYSTEM_ERROR = 0x00000705  # 0705 System error 06
    HITI_DS_0706_SYSTEM_ERROR = 0x00000706  # 0706 System error 07
    HITI_DS_0707_SYSTEM_ERROR = 0x00000707  # 0707 System error 08
    HITI_DS_0708_SYSTEM_ERROR = 0x00000708  # 0708 System error 09
    HITI_DS_0709_SYSTEM_ERROR = 0x00000709  # 0709 System error 10
    HITI_DS_0710_SYSTEM_ERROR = 0x00000710  # 0710 System error 11
    HITI_DS_0711_SYSTEM_ERROR = 0x00000711  # 0711 System error 12
    HITI_DS_0800_CALIBRATION_FAIL = 0x00000800  # 0800 Calibration fail 01
    HITI_DS_0801_CALIBRATION_FAIL = 0x00000801  # 0801 Calibration fail 02
    HITI_DS_0802_CALIBRATION_FAIL = 0x00000802  # 0802 Calibration fail 03
    HITI_DS_0803_CALIBRATION_FAIL = 0x00000803  # 0803 Calibration fail 04
    HITI_DS_0804_CALIBRATION_FAIL = 0x00000804  # 0804 Calibration fail 05
    HITI_DS_0805_CALIBRATION_FAIL = 0x00000805  # 0805 Calibration fail 06
    HITI_DS_0806_CALIBRATION_FAIL = 0x00000806  # 0806 Calibration fail 07
    HITI_DS_0807_CALIBRATION_FAIL = 0x00000807  # 0807 Calibration fail 08
    HITI_DS_0808_CALIBRATION_FAIL = 0x00000808  # 0808 Calibration fail 09
    HITI_DS_0809_CALIBRATION_FAIL = 0x00000809  # 0809 Calibration fail 10
    HITI_DS_0900_FIRMWARE_ERROR = 0x00000900  # 0900 Firmware error 01
    HITI_DS_0901_FIRMWARE_ERROR = 0x00000901  # 0901 Firmware error 02
    HITI_DS_0902_FIRMWARE_ERROR = 0x00000902  # 0902 Firmware error 03
    HITI_DS_0903_FIRMWARE_ERROR = 0x00000903  # 0903 Firmware error 04
    HITI_DS_0904_FIRMWARE_ERROR = 0x00000904  # 0904 Firmware error 05
    HITI_DS_0905_FIRMWARE_ERROR = 0x00000905  # 0905 Firmware error 06
    HITI_DS_0906_FIRMWARE_ERROR = 0x00000906  # 0906 Firmware error 07
    HITI_DS_0907_FIRMWARE_ERROR = 0x00000907  # 0907 Firmware error 08
    HITI_DS_0908_FIRMWARE_ERROR = 0x00000908  # 0908 Firmware error 09
    HITI_DS_0909_FIRMWARE_ERROR = 0x00000909  # 0909 Firmware error 10
    HITI_DS_0910_FIRMWARE_ERROR = 0x00000910  # 0910 Firmware error 11
    HITI_DS_0911_FIRMWARE_ERROR = 0x00000911  # 0911 Firmware error 12
    HITI_DS_0912_FIRMWARE_ERROR = 0x00000912  # 0912 Firmware error 13


class HITI_PAPER_TYPE(IntEnum):
    HITI_PAPER_TYPE_4X6_PHOTO = 0
    HITI_PAPER_TYPE_6X8_PHOTO = 6
    HITI_PAPER_TYPE_6X9_PHOTO = 12
    HITI_PAPER_TYPE_6X9_SPLIT_2UP = 14
    HITI_PAPER_TYPE_5X7_PHOTO = 4
    HITI_PAPER_TYPE_4X6_SPLIT_2UP = 17
    HITI_PAPER_TYPE_5X7_SPLIT_2UP = 19
    HITI_PAPER_TYPE_4X6_SPLIT_3UP = 21

class PAPER_SIZE(IntEnum):
    PAPER_SIZE_6X4 = 520
    PAPER_SIZE_6X8 = 521
    PAPER_SIZE_5X7 = 523
    PAPER_SIZE_6X8_SPLIT = 524
    PAPER_SIZE_6X4_SPLIT_2UP = 525
    PAPER_SIZE_5X7_2UP = 529
    PAPER_SIZE_6X8_2UP = 530
    PAPER_SIZE_6X8_FOR_6X4_2_SPILIT = 536
    PAPER_SIZE_6X8_FOR_6X4_3_SPILIT = 537
    PAPER_SIZE_6X6 = 532
    PAPER_SIZE_5X5 = 618
    PAPER_SIZE_6X5 = 554
    PAPER_SIZE_6X4_COMBO_PRINT_3UP=527
    

class HITI_RIBBON_TYPE(IntEnum):
    HITI_RIBBON_TYPE_4X6 = 1
    HITI_RIBBON_TYPE_5X7 = 2
    HITI_RIBBON_TYPE_6X9 = 3
    HITI_RIBBON_TYPE_6X8 = 4

class HITI_FLAGS(IntFlag):
    HITI_FLAG_NOT_SHOW_ERROR_MSG_DLG = 0x00000001
    HITI_FLAG_WAIT_MSG_DONE = 0x00000002
    HITI_FLAG_NOT_SHOW_CLEAN_MSG = 0x00000100

class HITI_COMMAND(IntEnum):
    HITI_COMMAND_RESET_PRINTER = 100
    HITI_COMMAND_CUT_PAPER = 103

class HITI_DEVINFO(IntEnum):
    HITI_DEVINFO_MFG_SERIAL = 1
    HITI_DEVINFO_MODEL_NAME = 2
    HITI_DEVINFO_FIRMWARE_VERSION = 3
    HITI_DEVINFO_RIBBON_INFO = 4
    HITI_DEVINFO_PRINT_COUNT = 5
    HITI_DEVINFO_CUTTER_COUNT = 6




