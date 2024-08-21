import ctypes
from ctypes import wintypes

from config import cfg
from dataModel import BITMAP, HITI_DS, HITI_JOB_PROPERTY_RT
from utility import  get_HITI_DS_name, get_ribbon_name


dll_path=cfg['DLL_PATH']
dll=ctypes.WinDLL(dll_path)



#函数定义
dll.HITI_CheckPrinterStatusW.restype = wintypes.DWORD
dll.HITI_CheckPrinterStatusW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
status = wintypes.DWORD()

dll.HITI_ApplyJobSettingW.restype = wintypes.DWORD
dll.HITI_ApplyJobSettingW.argtypes = [ctypes.c_wchar_p, wintypes.HDC,  ctypes.POINTER(ctypes.c_byte), ctypes.POINTER(ctypes.c_byte)]

dll.HITI_GetDeviceInfoW.argtypes = [
        ctypes.c_wchar_p,   # szPrinterName
        wintypes.DWORD,     # dwInfoType
        ctypes.POINTER(ctypes.c_byte),  # lpInfoData
        ctypes.POINTER(wintypes.DWORD)  # lpdwDataLen
    ]
dll.HITI_GetDeviceInfoW.restype = wintypes.DWORD  

dll.HITI_DoCommandW.argtypes = [
    ctypes.c_wchar_p,   # szPrinterName
    wintypes.DWORD      # dwCommand
]
dll.HITI_DoCommandW.restype = wintypes.DWORD  



dll.HITI_PrintOnePageW.restype = wintypes.DWORD 
dll.HITI_PrintOnePageW.argtypes = [ctypes.c_wchar_p, 
                                   ctypes.POINTER(HITI_JOB_PROPERTY_RT), 
                                   ctypes.POINTER(BITMAP)]


def HITI_CheckPrinterStatus(printer_name):
    # 调用函数
    result = dll.HITI_CheckPrinterStatusW(printer_name, ctypes.byref(status))
    status_name=get_HITI_DS_name(status.value)
    print(f"Printer {printer_name} status: {status_name}")
    return status.value

def HITI_ApplyJobSetting(printer_name,lpInJobProp,hDC):
    # 没有效果
    lpInDevMode = ctypes.cast(ctypes.pointer(ctypes.c_byte(0)), ctypes.POINTER(ctypes.c_byte)) 
    result = dll.HITI_ApplyJobSettingW(printer_name, hDC, lpInDevMode, lpInJobProp)
    if result == 0:
        print("Job setting applied successfully.")
    else:
        print(f"Failed to apply job setting. Error code: {result}")

def HITI_GetDeviceInfo(printer_name,info_type):
    # 初始化参数
    info_data = (ctypes.c_byte * 256)()  # 假设缓冲区长度为256
    data_len = wintypes.DWORD(len(info_data))
    # 调用函数
    result = dll.HITI_GetDeviceInfoW(printer_name, info_type, info_data, ctypes.byref(data_len))
    # 检查返回值
    if result == 0:
        if info_type == 1 or info_type == 2 or info_type == 3:  # TCHAR数组类型
            result_data = ''.join(map(chr, info_data[:data_len.value // ctypes.sizeof(ctypes.c_wchar)]))
            print(f"TCHAR array: {result_data}")
            return result_data
        elif info_type == 4:  # DWORD数组类型
            ribbon_type = ctypes.cast(info_data, ctypes.POINTER(wintypes.DWORD))[0]
            remain_ribbon_count = ctypes.cast(info_data, ctypes.POINTER(wintypes.DWORD))[1]
            
            print(f"Ribbon Type: {get_ribbon_name(ribbon_type)},Remain Ribbon Count: {remain_ribbon_count}")
            return (ribbon_type, remain_ribbon_count)
        elif info_type == 5 or info_type == 6:  # DWORD类型
            result_data = ctypes.cast(info_data, ctypes.POINTER(wintypes.DWORD))[0]
            print(f"printed: {result_data}")
            return result_data
    else:
        raise Exception(f"Error occurred: {result}")


def HITI_DoCommand(printer_name, command):
    result = dll.HITI_DoCommandW(printer_name, command)
    if result == 0:
        print(f"命令执行成功，返回值: {result}")
        return True
    else:
        print(f"命令执行失败，错误码: {result}")
        return False
    

