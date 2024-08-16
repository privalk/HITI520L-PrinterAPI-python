import ctypes
from ctypes import  c_void_p, c_wchar_p, sizeof, wintypes,windll, byref, create_unicode_buffer
import threading
import time
from tkinter import Tk
from config import cfg
from dataModel import BITMAP, HITI_DS, HITI_JOB_PROPERTY_RT
from utility import  get_HITI_DS_name, get_bmp_from_image, get_ribbon_name


dll_path=cfg['DLL_PATH']
dll=ctypes.WinDLL(dll_path)

#函数定义
dll.HITI_CheckPrinterStatusW.restype = wintypes.DWORD
dll.HITI_CheckPrinterStatusW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
status = wintypes.DWORD()

dll.HITI_ApplyJobSettingW.restype = wintypes.DWORD
dll.HITI_ApplyJobSettingW.argtypes = [wintypes.LPWSTR, wintypes.HDC, wintypes.LPVOID, wintypes.LPVOID]

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

def HITI_ApplyJobSetting(printer_name,JobProp):
    
    hDC = ctypes.windll.gdi32.CreateDCW("WINSPOOL", printer_name, None, None)  # 创建打印机DC
    # lpInDevMode 需要为0
    lpInDevMode = None  # 必须为0   .
    result = dll.HITI_ApplyJobSettingW(printer_name, hDC, lpInDevMode, ctypes.byref(JobProp))
    if result == 0:
        print("Job setting applied successfully.")
    else:
        print(f"Failed to apply job setting. Error code: {result}")
    ctypes.windll.gdi32.DeleteDC(hDC)  # 删除打印机DC

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
            print(f"DWORD: {result_data}")
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
    

def DoPrintJob(printer_name,image_path,_dwPaperType,_shOrientation,_shCopies=1,_dwPrintMode=0,_dwApplyMatte=0):
    """
    打印一张图片
    Args:
        printer_name: 打印机名称
        image_path: 图片路径
        _dwPaperType: 纸张类型 见HITI_PAPER_TYPE
        _dwPrintMode: 打印模式 0为Standard模式, 1为Fine模式
        _shOrientation: 打印方向 1:纵向 2:横向
        _shCopies: 打印份数
        _dwApplyMatte: 是否应用雾面 0:不应用 1:应用
    Returns:
        0: 打印完毕
    """
    #检测打印机状态
    dwError=HITI_CheckPrinterStatus(printer_name)
    if dwError==HITI_DS.HITI_DS_OFFLINE.value:
        print("打印机离线")
        return HITI_DS.HITI_DS_OFFLINE.name

    #检测打印机是否正在打印
    dwError=HITI_DS.HITI_DS_BUSY.value
    while dwError==HITI_DS.HITI_DS_BUSY.value:
        dwError=HITI_CheckPrinterStatus(printer_name)
        if dwError==HITI_DS.HITI_DS_OFFLINE.value:
            print("打印机离线")
            return HITI_DS.HITI_DS_OFFLINE.name
        elif dwError==HITI_DS.HITI_DS_BUSY.value:
            time.sleep(2)
        elif dwError!=HITI_DS.HITI_DS_IDLE.value:
            dwError_name=get_HITI_DS_name(dwError)
            print(f"打印机状态异常,{dwError_name}")
            return dwError_name

    #开始打印
    bitmap = get_bmp_from_image(image_path)
    # bitmap = load_image_as_bitmap(image_path,_dwPaperType)
    JobProp=HITI_JOB_PROPERTY_RT()
    JobProp.dwSize=sizeof(HITI_JOB_PROPERTY_RT)
    JobProp.dwPrintMode=_dwPrintMode
    JobProp.shOrientation=_shOrientation
    JobProp.shCopies=_shCopies
    JobProp.dwPaperType=_dwPaperType
    JobProp.dwApplyMatte=_dwApplyMatte
    # HITI_ApplyJobSetting(printer_name,JobProp)
    szPrinterName = create_unicode_buffer(printer_name)  
    dwError = dll.HITI_PrintOnePageW(szPrinterName,ctypes.byref(JobProp),ctypes.byref(bitmap))
    if dwError!=HITI_DS.HITI_DS_IDLE.value:
        dwError_name=get_HITI_DS_name(dwError)
        print(f"打印机状态异常,{dwError_name}")
        return dwError_name
    
    #检查打印是否完成
    dwStatus = HITI_DS.HITI_DS_BUSY.value
    while dwStatus != HITI_DS.HITI_DS_IDLE.value:
        dwStatus = HITI_CheckPrinterStatus(printer_name)
        if dwStatus == HITI_DS.HITI_DS_PRINTING.value:
            time.sleep(3)
        elif dwStatus==HITI_DS.HITI_DS_IDLE.value:
            print("打印完成")
        else:
            return get_HITI_DS_name(dwStatus)






    




