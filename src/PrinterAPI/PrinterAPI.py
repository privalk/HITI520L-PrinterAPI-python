import time
from . import HITI_SDK
import win32print

from dataModel import HITI_COMMAND, HITI_DEVINFO, HITI_DS, PAPER_SIZE
from utility import get_HITI_DS_name

import win32print
import win32ui
from PIL import Image, ImageWin

import threading

from config import cfg

class PrinterAPI:
    """
    使用print_name 初始化
    """
    printer_name=cfg['PRINTER_NAME']

    @staticmethod
    def do_print(image_path,_shOrientation,_dwPaperType=PAPER_SIZE.PAPER_SIZE_6X4,_shCopies=1):
        """
        打印图片
        Args:
            image_path: 图片路径
            _dwPaperType: 纸张类型 见PAPER_SIZE
            _shOrientation: 打印方向   1:纵向  2:横向 
            _shCopies: 打印份数
    
        Returns:
            0: 打印完毕
        """
        #检测打印机状态
        dwError=HITI_SDK.HITI_CheckPrinterStatus(PrinterAPI.printer_name)
        if dwError==HITI_DS.HITI_DS_OFFLINE.value:
            print("打印机离线")
            return HITI_DS.HITI_DS_OFFLINE.name

        #检测打印机是否正在打印
        dwError=HITI_DS.HITI_DS_BUSY.value
        while dwError==HITI_DS.HITI_DS_BUSY.value:
            dwError=HITI_SDK.HITI_CheckPrinterStatus(PrinterAPI.printer_name)
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
        hPrinter = win32print.OpenPrinter(PrinterAPI.printer_name,{"DesiredAccess": win32print.PRINTER_ALL_ACCESS})
        printer_info = win32print.GetPrinter(hPrinter, 2)
        devmode = printer_info['pDevMode']
        devmode.Orientation = _shOrientation  
        devmode.Copies = _shCopies
        devmode.PaperSize = _dwPaperType
        printer_info['pDevMode'] = devmode
        win32print.SetPrinter(hPrinter, 2, printer_info, 0)

        hDC = win32ui.CreateDC()
        hDC.CreatePrinterDC(PrinterAPI.printer_name)
        printer_size = hDC.GetDeviceCaps(110), hDC.GetDeviceCaps(111)

        # 打开图像并调整大小
        img = Image.open(image_path)
        img = img.resize(printer_size, Image.LANCZOS)
        
        # 启动打印作业
        hDC.StartDoc("Print Job")
        hDC.StartPage()

        # 将图像绘制到打印机设备上下文
        dib = ImageWin.Dib(img)
        dib.draw(hDC.GetHandleOutput(), (0, 0, printer_size[0], printer_size[1]))

        # 结束页面和打印作业
        hDC.EndPage()
        hDC.EndDoc()

        # 删除设备上下文并关闭打印机
        hDC.DeleteDC()
        win32print.ClosePrinter(hPrinter)

        #检查打印是否完成
        time.sleep(5)
        dwStatus = HITI_DS.HITI_DS_BUSY.value
        while dwStatus != HITI_DS.HITI_DS_IDLE.value:
            dwStatus = HITI_SDK.HITI_CheckPrinterStatus(PrinterAPI.printer_name)
            if dwStatus == HITI_DS.HITI_DS_PRINTING.value:
                time.sleep(3)
            elif dwStatus==HITI_DS.HITI_DS_IDLE.value:
                print("打印完成")
                return 0
            else:
                return get_HITI_DS_name(dwStatus)
            
    @staticmethod
    def printer_heart_beat():
        """
        打印机心跳
        """ 
        while True:
            status = HITI_SDK.HITI_CheckPrinterStatus(PrinterAPI.printer_name)
            
            # 等待一段时间后再次检查
            time.sleep(3)  # 每5秒检查一次打印机状态

    # 使用子线程运行心跳检查
    @staticmethod
    def run_printer_heart_beat_in_thread():
        thread = threading.Thread(target=PrinterAPI.printer_heart_beat, args=(PrinterAPI.printer_name,))
        thread.daemon = True  
        thread.start()
        return thread


    @staticmethod
    def do_reset_printer():
        """
        重置打印机

        """
        HITI_SDK.HITI_DoCommand(PrinterAPI.printer_name,HITI_COMMAND.HITI_COMMAND_RESET_PRINTER)
    @staticmethod
    def do_cut_paper():
        """
        切纸
        """
        HITI_SDK.HITI_DoCommand(PrinterAPI.printer_name,HITI_COMMAND.HITI_COMMAND_CUT_PAPER)
    @staticmethod
    def get_ribbon_info():
        """
        获取纸张信息
        """
        HITI_SDK.HITI_GetDeviceInfo(PrinterAPI.printer_name,HITI_DEVINFO.HITI_DEVINFO_RIBBON_INFO)
    @staticmethod
    def get_print_count():
        """
        获取打印计数
        """
        HITI_SDK.HITI_GetDeviceInfo(PrinterAPI.printer_name,HITI_DEVINFO.HITI_DEVINFO_PRINT_COUNT)
