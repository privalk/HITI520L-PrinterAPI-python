import threading
import win32gui
import win32con
import ctypes
from ctypes import wintypes

# 定义消息常量
WM_HITI_PRINTER = 0x5555
MSG_JOB_BEGIN = 1
MSG_PRINT_ONE_PAGE = 3
MSG_PRINT_ONE_COPY = 4
MSG_JOB_END = 6
MSG_DEVICE_STATUS = 7
MSG_JOB_CANCELED = 12
hwnd = None

# 定义处理函数
def message_handler(hwnd, msg, wparam, lparam):
    if msg == WM_HITI_PRINTER:
        if wparam == MSG_JOB_BEGIN:
            print(f"Job Begin: Spooler ID {lparam}")
        elif wparam == MSG_PRINT_ONE_PAGE:
            print(f"Printing Page: Page number {lparam}")
        elif wparam == MSG_PRINT_ONE_COPY:
            print(f"Printing Copy: Copy number {lparam}")
        elif wparam == MSG_JOB_END:
            print(f"Job End: Spooler ID {lparam}")
        elif wparam == MSG_DEVICE_STATUS:
            print(f"Device Status: Status Code {lparam}")
        elif wparam == MSG_JOB_CANCELED:
            print(f"Job Canceled: Spooler ID {lparam}")
    else:
        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)
    return 0

# 注册窗口类和创建窗口的函数
def create_window():
    print("create window")
    wc = win32gui.WNDCLASS()
    wc.lpfnWndProc = message_handler
    wc.hInstance = win32gui.GetModuleHandle(None)
    wc.lpszClassName = "HiTiPrinterMessageWindow"

    class_atom = win32gui.RegisterClass(wc)
    global hwnd 
    hwnd = win32gui.CreateWindow(class_atom, "HiTiPrinterMessageWindow", 0, 0, 0, 0, 0, 0, 0, wc.hInstance, None)
    print(hwnd)
    # 主消息循环
    listening_thread = threading.Thread(target=win32gui.PumpMessages)
    listening_thread.daemon = True 
    listening_thread.start()
def get_hwnd():
    return hwnd

