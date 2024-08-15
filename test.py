import threading
import HITI_SDK
from HiTiPrinterMsgReceiver import create_window, get_hwnd
from config import cfg
from dataModel import HITI_DS, HITI_JOB_PROPERTY_RT, InfoType
HITI_SDK.HITI_CheckPrinterStatus("HiTi P520L")
HITI_SDK.HITI_GetDeviceInfo("HiTi P520L",1)
# HITI_SDK.HITI_DoCommand("HiTi P520L",100)









print(HITI_DS.HITI_DS_OFFLINE)
