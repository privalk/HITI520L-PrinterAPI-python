from ctypes import POINTER, c_char, c_char_p, c_ubyte, c_uint32, c_void_p, cast, memmove, windll, wintypes
import ctypes
import io
from PIL import Image
import numpy as np
import pefile
import win32print

from dataModel import BITMAP, HITI_DS, RibbonType
# 加载图片并转换为位图
@staticmethod
def get_bmp_from_imageo(image_path,paper_type,_shOrientation,for_first_half_page=True):
    # 设置不同纸张类型的宽度和高度
    if _shOrientation == 1:
        paper_dimensions = {
            0: (1240, 1844),   # 6x4
            1: (2434, 1844),   # 6x8
            2: (2740, 1844),   # 6x9
            3: (1240, 1844),   # 6x9 split 2up tile2
            4: (2104, 1504),   # 5x7
            5: (1240, 1844),   # 4x6 split 2up
            6: (1236, 2464),   # 8x4
            7: (1836, 2464),   # 8x6
            8: (2436, 2464),   # 8x8
            9: (3636, 2464),   # 8x12
        }
    elif _shOrientation == 2:
        paper_dimensions = {
            0: (1844, 1240),   # 6x4
            1: (1844, 2434),   # 6x8
            2: (1844, 2740),   # 6x9
            3: (1844, 1240),   # 6x9 split 2up tile2
            4: (1504, 2104),   # 5x7
            5: (1844, 1240),   # 4x6 split 2up
            6: (2464, 1236),   # 8x4
            7: (2464, 1836),   # 8x6
            8: (2464, 2436),   # 8x8
            9: (2464, 3636),   # 8x12
        }

    edge_width, edge_height = paper_dimensions.get(paper_type, (1844, 1240))
    page_width, page_height = paper_dimensions.get(paper_type, (1844, 1240))

    # 打开图像
    image = Image.open(image_path)

    # 设置目标图像的尺寸
    if for_first_half_page:
        dst_width, dst_height = page_width, page_height
    else:
        dst_width, dst_height = edge_width, edge_height

    # 调整图像大小
    resized_image = image.resize((dst_width, dst_height), Image.LANCZOS)
    # 将RGB图像转换为BGR格式
    r, g, b = resized_image.split()
    bgr_image = Image.merge("RGB", (b, g, r))

    # 翻转图像
    bgr_image = bgr_image.transpose(Image.FLIP_TOP_BOTTOM)



    # 计算每行字节数，确保它是4的倍数（位图格式要求）
    # bm_width_bytes = (dst_width * 3 + 3) & ~3  # 3字节表示24位图像 (RGB)，对齐到4字节

    # 获取位图数据
    bmp_data = bgr_image.tobytes()

    # 创建 BITMAP 结构体
    bitmap = BITMAP()
    bitmap.bmType = 0x5250  # 假设的类型值，与原代码一致
    bitmap.bmWidth = dst_width
    bitmap.bmHeight = dst_height
    bitmap.bmWidthBytes = (dst_width * 3 * 2) // 2
    bitmap.bmPlanes = 1
    bitmap.bmBitsPixel = 24
    bitmap.bmBits = cast(c_char_p(bmp_data), c_void_p)  # 转换为指针类型

    return bitmap

import matplotlib.pyplot as plt
def preview_bitmapold(bitmap):
    # 从 BITMAP 结构体中获取数据
    width = bitmap.bmWidth
    height = bitmap.bmHeight
    bm_width_bytes = bitmap.bmWidthBytes

    # 获取图像数据并重构为图像对象
    image_data = ctypes.string_at(bitmap.bmBits, height * bm_width_bytes)  # 从指针获取图像数据
    image = Image.frombytes('RGB', (width, height), image_data, 'raw', 'BGR', bm_width_bytes, 1)

    # 再次翻转图像（因为之前进行了 FLIP_TOP_BOTTOM 操作）
    image = image.transpose(Image.FLIP_TOP_BOTTOM)

    # 显示图像
    image.show()


def preview_bitmap(bitmap):
    # 从 bmBits 中读取图像数据
    image_data = np.ctypeslib.as_array(bitmap.bmBits, (bitmap.bmHeight, bitmap.bmWidthBytes))
    
    # 如果 bmBitsPixel 是24，表示RGB格式，每个像素3个字节
    if bitmap.bmBitsPixel == 24:
        image_data = image_data.reshape((bitmap.bmHeight, bitmap.bmWidth, 3))
    elif bitmap.bmBitsPixel == 32:
        image_data = image_data.reshape((bitmap.bmHeight, bitmap.bmWidth, 4))
    
    # 由于图像通常是从左下角开始的，我们需要将其上下翻转
    image_data = np.flipud(image_data)
    
    # 显示图像
    plt.imshow(image_data)
    plt.axis('off')  # 不显示坐标轴
    plt.show()
@staticmethod
def print_printer_list():
    PRINTER_ENUM_LOCAL = 0x00000002
    printers = win32print.EnumPrinters(PRINTER_ENUM_LOCAL)
    # 输出打印机信息
    for printer in printers:
        print(f"Printer Name: {printer[2]}")
        print(f"Server Name: {printer[1]}")
        print(f"Printer Description: {printer[3]}")
        print('-' * 40)

        
#输出dll函数
@staticmethod
def print_dll_functions(dll_path):
    pe = pefile.PE(dll_path)
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name.decode('utf-8'))

@staticmethod
def get_ribbon_name(value):
    for ribbon in RibbonType:
        if ribbon.value == value:
            return ribbon.name
    return None

@staticmethod
def get_HITI_DS_name(value):
    for hiti_ds in HITI_DS:
        if hiti_ds.value == value:
            return hiti_ds.name
    return None


@staticmethod
def str_to_BITMAP(bmp_bytes):
    # 将字符串解析为字典
    bmp_str = bmp_bytes.decode('utf-8')
    bmp_dict = {}
    for item in bmp_str.split(','):
        key, value = item.split('=')
        bmp_dict[key] = int(value.strip('"'))

    # 构建 BITMAP 结构体实例
    bitmap = BITMAP(
        bmType=bmp_dict['bmType'],
        bmWidth=bmp_dict['bmWidth'],
        bmHeight=bmp_dict['bmHeight'],
        bmWidthBytes=bmp_dict['bmWidthBytes'],
        bmPlanes=bmp_dict['bmPlanes'],
        bmBitsPixel=bmp_dict['bmBitsPixel'],
        bmBits=bmp_dict['bmBits'] 
    )
    return bitmap