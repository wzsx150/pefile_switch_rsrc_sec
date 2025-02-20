# -*- coding: utf-8 -*-
import os
import sys
import pefile

# 读取PE文件的重定向表工具 v1.0-20250221  by wzsx150 
# 推荐使用 Python 3.10 以上版本运行该脚本，不支持 Python 2。需要安装相关库。

def print_relocation_info(dll_path, start_offset, end_offset):
    try:
        # 加载 DLL 文件
        pe = pefile.PE(dll_path)
    except Exception as e:
        print(f"加载文件错误：{e}")
        sys.exit(1)

    try:
        # 检查是否存在重定位表
        if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            print("重定位表信息:")
            for reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                # 使用 struct 属性获取 RVA 和块大小
                rva = reloc.struct.VirtualAddress
                size = reloc.struct.SizeOfBlock
                # 一个块的大小应该是（8 + 2 * 条目数）。
                
                # 输出指定的范围的重定向表项
                if (end_offset is None and rva >= start_offset) or (end_offset is not None and start_offset <= rva <= end_offset):
                    print(f"  重定位表 RVA: {hex(rva)}, 块大小: {size} 字节")
                    # 遍历重定位信息
                    for i, entry in enumerate(reloc.entries):
                        # 获取重定位类型和偏移
                        reloc_type = entry.type
                        reloc_offset = entry.rva
                        
                        # 输出重定位条目的十六进制表示
                        # 这里我们将 RVA 和类型组合成一个字节串
                        entry_data = (reloc_offset & 0xFFF) | (reloc_type << 12)
                        block_off = (reloc_offset & 0xFFF)
                        print(f"    第{i:04}条，重定位类型: {reloc_type}, 总偏移: {hex(reloc_offset)}, 块内偏移: {hex(block_off)}, 值: {hex(entry_data)}")
        else:
            print("该 DLL 文件没有重定位表。")
    except Exception as e:
        print(f"获取重定位表错误：{e}")
        sys.exit(2)

def parse_offset(offset_str):
    """解析偏移量，支持十进制和十六进制格式"""
    if offset_str.startswith("0x"):
        return int(offset_str, 16)  # 解析十六进制
    elif offset_str == "":
        return None  # 返回 None 表示省略
    else:
        return int(offset_str)  # 解析十进制

def main():
    # 检查参数数量
    if len(sys.argv) == 3:
        offset_range = sys.argv[2]
    else:
        print("用法: python script.py <pe_file> <开始输出的偏移量>:<结束输出的偏移量>\n开始偏移量不填表示从头就输出，结束偏移量不填表示一直到文件尾都输出。\n")
        sys.exit(1)

    pe_file = sys.argv[1]

    if not os.path.isfile(pe_file):
        print(f"错误，找不到文件: {pe_file}")
        sys.exit(1)

    # 分割偏移量
    try:
        start_offset_str, end_offset_str = offset_range.split(':')
        start_offset = parse_offset(start_offset_str)
        end_offset = parse_offset(end_offset_str)
    except Exception as e:
        print("偏移量格式错误，请使用 <开始输出的偏移量>:<结束输出的偏移量> 格式。\n支持十六进制和十进制表示。")
        sys.exit(1)

    # 处理省略的偏移量
    is_max = False
    if start_offset is None:
        start_offset = 0  # 如果省略左边，默认为 0
    if end_offset is None:
        is_max = True
    elif end_offset < start_offset:
        print("输入的偏移量错误，<结束输出的偏移量> 应大于等于 <开始输出的偏移量>")
        sys.exit(1)

    # 输出获取的参数
    print(f"PE 文件: {pe_file}")
    print(f"指定的开始输出的偏移量: {start_offset:#x}")  # 以十六进制格式输出
    print(f"指定的结束输出的偏移量: {'文件结尾' if is_max else hex(end_offset)}")  # 处理无穷大情况
    
    print_relocation_info(pe_file, start_offset, end_offset)

if __name__ == "__main__":
    print("查看 PE 文件重定向表工具")
    print("请确认 PE 文件是完整无损坏。")
    print("")
    main()
