# -*- coding: utf-8 -*-
import pefile
import sys
import os
import io
import argparse
import struct


#### Windows PE 文件移动 .rsrc 区段工具 v1.0-20250211  by wzsx150 
# 功能：将 Windows PE 文件的 .rsrc 区段移动到文件的最后，让 .rsrc 变成最后一个区段。也支持资源区段名是其他名称的情况。
# 正常情况下，PE 文件的最后一个区段一般是 .rsrc 区段，当我们修改该区段时，区段大小发生变化，它不会影响其他区段，也不影响程序正常运行。
# 针对 exe、dll 等 PE 文件经过脱壳、解密、或者非标宏汉化等操作后，导致最后一区段不是 .rsrc 区段，此时再修改 .rsrc 区段数据，可能就会导致程序错误或者无法运行。
# 为了解决该问题，编写了 Python 脚本，脚本中有大量的注释和调试语句，方便理解和修改。

## 建议使用 py3.10 运行脚本。
## 由于 pefile 库的版本不同，pe的有些参数或者变量名可能会有所不同。

# 使用方法: pefile_switch_rsrc_sec.py [-o OUTPUT] [-l] [-d] [-h] input_file
#   input_file            输入的 PE 文件路径: *.exe、*.dll 等文件
# 可选参数:
#   -o OUTPUT, --output OUTPUT  输出文件路径，默认为 '<原始文件名>_modsec.<后缀名>'
#   -l, --list            仅显示原始 PE 文件的详细信息, 不做修改和处理
#   -d, --debug           处理过程中，生成临时文件、输出调试信息并写入日志文件
#   -h, --help            显示此帮助信息并退出


null_char = '\x00'
input_file = None
output_file = None
rsrc_section = None
file_size_diff = 0
debug_out = False

def debug_print(*args, debug=False, **kwargs):
    """
    可控的 print 替代函数。
    当 debug_out = True 时，输出到控制台；
    当 debug_out = False 时，不输出任何内容。
    """
    global debug_out
    if debug_out:
        print(*args, **kwargs)  # 仅在 debug = True 时调用真正的 print

def print_basic_info(pe):
    """打印 PE 文件的基本信息"""
    try:
        print("#### 基本信息")
        print(f"PE 文件类型: {'PE32+' if pe.OPTIONAL_HEADER.Magic == 0x20B else 'PE32'}")
        print(f"文件入口点 (EntryPoint): {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"镜像基址 (ImageBase): {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"文件对齐 (FileAlignment): {hex(pe.OPTIONAL_HEADER.FileAlignment)}")
        print(f"节对齐 (SectionAlignment): {hex(pe.OPTIONAL_HEADER.SectionAlignment)}")
        print(f"子系统 (Subsystem): {pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, '未知')}")
        print(f"文件头时间戳 (TimeDateStamp): {pe.FILE_HEADER.TimeDateStamp} (UNIX 时间戳)")
        print(f"区段数量 (NumberOfSections): {pe.FILE_HEADER.NumberOfSections}")

        # 计算区段表的起始地址
        section_table_start = (
            pe.DOS_HEADER.e_lfanew +  # DOS Header 的偏移量
            4 +  # PE Signature ("PE\0\0") 的大小
            pe.FILE_HEADER.sizeof() +  # File Header 的大小
            pe.FILE_HEADER.SizeOfOptionalHeader  # Optional Header 的大小
        )
        print(f"区段表起始地址 (Section Table Start): {hex(section_table_start)}")

        # 计算区段表的大小(字节)
        section_table_size = pe.FILE_HEADER.NumberOfSections * 40  # 每个区段描述结构为 40 字节
        print(f"区段表大小 (Section Table Size): {hex(section_table_size)}")

        # 输出可能受区段表影响的字段
        print(f"头部大小 (SizeOfHeaders): {hex(pe.OPTIONAL_HEADER.SizeOfHeaders)}")
        print(f"镜像大小 (SizeOfImage): {hex(pe.OPTIONAL_HEADER.SizeOfImage)}")

    except AttributeError as e:
        print(f"[错误] 获取 PE 基本信息失败: {e}")
    print("")

def print_directory_info(pe):
    """打印 PE 文件的目录信息"""
    try:
        print("#### 目录信息")
        print(f"{'Name':<40} {'VirtualAddr':<13} {'VirtualSize':<13}")
        print("=" * 79)
        for index, directory in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            directory_name = pefile.DIRECTORY_ENTRY.get(index, f"UNKNOWN_{index}")
            print(f"{directory_name:<40} "
                  f"{hex(directory.VirtualAddress):<13} "
                  f"{hex(directory.Size):<13}")
    except AttributeError as e:
        print(f"[错误] 获取目录信息失败: {e}")
    print("=" * 79 + "\n")

def print_section_info(pe):
    """打印 PE 文件的区段信息"""
    print(f"#### 区段信息")
    print(f"{'Name':<10} {'VirtualAddr':<13} {'VirtualSize':<13} {'RawDataAddr':<13} {'RawDataSize':<13} {'Flags':<13}")
    print("=" * 79)
    for section in pe.sections:
        try:
            print(f"{section.Name.decode().rstrip(null_char):<10} "
                  f"{hex(section.VirtualAddress):<13} "
                  f"{hex(section.Misc_VirtualSize):<13} "
                  f"{hex(section.PointerToRawData):<13} "
                  f"{hex(section.SizeOfRawData):<13} "
                  f"{hex(section.Characteristics):<13}")
        except AttributeError as e:
            print(f"[错误] 获取区段属性信息出错: {e}")
            print(f"[信息] 区段原始数据: {section.dump_dict()}")
    print("=" * 79 + "\n")

def print_imports(pe):
    """打印 PE 文件的导入表信息"""
    try:
        print("#### 导入表信息")
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"== 导入的 DLL: {entry.dll.decode()}")
                # 下面几行是输出导入函数的信息
                # print(f"{'函数名':<27} {'函数地址':<13}")
                # for imp in entry.imports:
                    # print(f"{imp.name.decode() if imp.name else 'N/A':<30} "
                          # f"{hex(imp.address):<13}")
        else:
            print("没有导入表信息")
    except AttributeError as e:
        print(f"[错误] 获取导入表信息失败: {e}")
    print("")

def print_exports(pe):
    """打印 PE 文件的导出表信息"""
    try:
        print("#### 导出表信息")
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            print(f"{'导出函数名':<25} {'函数地址':<9} {'序号':<4}")
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print(f"{exp.name.decode() if exp.name else 'N/A':<30} "
                      f"{hex(exp.address):<13} "
                      f"{exp.ordinal:<4}")
        else:
            print("没有导出表信息")
    except AttributeError as e:
        print(f"[错误] 获取导出表信息失败: {e}")
    print("")

def get_file_size_diff(pe):
    '''获取文件实际大小和理论大小之间的差值，理论大小是由区段表计算出来的。有些文件尾部可能多一些数据，或少一些数据'''
    file_size_t = 0
    for section in pe.sections:
        # 轮询每个区段的结束地址
        section_end = section.PointerToRawData + section.SizeOfRawData
        # 更新理论上文件大小
        file_size_t = max(file_size_t, section_end)

    file_size_a = len(pe.__data__)  # 获取文件实际大小，等同于直接获取文件大小
    debug_print(f"[DEBUG] 文件的实际总大小：{hex(file_size_a)}，理论总大小：{hex(file_size_t)}")
    return (file_size_a - file_size_t)

def write_pe_info_to_file(pe, output_filename):
    """
    将 PE 文件的详细信息写入到指定的文件中。
    :param pe: pefile.PE 对象
    :param output_filename: 输出文件名
    """
    # Data Directories 的名称映射
    data_directories_names = [
        "Export Table",          # 0
        "Import Table",          # 1
        "Resource Table",        # 2
        "Exception Table",       # 3
        "Certificate Table",     # 4
        "Base Relocation Table", # 5
        "Debug Directory",       # 6
        "Architecture",          # 7
        "Global Pointer",        # 8
        "TLS Table",             # 9
        "Load Config Table",     # 10
        "Bound Import",          # 11
        "IAT (Import Address Table)", # 12
        "Delay Import Descriptor",   # 13
        "CLR Runtime Header",        # 14
        "Reserved",                  # 15
    ]

    with open(output_filename, 'w', encoding='utf-8') as f:
        # 定义一个写入函数，方便统一输出
        def write_line(line=""):
            f.write(line + "\n")

        # 输出 PEfile 的版本信息
        write_line(f"Python 的 PEfile 库的版本: {pefile.__version__}")
        write_line("=" * 50)

        # DOS Header 信息
        write_line("[DOS Header]")
        write_line(f"Magic: {pe.DOS_HEADER.e_magic}")
        write_line(f"Address of New EXE Header: {hex(pe.DOS_HEADER.e_lfanew)}")
        write_line()

        # NT Headers 信息
        write_line("[NT Headers]")
        write_line(f"Signature: {hex(pe.NT_HEADERS.Signature)}")
        write_line()

        # File Header 信息
        write_line("[File Header]")
        write_line(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
        write_line(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        write_line(f"Time Date Stamp: {hex(pe.FILE_HEADER.TimeDateStamp)}")
        write_line(f"Pointer to Symbol Table: {hex(pe.FILE_HEADER.PointerToSymbolTable)}")
        write_line(f"Number of Symbols: {pe.FILE_HEADER.NumberOfSymbols}")
        write_line(f"Size of Optional Header: {pe.FILE_HEADER.SizeOfOptionalHeader}")
        write_line(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")
        write_line()

        # Optional Header 信息
        write_line("[Optional Header]")
        write_line(f"Magic: {hex(pe.OPTIONAL_HEADER.Magic)}")
        write_line(f"Address of EntryPoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        write_line(f"ImageBase: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        write_line(f"SectionAlignment: {hex(pe.OPTIONAL_HEADER.SectionAlignment)}")
        write_line(f"FileAlignment: {hex(pe.OPTIONAL_HEADER.FileAlignment)}")
        write_line(f"SizeOfImage: {hex(pe.OPTIONAL_HEADER.SizeOfImage)}")
        write_line(f"SizeOfHeaders: {hex(pe.OPTIONAL_HEADER.SizeOfHeaders)}")
        write_line(f"Subsystem: {hex(pe.OPTIONAL_HEADER.Subsystem)}")
        write_line(f"DllCharacteristics: {hex(pe.OPTIONAL_HEADER.DllCharacteristics)}")
        write_line(f"SizeOfStackReserve: {hex(pe.OPTIONAL_HEADER.SizeOfStackReserve)}")
        write_line(f"SizeOfStackCommit: {hex(pe.OPTIONAL_HEADER.SizeOfStackCommit)}")
        write_line(f"SizeOfHeapReserve: {hex(pe.OPTIONAL_HEADER.SizeOfHeapReserve)}")
        write_line(f"SizeOfHeapCommit: {hex(pe.OPTIONAL_HEADER.SizeOfHeapCommit)}")
        write_line(f"LoaderFlags: {hex(pe.OPTIONAL_HEADER.LoaderFlags)}")
        write_line(f"NumberOfRvaAndSizes: {pe.OPTIONAL_HEADER.NumberOfRvaAndSizes}")
        write_line()

        # Data Directories 信息
        write_line("[Data Directories]")
        for i, directory in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            # 获取目录名称，如果超出范围则显示 "Unknown"
            directory_name = data_directories_names[i] if i < len(data_directories_names) else "Unknown"
            write_line(f"Directory {i}: {directory_name}")
            write_line(f"  VirtualAddress: {hex(directory.VirtualAddress)}")
            write_line(f"  Size: {hex(directory.Size)}")
        write_line()

        # Sections 信息
        write_line("[Sections]")
        write_line(f"{'Name':<9} {'Virtual Address':<16} {'Virtual Size':<15} {'Raw Address':<13} {'Raw Size':<13} {'Flags':<13}")
        write_line("=" * 84)
        for section in pe.sections:
            try:
                # 去掉区段名称中的 NUL 字符
                section_name = section.Name.decode().rstrip(null_char)
                write_line(f"{section_name:<9} "
                           f"{hex(section.VirtualAddress):<16} "
                           f"{hex(section.Misc_VirtualSize):<15} "
                           f"{hex(section.PointerToRawData):<13} "
                           f"{hex(section.SizeOfRawData):<13} "
                           f"{hex(section.Characteristics):<13}")
            except AttributeError as e:
                write_line(f"[错误] 读取区段属性出错: {e}")
                write_line(f"区段原始数据: {section.dump_dict()}")
        write_line()

        # Import Table 信息
        write_line("[Import Table]")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            try:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    write_line(f"  DLL: {entry.dll.decode('utf-8')}")
                    for imp in entry.imports:
                        write_line(f"    {hex(imp.address)}: {imp.name.decode('utf-8') if imp.name else 'Ordinal'}")
            except Exception as e:
                write_line(f"[错误] 读取导入表信息出错: {e}")
            write_line()

        # Export Table 信息
        write_line("[Export Table]")
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            try:
                export_name = pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8') if pe.DIRECTORY_ENTRY_EXPORT.name else "N/A"
                number_of_functions = getattr(pe.DIRECTORY_ENTRY_EXPORT, 'NumberOfFunctions', "N/A")
                number_of_names = getattr(pe.DIRECTORY_ENTRY_EXPORT, 'NumberOfNames', "N/A")
                write_line(f"  Export Name: {export_name}")
                write_line(f"  Number of Functions: {number_of_functions}")
                write_line(f"  Number of Names: {number_of_names}")
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exp_name = exp.name.decode('utf-8') if exp.name else "Ordinal"
                    write_line(f"    {hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)}: {exp_name}")
            except Exception as e:
                write_line(f"[错误] 读取导出表信息出错: {e}")
            write_line()

        write_line("=" * 50)
        write_line("PE 文件信息写入完成！")

    debug_print(f"[DEBUG] PE 文件信息已成功写入到文件: {output_filename}")


def align(value, alignment):
    """计算对齐，用于 [文件对齐 (FileAlignment)] 和 [节对齐 (SectionAlignment)]等需要对齐的情况"""
    return (value + alignment - 1) & ~(alignment - 1)



def get_rsrc_section(pe):
    '''查找 PE 文件中资源区段，返回该资源区段。一般是 .rsrc ，但也可能存在特殊情况'''
    global rsrc_section
    try:
        # 获取资源表数据目录
        resource_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
        resource_rva = resource_dir.VirtualAddress
        resource_size = resource_dir.Size
        debug_print(f"[DEBUG] 资源目录信息：resource_rva={hex(resource_rva)}, resource_size={hex(resource_size)}")
                
        # 检查资源目录中是否存在资源表
        if resource_rva == 0 or resource_size == 0:
            debug_print("[DEBUG] 资源目录中不存在资源表，无需修复")
            return None, True
    except Exception as e:
        print(f"[错误] get_rsrc_section() 获取资源表数据目录出错: {e}")
        return None, False

    try:
        # 查找 .rsrc 资源区段或者其他名字的资源区段。这里使用的是资源目录中的虚拟地址来查找资源区段的，该方式比较准确，这样查找出来的资源区段名称可能不一定是 .rsrc 区段。
        # 请确保 PE 文件是完整无误的文件，否则，可能导致这里找到的区段不正确。
        # 查找第一个资源区段，不考虑多个资源区段的情况
        rsrc_section_t = None
        rsrc_section_n = None
        for section in pe.sections:
            debug_print(f"[DEBUG] 扫描区段: Name={section.Name.decode().rstrip(null_char)}, VirtualAddress={hex(section.VirtualAddress)}, SizeOfRawData={hex(section.SizeOfRawData)}")
            if section.VirtualAddress <= resource_rva < section.VirtualAddress + section.Misc_VirtualSize:
                rsrc_section_t = section
            if section.Name.decode().rstrip(null_char) == ".rsrc":
                rsrc_section_n = section
    except Exception as e:
        print(f"[错误] get_rsrc_section() 查找资源区段时出错: {e}")
        return None, False

    if rsrc_section_t is None:
        #### 建议使用这种方式
        debug_print("[DEBUG] 没有找到资源区段")
        return None, True
        
        #### 如果没有找到资源区段，则处理 .rsrc 区段，不建议这么做
        # if rsrc_section_n is None:
            # debug_print("[DEBUG] 没有找到资源区段或 .rsrc 区段")
            # return None
        # else:
            # debug_print("[DEBUG] 没有找到资源区段, 但发现 .rsrc 区段")
            # return rsrc_section_n
    else:
        return rsrc_section_t, True  # 最准确的资源区段


def fix_rsrc_data_entries(file_data, pe, old_rsrc_va, new_rsrc_va):
    """修复 .rsrc 区段数据的 IMAGE_RESOURCE_DATA_ENTRY(资源数据条目) 的 DataRVA(相对虚拟地址) 字段，并返回修复后的 .rsrc 区段数据。"""
    global input_file, output_file, rsrc_section, debug_out
    file_base, file_ext = os.path.splitext(input_file)
    outfile_base, outfile_ext = os.path.splitext(output_file)
    
    try:
        # debug模式时，日志文件保存到当前目录下。否则，输出到假文件。
        log_path = os.path.join(os.getcwd(), f"{file_base}_rc_debug.log")
        log_file = open(log_path, "w", encoding="utf-8") if debug_out else io.StringIO()  # 使用 StringIO 作为假文件
        
        with log_file:
            if rsrc_section is None:
                log_file.write("[DEBUG] 没有找到资源区段\n")
                return None

            log_file.write(f"[DEBUG] 找到资源区段: Name={rsrc_section.Name.decode().rstrip(null_char)}, PointerToRawData={hex(rsrc_section.PointerToRawData)}, SizeOfRawData={hex(rsrc_section.SizeOfRawData)}\n")

            # 从原始文件内容中获取资源区段实际存放的数据，以下两种方法二选一
            # rsrc_data = bytearray(file_data[rsrc_section.PointerToRawData:rsrc_section.PointerToRawData + rsrc_section.SizeOfRawData])  # 方法1，根据文件偏移的内容获取
            rsrc_data = bytearray(pe.get_data(rsrc_section.VirtualAddress, rsrc_section.SizeOfRawData))  # 方法2，根据虚拟地址获取
            
            if debug_out:
                # 将 rsrc 资源区段存放的实际数据写入到如下文件，方便对比查看。
                with open(f"{file_base}_temp_rc.bin", 'wb') as f:
                    f.write(rsrc_data)
            
            if len(rsrc_data) != rsrc_section.SizeOfRawData:
                log_file.write(f"[DEBUG] 警告：提取的 {rsrc_section.Name.decode().rstrip(null_char)} 数据长度 ({len(rsrc_data)}) 与 SizeOfRawData ({rsrc_section.SizeOfRawData}) 不一致\n")
                return None

            log_file.write(f"[DEBUG] 成功提取 {rsrc_section.Name.decode().rstrip(null_char)} 区段数据\n")
            log_file.write(f"[DEBUG] 开始修复 {rsrc_section.Name.decode().rstrip(null_char)} 资源区段\n\n")

            # 定义结构大小
            IMAGE_RESOURCE_DIRECTORY_SIZE = 16  # IMAGE_RESOURCE_DIRECTORY 的大小
            IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE = 8  # IMAGE_RESOURCE_DIRECTORY_ENTRY 的大小
            IMAGE_RESOURCE_DATA_ENTRY_SIZE = 16  # IMAGE_RESOURCE_DATA_ENTRY 的大小

            # 标准资源类型名称
            resource_type_names = {
                1: "RT_CURSOR",
                2: "RT_BITMAP",
                3: "RT_ICON",
                4: "RT_MENU",
                5: "RT_DIALOG",
                6: "RT_STRING",
                7: "RT_FONTDIR",
                8: "RT_FONT",
                9: "RT_ACCELERATOR",
                10: "RT_RCDATA",
                11: "RT_MESSAGETABLE",
                12: "RT_GROUP_CURSOR",
                14: "RT_GROUP_ICON",
                16: "RT_VERSION",
                17: "RT_DLGINCLUDE",
                19: "RT_PLUGPLAY",
                20: "RT_VXD",
                21: "RT_ANICURSOR",
                22: "RT_ANIICON",
                23: "RT_HTML",
                24: "RT_MANIFEST",
            }

            # 验证 RVA 是否有效，因为是相对虚拟地址的偏移，所以减去虚拟地址就是文件中的数据偏移，不可能超过资源区段的总大小
            def is_valid_rva(rva):
                offset = rva - old_rsrc_va
                valid = 0 <= offset < len(rsrc_data)
                log_file.write(f"[DEBUG] 验证 RVA: rva={hex(rva)}, offset={hex(offset)}, valid={valid}\n")
                return valid

            # 提取资源目录的名称或 ID
            def get_entry_name(entry_data):
                name_is_string = struct.unpack("<I", entry_data[0:4])[0] & 0x80000000
                if name_is_string:  # 如果是具名资源
                    name_offset = struct.unpack("<I", entry_data[0:4])[0] & 0x7FFFFFFF

                    # 输出调试信息
                    # log_file.write(f"[DEBUG] NameOffset={hex(name_offset)}\n")

                    # 验证偏移是否有效
                    if 0 <= name_offset < len(rsrc_data):
                        # 读取 IMAGE_RESOURCE_DIR_STRING_U
                        try:
                            name_length = struct.unpack("<H", rsrc_data[name_offset:name_offset + 2])[0]
                            name_string = rsrc_data[name_offset + 2:name_offset + 2 + name_length * 2].decode('utf-16le', errors='ignore')
                            # log_file.write(f"[DEBUG] 解析名称成功: {name_string}\n")
                            return f"{name_string}"
                        except Exception as e:
                            # log_file.write(f"[ERROR] 无法解析名称: {e}\n")
                            return "Invalid Name (Parsing Error)"
                    else:
                        # log_file.write(f"[ERROR] NameOffset 超出范围: name_offset={hex(name_offset)}\n")
                        return "Invalid Name Offset"
                else:  # 如果是按 ID 索引的资源
                    entry_id = struct.unpack("<I", entry_data[0:4])[0]
                    resource_name = resource_type_names.get(entry_id, f"{entry_id}")
                    # log_file.write(f"[DEBUG] 解析 ID 成功: {resource_name}\n")
                    return resource_name

            # 递归解析资源表，资源目录是相对文件区段偏移，所以不需要修改；资源数据是相对虚拟地址偏移，所以需要进行修改，否则移动区段后无法读取到资源数据。
            def parse_resource_directory(offset, level=0, max_depth=10, pre_lvl_str=''):
                if level > max_depth:
                    log_file.write(f"[DEBUG] 超过递归最大深度: level={level}, max_depth={max_depth}\n")
                    return

                # log_file.write(f"[DEBUG] {'--' * level}正在解析资源目录: offset={hex(offset)}, level={level}\n")
                # 读取 IMAGE_RESOURCE_DIRECTORY
                resource_dir_data = rsrc_data[offset:offset + IMAGE_RESOURCE_DIRECTORY_SIZE]
                if len(resource_dir_data) < IMAGE_RESOURCE_DIRECTORY_SIZE:
                    log_file.write(f"[DEBUG] 无效的资源目录偏移: {hex(offset)}\n")
                    return

                # 输出资源目录的基本属性
                characteristics, timestamp, major_version, minor_version = struct.unpack("<I I H H", resource_dir_data[0:12])
                log_file.write(f"[DEBUG] {'--' * level}资源目录属性: level={level}, Characteristics={hex(characteristics)}, TimeStamp={hex(timestamp)}, MajorVersion={major_version}, MinorVersion={minor_version}\n")

                # 读取资源目录下的条目数量
                number_of_named_entries, number_of_id_entries = struct.unpack("<HH", resource_dir_data[12:16])
                total_entries = number_of_named_entries + number_of_id_entries
                log_file.write(f"[DEBUG] {'--' * level}资源目录下的条目数量: named={number_of_named_entries}, id={number_of_id_entries}, total={total_entries}\n")
                

                # 解析资源目录下的每个条目
                entry_offset = offset + IMAGE_RESOURCE_DIRECTORY_SIZE
                for i in range(total_entries):
                    entry_data = rsrc_data[entry_offset:entry_offset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE]
                    if len(entry_data) < IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE:
                        log_file.write(f"[DEBUG] {'--' * (level+1)}无效的资源目录条目偏移: {hex(entry_offset)}\n")
                        continue

                    # 获取条目的名称或 ID
                    entry_name = get_entry_name(entry_data)
                    log_file.write(f"[DEBUG] {'--' * (level+1)}条目 {pre_lvl_str}{i} 名称或ID: {entry_name}\n")

                    # 检查是否是子目录
                    data_is_directory = struct.unpack("<I", entry_data[4:8])[0] & 0x80000000
                    subdir_rva = struct.unpack("<I", entry_data[4:8])[0] & 0x7FFFFFFF
                    log_file.write(f"[DEBUG] {'--' * (level+1)}条目 {pre_lvl_str}{i} 信息: data_is_directory={bool(data_is_directory)}, subdir_rva={hex(subdir_rva)}\n")

                    if data_is_directory:
                        # 如果是子目录，递归解析
                        subdir_offset = subdir_rva
                        if 0 <= subdir_offset < len(rsrc_data):
                            log_file.write(f"[DEBUG] {'--' * (level+1)}子目录偏移: subdir_offset={hex(subdir_offset)}\n")
                            parse_resource_directory(subdir_offset, level + 1, pre_lvl_str=pre_lvl_str+f'{i}/')
                        else:
                            log_file.write(f"[ERROR] {'--' * (level+1)}子目录偏移无效: subdir_offset={hex(subdir_offset)}\n")
                    else:
                        # 如果是资源数据条目，进行解析和修复
                        data_entry_offset = subdir_rva
                        if 0 <= data_entry_offset < len(rsrc_data):
                            log_file.write(f"[DEBUG] {'--' * (level+1)}数据条目偏移: data_entry_offset={hex(data_entry_offset)}\n")
                            fix_resource_data_entry(data_entry_offset, level+1)
                        else:
                            log_file.write(f"[ERROR] {'--' * (level+1)}数据条目偏移无效: data_entry_offset={hex(data_entry_offset)}\n")

                    # 移动到下一个条目
                    entry_offset += IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
                log_file.write(f"\n")


            # 解析并修复 IMAGE_RESOURCE_DATA_ENTRY (资源数据) 的相对虚拟地址
            def fix_resource_data_entry(offset, level):
                # 检查偏移是否有效
                if offset < 0 or offset + IMAGE_RESOURCE_DATA_ENTRY_SIZE > len(rsrc_data):
                    log_file.write(f"[DEBUG] {'--' * (level)}无效的资源数据条目偏移: {hex(offset)}\n")
                    return

                # 读取 IMAGE_RESOURCE_DATA_ENTRY 是否有效
                data_entry = rsrc_data[offset:offset + IMAGE_RESOURCE_DATA_ENTRY_SIZE]
                if len(data_entry) < IMAGE_RESOURCE_DATA_ENTRY_SIZE:
                    log_file.write(f"[DEBUG] {'--' * (level)}无效的资源数据条目数据: {hex(offset)}\n")
                    return

                # 读取资源数据的各个字段
                data_rva, size, code_page, reserved = struct.unpack("<I I I I", data_entry)
                log_file.write(f"[DEBUG] {'--' * (level)}资源数据条目属性: DataRVA={hex(data_rva)}, Size={hex(size)}, CodePage={code_page}, Reserved={reserved}\n")
                
                # 修复资源数据条目的 rva (相对虚拟地址)，将修复后的 DataRVA 写回 rsrc_data
                fixed_data_rva = data_rva - old_rsrc_va + new_rsrc_va  # 修复原理很简单，因为它是相对虚拟地址的偏移，所以修改为相对新虚拟地址的偏移就行了。
                struct.pack_into("<I", rsrc_data, offset, fixed_data_rva)
                log_file.write(f"[DEBUG] {'--' * (level)}[修复] 已将 DataRVA={hex(fixed_data_rva)} 写入偏移位置: data_entry_offset={hex(offset)}\n")


            ## 开始解析和处理资源区段中的资源条目
            parse_resource_directory(0)
            log_file.write("[DEBUG] 修复完成\n")
            
            if debug_out:
                #将修复后的资源区段存放的实际数据写入到如下文件，方便对比查看。
                temp_file = f"{outfile_base}_temp_rc.bin"
                with open(temp_file, 'wb') as f:
                    f.write(rsrc_data)
                debug_print(f"[DEBUG] 将修复后的 {rsrc_section.Name.decode().rstrip(null_char)} 区段数据写入临时文件: {temp_file}")
            
            # 返回修复后的资源区段中实际存放的数据
            return rsrc_data
    except Exception as e:
        print(f"[错误] 修复资源表出错，错误信息: {e}")
        return None


def move_rsrc_section_to_end(input_file, output_file):
    '''将资源区段(一般是 .rsrc 区段)的数据移动到 PE 文件最后一个区段，并删除原来的资源区段'''
    global debug_out, rsrc_section, file_size_diff
    file_base, file_ext = os.path.splitext(input_file)
    outfile_base, outfile_ext = os.path.splitext(output_file)
    file_data_tail_unknown = b''  # 文件尾多余的数据内容
    file_data_tail_unknown_size = 0  #文件尾多余的数据大小
    
    try:
        # 读取原始 PE 文件
        pe = pefile.PE(input_file)
    except pefile.PEFormatError as e:
        print(f"[错误] 文件'{input_file}'不是有效的 PE 文件或文件损坏，错误信息: {e}")
        return False
    except Exception as e:
        print(f"[错误] 读取文件'{input_file}'出错，错误信息: {e}")
        return False

    try:
        # 读取原始文件数据
        with open(input_file, 'rb') as f:
            file_data = f.read()
        if file_size_diff < 0:
            # 在文件的末尾增加 缺少的 \x00 空字节，将文件实际长度不足的时候，直接补足，让实际大小和理论大小保持一致
            file_data += b'\x00' * (0 - file_size_diff)
        if file_size_diff > 0:
            # 将文件末尾多余的未识别的字节认为是类似于签名信息，资源区段移动完成后，还是把这些字节放在文件的最后
            file_data_tail_unknown = file_data[-file_size_diff:]
            file_data_tail_unknown_size = len(file_data_tail_unknown)
            debug_print(f"[DEBUG] 提取文件末尾多余的数据大小：{hex(file_data_tail_unknown_size)}")
    except Exception as e:
        print(f"[错误] 读取文件'{input_file}'出错，错误信息: {e}")
        return False

    try:
        if debug_out:
            # 调试：输出原始 PE 文件基本信息
            write_pe_info_to_file(pe, f"{file_base}_PE信息.txt")
    except Exception as e:
        print(f"[错误] 输出原始 PE 文件基本信息出错，错误信息: {e}")
        return False
        
    try:
        # 获取文件对齐、节对齐(区段对齐)的值
        file_alignment = pe.OPTIONAL_HEADER.FileAlignment
        section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

        # 查找 .rsrc 资源区段，也可能不叫 .rsrc 的名字
        rsrc_section, no_err = get_rsrc_section(pe)
        if rsrc_section is None and no_err == True:
            print("原文件中不存在资源区段或资源表，无需修复")
            return False
        elif rsrc_section is None:
            print("[错误] 找不到资源区段")
            return False
        else:
            print(f"[信息] 找到资源区段 '{rsrc_section.Name.decode().rstrip(null_char)}'")

        # 将区段表按照 虚拟地址 从小到大 进行排序，这样可以兼容一些特殊 PE 文件
        all_sections_vir = sorted(pe.sections, key=lambda x: x.VirtualAddress)
        # 将区段表按照 在文件中的偏移 从小到大 进行排序，这样可以兼容一些特殊 PE 文件
        all_sections_raw = sorted(pe.sections, key=lambda x: x.PointerToRawData)
        
        rsrc_section_index = -1
        for i, section in enumerate(all_sections_vir):
            if section.Name == rsrc_section.Name:
                rsrc_section_index = i
                break
        if rsrc_section_index == -1:
            print("[错误] 找不到资源区段，查找区段索引出错")
            return False

        print("[原始文件]资源区段信息:")
        print(f"  名称: {rsrc_section.Name.decode().rstrip(null_char)}")
        print(f"  虚拟地址: {hex(rsrc_section.VirtualAddress)}")
        print(f"  虚拟大小: {hex(rsrc_section.Misc_VirtualSize)}")
        print(f"  在文件中的偏移: {hex(rsrc_section.PointerToRawData)}")
        print(f"  在文件中的大小: {hex(rsrc_section.SizeOfRawData)}")
        print(f"  属性: {hex(rsrc_section.Characteristics)}")
        print("")

        # 如果资源区段已经是最后一个区段了，那就不需要进行移动。
        if all_sections_vir[-1].Name == rsrc_section.Name:
            print("[信息] 原始文件的最后一个区段就是资源区段，无需调整。")
            return False

        # 计算移动后的新的 VirtualAddress 和 PointerToRawData
        new_virtual_address = align(all_sections_vir[-1].VirtualAddress + all_sections_vir[-1].Misc_VirtualSize, section_alignment)
        # 在文件中的偏移，因为只是将资源区段移动到文件的末尾，正常情况，文件总大小应该不会产生变化。
        # 这里考虑了文件尾有多余文件的情况。若其他原因导致变化，也可以在这里修正。
        new_raw_address = align((len(file_data) - rsrc_section.SizeOfRawData - file_data_tail_unknown_size), file_alignment)

        # 创建新的资源区段的元数据
        new_rc_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
        new_rc_section.__unpack__(rsrc_section.__pack__())  # 复制原区段元数据
        new_rc_section.set_file_offset(pe.sections[-1].get_file_offset() + 0x28)  # 每个区段表占 0x28 字节

        # 修改新的资源区段的元数据
        new_rc_section.VirtualAddress = new_virtual_address
        new_rc_section.PointerToRawData = new_raw_address
        new_rc_section.Characteristics = rsrc_section.Characteristics
        
        # 修复移动后的资源区段的数据，这样就得到了新的资源区段的数据
        new_section_data = fix_rsrc_data_entries(file_data, pe, rsrc_section.VirtualAddress, new_virtual_address)
        if new_section_data is None:
            # print("[错误] 修复资源表出错")
            return False
        if len(new_section_data) != rsrc_section.SizeOfRawData:
            print("[警告] 资源区段的长度修改前后不一致，可能存在问题")

        # 继续修改新的资源区段的元数据
        new_rc_section.SizeOfRawData = align(len(new_section_data), file_alignment)
        new_rc_section.Misc_VirtualSize = rsrc_section.Misc_VirtualSize

        print("")
        print("[预计修改]资源区段信息:")
        print(f"  名称: {new_rc_section.Name.decode().rstrip(null_char)}")
        print(f"  虚拟地址: {hex(new_rc_section.VirtualAddress)}")
        print(f"  虚拟大小: {hex(new_rc_section.Misc_VirtualSize)}")
        print(f"  在文件中的偏移: {hex(new_rc_section.PointerToRawData)}")
        print(f"  在文件中的大小: {hex(new_rc_section.SizeOfRawData)}")
        print(f"  属性: {hex(new_rc_section.Characteristics)}")
        print("")

        # 将修复后资源区段数据追加到文件内容的末尾，考虑文件尾有多余数据的情况
        if file_size_diff > 0:
            file_data = file_data[:-file_data_tail_unknown_size] + new_section_data + file_data_tail_unknown
        else:
            file_data += new_section_data
        print(f"[信息] 修复后的资源区段数据追加到文件末尾，新区段大小: {hex(len(new_section_data))}")

        # 从文件内容中移除原资源区段的数据
        start = rsrc_section.PointerToRawData
        end = rsrc_section.PointerToRawData + rsrc_section.SizeOfRawData
        file_data = file_data[:start] + file_data[end:]
        print(f"[信息] 移除原资源区段数据，文件偏移范围: {hex(start)} - {hex(end)} ，需要更新它后面的区段的信息")

        # 更新其他区段的 PointerToRawData ，按照在文件中偏移排序，大于原资源区段的区段都需要修改
        for section in all_sections_raw:
            if section.PointerToRawData > start:
                section.PointerToRawData -= (end - start)
                print(f"[信息] -- 更新区段 {section.Name.decode().rstrip(null_char)} 的在文件中的偏移地址：PointerToRawData={hex(section.PointerToRawData)}")

        # 更新原资源区段的上一个区段的虚拟大小
        # 理论上虚拟地址空间是连续的，所以当我们删除其中一个区段时，需要将被删除位置的虚拟空间分配给他上一个区段。若不这样修复，会导致程序无法运行。如果有其他特殊情况的 PE 文件，估计本脚本可能不支持。
        all_sections_vir = list(all_sections_vir)  # 获取所有区段
        all_sections_vir[rsrc_section_index -1].Misc_VirtualSize = all_sections_vir[rsrc_section_index +1].VirtualAddress - all_sections_vir[rsrc_section_index -1].VirtualAddress

        # 将新的资源区段添加到区段表末尾
        del all_sections_vir[rsrc_section_index]  # 删除原资源区段信息
        all_sections_vir.append(new_rc_section)  # 将更新后的资源区段添加到末尾

        # 计算区段表的总长度，理论上只是调整区段表中的资源区段的位置，区段表的总长度是不会发生变化的。
        # 如果区段表长度发生变化，有可能需要调整所有区段的在文件中的偏移地址
        original_section_table_size = len(pe.sections) * 0x28  # 每个区段表占 0x28 字节
        new_section_table_size = len(all_sections_vir) * 0x28

        # 如果区段表长度不一致，要么有问题，要么需要更新处理代码
        if not new_section_table_size == original_section_table_size:
            print(f"[错误] 区段表的长度修改前后不一致，请检查原文件是否正确。")
            return False

        # 更新 pe.sections 区段表。这里的赋值，只是内存中的 pe 对象的数据发生改变，他并不会写入实际文件。
        pe.sections = all_sections_vir  # 替换 pe.sections 为更新后的区段列表

        # 更新 PE 文件头信息
        pe.FILE_HEADER.NumberOfSections = len(all_sections_vir)  # 更新区段数量，应该是没有变化
        pe.OPTIONAL_HEADER.SizeOfImage = align(all_sections_vir[-1].VirtualAddress + all_sections_vir[-1].Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)
        print(f"[信息] 文件头中的镜像大小已更新: SizeOfImage={hex(pe.OPTIONAL_HEADER.SizeOfImage)}")
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].VirtualAddress = new_rc_section.VirtualAddress
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size = new_rc_section.Misc_VirtualSize
        print(f"[信息] 文件头中资源表入口地址已更新: VirtualAddress={hex(new_rc_section.VirtualAddress)}, Size={hex(new_rc_section.Misc_VirtualSize)}")

        updated_pe_data = pe.write()
        if debug_out:
            # 将修改后的 PE 文件头写入临时文件
            temp_file = f"{outfile_base}_temp_header.bin"
            with open(temp_file, 'wb') as temp_f:
                temp_f.write(updated_pe_data[:pe.OPTIONAL_HEADER.SizeOfHeaders])
            debug_print(f"[DEBUG] 修改后的 PE 文件头已写入临时文件: '{temp_file}'，文件头大小：{hex(pe.OPTIONAL_HEADER.SizeOfHeaders)}，注意该文件头中的区段表是没有更新的，其他数据应该是更新后的。")

        # 将新的文件头合并到文件内容中，此处的区段表还是原始的。
        file_data = updated_pe_data[:pe.OPTIONAL_HEADER.SizeOfHeaders] + file_data[pe.OPTIONAL_HEADER.SizeOfHeaders:]

        # 重建新的区段表，重建后的分区表是按照 虚拟地址 从小到大排列的。
        new_section_table = b"".join(section.__pack__() for section in all_sections_vir)
        # section_table_offset = pe.sections[0].get_file_offset()  # 区段表的偏移计算方法1
        section_table_offset = pe.DOS_HEADER.e_lfanew + 24 + pe.FILE_HEADER.SizeOfOptionalHeader  # 区段表的偏移计算方法2，更准确

        # 将重建后的区段表合并到文件内容中，手动替换新的区段表
        file_data = file_data[:section_table_offset] + new_section_table + file_data[section_table_offset + len(new_section_table):]
        print(f"[信息] 区段表已更新，写入文件偏移位置：{hex(section_table_offset)} ，区段表大小：{hex(new_section_table_size)}")

        # 将更新后的文件数据写入输出文件
        with open(output_file, 'wb') as f:
            f.write(file_data)
        print(f"[信息] 修改后的文件内容已写入新文件: {output_file}")
        return True

    except Exception as e:
        print(f"[错误] 操作失败，错误信息: {e}")
        return False



def main():
    global input_file, output_file, file_size_diff, debug_out
    # 使用 argparse 模块解析命令行参数
    parser = argparse.ArgumentParser(description="Windows PE 文件移动 .rsrc 区段工具", add_help=False)
    parser._positionals.title = "位置参数"  # 将 "positional arguments" 改为 "位置参数"
    parser._optionals.title = "可选参数"    # 将 "optional arguments" 改为 "可选参数"
    parser.add_argument("input_file", help="输入的 PE 文件路径: *.exe、*.dll 等文件")
    parser.add_argument("-o", "--output", help="输出文件路径，默认为 \'<原始文件名>_modsec.<后缀名>\'")
    parser.add_argument("-l", "--list", action="store_true", help="仅显示原始 PE 文件的详细信息, 不做修改和处理")
    parser.add_argument("-d", "--debug", action="store_true", help="处理过程中，生成临时文件、输出调试信息并写入日志文件")
    parser.add_argument("-h", "--help", action="help", help="显示此帮助信息并退出")

    # 如果没有提供任何参数，打印帮助信息并退出
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()  # 获取并解析命令行参数
    input_file = args.input_file  # 获取输入文件路径

    # 检查输入文件是否存在
    if not os.path.isfile(input_file):
        print(f"文件'{input_file}'不存在，请检查文件路径!")
        sys.exit(2)
    
    # 生成输出的文件名
    file_base, file_ext = os.path.splitext(input_file)
    output_file = args.output if args.output else f"{file_base}_moverc{file_ext}"
    # 输出文件路径和输入文件路径相同时，视同没有指定输出路径
    if os.path.abspath(input_file) == os.path.abspath(output_file):
        output_file = f"{file_base}_moverc{file_ext}"

    # 指定 debug 参数，处理过程中，生成临时文件、输出调试信息并写入日志文件
    if args.debug:
        debug_out = True

    try:
        # 读取 PE 文件
        pe = pefile.PE(input_file)
    except pefile.PEFormatError as e:
        print(f"[错误] 文件'{input_file}'不是有效的 PE 文件或文件损坏，错误信息: {e}")
        return
    except Exception as e:
        print(f"[错误] 读取文件'{input_file}'出错，错误信息: {e}")
        return
    
    print(f"文件: '{input_file}'")
    print("======== 原始 PE 文件详细信息 ========")
    try:
        print_basic_info(pe)  #基本信息
        print_directory_info(pe)  #目录信息
        print_section_info(pe)  #区段信息
        # print_imports(pe)  #导入表信息
        # print_exports(pe)  #导出表信息
    except Exception as e:
        print(f"[错误] 读取原始 PE 文件信息出错，错误信息: {e}")
        return
    
    try:
        file_size_diff = get_file_size_diff(pe)
        if file_size_diff > 0:
            print(f"[信息] 原始文件结尾存在 {hex(file_size_diff)}({file_size_diff}) 字节的未知数据\n")
        elif file_size_diff < 0:
            print(f"[信息] 原始文件结尾缺少 {hex(0 - file_size_diff)}({0 - file_size_diff}) 字节的数据(可能是正常的空数据)\n")
    except Exception as e:
        print(f"[错误] 分析原始文件大小出错，错误信息: {e}")
        return
    
    # 指定 list 参数，仅显示原始 PE 文件的详细信息, 不做修改和处理
    if args.list:
        return

    # 移动资源区段的数据到 PE 文件末尾
    if move_rsrc_section_to_end(input_file, output_file):
        # 验证写入是否成功
        modified_pe = pefile.PE(output_file)
        if debug_out:
            # 输出修改后 PE 文件基本信息
            outfile_base, outfile_ext = os.path.splitext(output_file)
            write_pe_info_to_file(modified_pe, f"{outfile_base}_PE信息.txt")
            
        print("\n验证修改后的 PE 文件的信息：")
        print("======== 修改 PE 文件详细信息 ========")
        try:
            print_basic_info(modified_pe)  #基本信息
            print_directory_info(modified_pe)  #目录信息
            print_section_info(modified_pe)  #区段信息
            # print_imports(modified_pe)  #导入表信息
            # print_exports(modified_pe)  #导出表信息
        except Exception as e:
            print(f"[错误] 读取修改 PE 文件信息出错，错误信息: {e}")
            return
            
        try:
            file_size_diff = get_file_size_diff(modified_pe)
            if file_size_diff > 0:
                print(f"[信息] 修改后文件结尾存在 {hex(file_size_diff)}({file_size_diff}) 字节的未知数据\n")
            elif file_size_diff < 0:
                print(f"[信息] 修改后文件结尾缺少 {hex(0 - file_size_diff)}({0 - file_size_diff}) 字节的数据(可能是正常的空数据)\n")
        except Exception as e:
            print(f"[错误] 分析修改后文件大小出错，错误信息: {e}")
        
        print(f"已成功将资源区段移动到文件末尾，输出文件为: '{output_file}'")
    # else:
        # print("=" * 79)
        # print(f"生成失败")

if __name__ == "__main__":
    main()
