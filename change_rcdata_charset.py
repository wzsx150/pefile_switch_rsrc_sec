# -*- coding: utf-8 -*-
import os
import subprocess
import sys
import pefile
import shutil
import chardet


# 修改 RCDATA 资源的字符集的工具 v2.0-20250220  by wzsx150 
# 将 RCDATA 资源中的 dfm 文件（delphi）中的 Font.Charset = ANSI_CHARSET 修改成 Font.Charset = DEFAULT_CHARSET ，这样可以解决有些界面汉字是乱码的问题。
# 将 Windows PE 文件(.exe、.dll等)的资源文件中类型是 RCDATA 类型的资源中，有一些是delphi的dfm文件，该脚本就是将这些资源解包，然后替换修改，然后再导入。
# 写的比较粗糙，没有做各种人性化的适配，主要是自用。

# 注意：
# 1、推荐使用 Python 3.10 以上版本运行该脚本，不支持 Python 2。需要安装相关库。
# 2、请确认 PE 文件是完整无损坏的，并且 .rsrc 资源区段是允许被修改的（比如：.rsrc 区段一般要是 PE 文件的最后一个区段），否则可能导致修改后程序无法运行。


# Resource Hacker 的路径
RESOURCE_HACKER_PATH = r"ResourceHacker_zh-CN.exe"  # 请替换为你的 Resource Hacker 安装路径

def get_rcdata_resources(exe_path):
    """获取 EXE 文件中所有 RCDATA 类型资源的名称"""
    rcdata_resources = []
    try:
        pe = pefile.PE(exe_path)
        for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource.name is None and resource.id == 10:  # 10 是 RCDATA 的 ID
                for entry in resource.directory.entries:
                    rcdata_resources.append(entry.name)
            elif resource.name is not None and resource.id == 10:
                rcdata_resources.append(resource.name.decode('utf-8'))
    except Exception as e:
        print(f"错误，获取 RCDATA 资源时出错: {e}")
        sys.exit(11)
    
    print("RCDATA 类型资源名：", end='')
    for resource_name in rcdata_resources:
        print(resource_name, end=' ')  # 输出每个资源名
    print("")

    return rcdata_resources

def extract_rc_resources(exe_path, resource_names):
    """提取指定 RCDATA 资源并返回资源名称和文件路径的字典"""
    temp_dir = "extracted_resources_temp_"

    try:
        # 删除临时文件夹（如果存在）
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            print(f"已清空临时文件夹: {temp_dir}")
        
        os.makedirs(temp_dir, exist_ok=True)
    except Exception as e:
        print(f"错误，清空临时文件夹 {temp_dir} 失败: {e}")
        sys.exit(4)

    rc_files = {}
    for resource_name in resource_names:
        if len(str(resource_name)) > 1:
            resource_name_dfm = str(resource_name)[1:]
        else:
            continue
        command = [
            RESOURCE_HACKER_PATH,
            "-open", exe_path,
            "-save", f"{temp_dir}\\{resource_name}.rc",
            "-action", "extract",
            "-mask", f"RCDATA,{resource_name},",
            "-log", "NUL"  # 如果想命令行输出日志，就把这行注释掉
        ]
        try:
            subprocess.run(command, check=True)
            rc_files[resource_name] = f"{temp_dir}\\{resource_name_dfm}.dfm"  #如果是dfm，Resource Hacker会自动解析成dfm文件，所以这里直接找 dfm 文件。
        except subprocess.CalledProcessError as e:
            print(f"错误，提取资源 '{resource_name}' 时出错: {e}")
            sys.exit(12)

    return rc_files

def detect_file_encoding(file_path):
    """检测文件编码"""
    with open(file_path, 'rb') as file:
        raw_data = file.read()
    result = chardet.detect(raw_data)
    return result['encoding']

def modify_rc_file(rc_file):
    """修改 .rc/.dfm 文件中的字符集"""
    if os.path.exists(rc_file):
        print(f"   找到 dfm 资源文件: {rc_file}，继续处理")
    else:
        print(f"   找不到 dfm 资源文件: {rc_file}，跳过...")
        return False

    encoding = detect_file_encoding(rc_file)
    # print(f"   检测到 {rc_file} 的编码为: {encoding}")

    with open(rc_file, 'r', encoding=encoding, newline='') as file:
        content = file.readlines()

    # 这里采用明文替换方式，可能读取文件和替换不一定兼容性很强，若有需要可以改进代码。
    modified = False
    modified_content = []
    for line_number, line in enumerate(content):
        if "Font.Charset = ANSI_CHARSET" in line:
            temp_line = line
            line = line.replace("Font.Charset = ANSI_CHARSET", "Font.Charset = DEFAULT_CHARSET")  # 替换为新的字符集
            print(f"   第 {line_number + 1} 行发现并替换内容: '{temp_line.strip()}' -> '{line.strip()}'")
            modified = True
        modified_content.append(line)

    # 如果修改了内容，就替换后的所有内容写入文件。
    if modified:
        with open(rc_file, 'w', encoding=encoding, newline='') as file:
            file.writelines(modified_content)
        print(f"   修改后的文件已保存: {rc_file}")
    else:
        print(f"   没有需要替换的内容。")

    return modified

def import_rc_resources(exe_path, rc_files, new_exe_name):
    """将修改后的 .rc 文件导入回 EXE 文件"""
    for resource_name, rc_file in rc_files.items():
        command = [
            RESOURCE_HACKER_PATH,
            "-open", exe_path,
            "-save", new_exe_name,  # 保存为新文件
            "-action", "addoverwrite",
            "-resource", f"{rc_file}",
            "-mask", f"RCDATA,{resource_name},",
            "-log", "NUL"  # 如果想命令行输出日志，就把这行注释掉
        ]
        try:
            subprocess.run(command, check=True)
            print(f"   已导入修改后的资源 '{resource_name}'")
        except subprocess.CalledProcessError as e:
            print(f"   导入资源 '{resource_name}' 时出错: {e}")
            sys.exit(13)

def main(exe_path):
    # 生成新的 EXE 文件名
    base_name, ext = os.path.splitext(exe_path)
    new_exe_name = f"{base_name}_change_charset{ext}"

    # 复制源文件到新的文件名
    shutil.copy2(exe_path, new_exe_name)
    print(f"已将源文件复制到: {new_exe_name}")

    # 获取 RCDATA 资源名称
    print(f"== 正在获取 {exe_path} 中的 RCDATA 资源名称...")
    resource_names = get_rcdata_resources(exe_path)

    # 提取 RCDATA 资源
    print(f"== 正在从 {exe_path} 提取 RCDATA 资源...")
    rc_files = extract_rc_resources(exe_path, resource_names)

    # 修改每个 RCDATA 中的 dfm 文件
    modified_files = []
    for resource_name, rc_file in rc_files.items():
        print(f"== 正在查找并修改 RCDATA 文件 {rc_file}...")
        if modify_rc_file(rc_file):
            modified_files.append((resource_name, rc_file))

    # 导入所有修改后的 RCDATA 资源
    print("")
    if modified_files:
        print(f"== 正在将修改后的资源导入到 {new_exe_name}...")
        import_rc_resources(new_exe_name, dict(modified_files), new_exe_name)
        print(f"== 完成修改，生成文件：'{new_exe_name}'")
    else:
        print("== 没有任何资源文件被修改，未进行导入。")

if __name__ == "__main__":
    print("将PE文件中RCDATA资源中的 Font.Charset = ANSI_CHARSET 修改成 Font.Charset = DEFAULT_CHARSET 的工具。")
    print("请确认 PE 文件是完整无损坏的，并且 .rsrc 资源区段是允许被修改的（比如：.rsrc 区段一般要是 PE 文件的最后一个区段），否则可能导致修改后程序无法运行。")
    print("")
    if len(sys.argv) != 2:
        print("用法: python script.py <pe_file>\n")
        sys.exit(0)

    exe_path = sys.argv[1]

    if not os.path.isfile(exe_path):
        print(f"错误，找不到文件: {exe_path}")
        sys.exit(1)

    if not os.path.isfile(RESOURCE_HACKER_PATH):
        print(f"错误，找不到 Resource Hacker 程序，请确认程序文件存在: '{RESOURCE_HACKER_PATH}'")
        print(f"或者修改该 Python 脚本中 RESOURCE_HACKER_PATH 变量的值(即文件路径)。")
        sys.exit(2)

    main(exe_path)
