# Windows PE 文件移动 .rsrc 区段工具
将 Windows PE 文件的 .rsrc 区段移动到文件的最后，让 .rsrc 变成最后一个区段。也支持资源区段名是其他名称的情况。

正常情况下，PE 文件的最后一个区段一般是 .rsrc 区段，当我们修改该区段时，区段大小发生变化，它不会影响其他区段，也不影响程序正常运行。
针对 exe、dll 等 PE 文件经过脱壳、解密、或者非标宏汉化等操作后，导致最后一区段不是 .rsrc 区段，此时再修改 .rsrc 区段数据，可能就会导致程序错误或者无法运行。
为了解决该问题，编写了 Python 脚本，脚本中有大量的注释和调试语句，方便理解和修改。

建议使用 py3.10 运行脚本。
由于 pefile 库的版本不同，pe的有些参数或者变量名可能会有所不同。


## 依赖库
pefile


## 用法
```
pefile_switch_rsrc_sec.py [-o OUTPUT] [-l] [-d] [-h] input_file

Windows PE 文件移动 .rsrc 区段工具

位置参数:
  input_file            输入的 PE 文件路径: *.exe、*.dll 等文件

可选参数:
  -o OUTPUT, --output OUTPUT
                        输出文件路径，默认为 '<原始文件名>_modsec.<后缀名>'
  -l, --list            仅显示原始 PE 文件的详细信息, 不做修改和处理
  -d, --debug           处理过程中，生成临时文件、输出调试信息并写入日志文件
  -h, --help            显示此帮助信息并退出
```

## 感谢
感谢 wanfu 大佬的指点和非标宏。