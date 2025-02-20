## Windows PE 文件移动 .rsrc 区段工具
将 Windows PE 文件的 .rsrc 区段移动到文件的最后，让 .rsrc 变成最后一个区段。也支持资源区段名是其他名称的情况。

正常情况下，PE 文件的最后一个区段一般是 .rsrc 区段，当我们修改该区段时，区段大小发生变化，它不会影响其他区段，也不影响程序正常运行。
针对 exe、dll 等 PE 文件经过脱壳、解密、或者非标宏汉化等操作后，导致最后一区段不是 .rsrc 区段，此时再修改 .rsrc 区段数据，可能就会导致程序错误或者无法运行。
为了解决该问题，编写了 Python 脚本，脚本中有大量的注释和调试语句，方便理解和修改。

建议使用 Python 3.10 以上版本运行脚本，不支持 Python 2。
由于 pefile 库的版本不同，pe的有些参数或者变量名可能会有所不同。


### 依赖库
pefile


### 用法
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

### 感谢
感谢 wanfu 大佬的指点和非标宏。



### 其他

自用的一些脚本，解决汉化过程中遇到的一些问题：

- change_rcdata_charset.py ：将 RCDATA 资源中的 dfm 文件（delphi）中的 Font.Charset = ANSI_CHARSET 修改成 Font.Charset = DEFAULT_CHARSET ，这样可以解决有些界面汉字是乱码的问题。通过修改脚本代码，理论上也可以支持修改更多字符集的情况。注意需要配合 ResourceHacker_zh-CN.exe 使用，请自行下载 Resource Hacker 工具。
- py_read_reloc.py ：读取 PE 文件的重定向表，主要是针对 dll 等被加载的文件。当修改某些段的数据以后，有些带全局的偏移量的数据就需要根据基地址进行重定向，此时就需要也修改重定向表，保证程序代码可以正常运行。

