# SZSolutions

SZSolutions威胁分析辅助工具:

常用使用方法cmd同目录运行

SZSolutions-v1.0.7.exe -m pack -f [全流量导出文件] -t 全流量（默认全流量）-c [指定config文件]

SZSolutions-v1.0.7.exe -h 查看全部参数说明
```shell
 _______  ________  _  _______        _  ____  _____
|_____  ||  ____  || ||_____  |      | ||__  ||___  |
      | || |    | || |      | |      | | _ | | _  | |
      | || |    | ||_|      | |      | || || || | | |
      | || |    | |         | |      | || ||_|| | |_|
      | || |____| |         | |_____ |_|| |__ | |_________
      |_||________|         |_______|   |____||___________| Threat Identification and Analysis

usage: SZSolutions-v1.0.7.exe [-h] -m mode -f file [-t type] [-g grasp] [-c config] [-p putout] [-e encode] [-s srcip]
                              [-o] [-rk]

SZSolutions威胁分析工具，安全运营的首选！

optional arguments:
  -h, --help            show this help message and exit
  -m mode, --mode mode  指定模式
  -f file, --file file  指定受检文件名
  -t type, --type type  指定受检文件类型
  -g grasp, --grasp grasp
                        指定关键遍历字段
  -c config, --config config
                        指定配置文件
  -p putout, --putout putout
                        指定输出文档类型
  -e encode, --encode encode
                        指定读取文档编码
  -s srcip, --srcip srcip
                        指定读取文档src_ip列字段名
  -o, --outxls          以xls格式输出文档
  -rk, --removekongge   去除关键遍历字段里空格
```

更新日志
-----------------------------------------------------------
v1.0.7更新（20230817）
1、解决了一个小小的报错问题。
2、新增-rk参数，可移除检测字段中所有空格。

v1.0.6更新（20220329）
1、推出新输出类型xls（默认为xlsx）解决非法字符编码问题，新加入-o参数进行控制。如在默认输出文档后出现非法字符提示，可在原命令行参数中增加输入-o，将更改为输出xls类型结果文档。

v1.0.5更新（20220324）
1、解决了一系列隐藏bug
2、更新config文件中BadKids,WhiteSilk表加载方式。
3、更新了config文件中最重要的规则部分，进一步降低误报。 

v1.0.4更新（20220323）
1、更新config文件中WhiteSilk表，表中支撑以IP地址为白名单。

v1.0.3更新（20220322）
1、修复了若干已知问题。

v1.0.2更新（20220321）
1、更换编译环境，压缩体积。
2、更新config文件中badkids表，表中支撑以告警名称为黑名单，排除高误报告警。



