# nandMScan 端口扫描工具
此工具主要用于大批量的端口扫描与服务识别，我们都知道如果直接使用nmap做端口扫描，扫描的速度会太慢，效率太低，如果直接使用Masscan进行端口又无法进行服务识别。

此工具就是调用masscan进行端口扫描，端口扫描完后再调用nmap进行多线程服务识别（默认一个线程），同时还支持对每个开放端口进行http与https的探测，获取title,状态码，len等信息。
支持多种扫描输入格式，支持：`文件导入、IP段、单个网站、等等`。
```
nandMScan 端口&服务极速扫描器 V1.3 by test502git  请确保系统中已安装了 nmap、masscan、sudo。
-f      IP列表文件
-u      单个IP检测
-p      扫描的端口                        默认：1-65535
-t      Masscan扫描端口的发包线程         默认：2000
-s      Nmap识别服务的线程                默认：1  识别服务线程建议5~30之间
--http  对开放的端口进行Http协议访问，获取Title、StatusCode、DataSize    默认：不访问

使用案例如下：
python3 nandM.py -f ip.txt
python3 nandM.py -u 198.13.36.73
python3 nandM.py -u 198.13.36.0/24  -t 5000                         #对IP段的全端口扫描并识别服务，设置Masscan扫描端口的发包线程5000
python3 nandM.py -u 198.13.36.0/24  -p 80 -s 0 --http               # -s 0 代表不识别服务，直接--http 访问
python3 nandM.py -u 192.168.0.100-192.168.0.200 -p 22,80,445        # 对IP段的22、80、445端口扫描并识别服务
python3 nandM.py -u 192.168.0.100-192.168.0.200 -p 22,80,445 --http # 对IP段的22、80、445端口扫描并识别服务，再http 访问

```
# 使用介绍：
## 运行环境：Linxu Kali（测试通过）
![mahua](https://s1.ax1x.com/2020/09/14/wDa1qf.png)
![mahua](https://s1.ax1x.com/2020/09/14/wDd4pj.png)








