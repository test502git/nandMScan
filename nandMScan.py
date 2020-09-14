# encoding=utf8
import sys
version = sys.version_info
if version < (3, 0):
    print('The current version is not supported, you need to use python3')
    sys.exit()
try:
    import datetime,json
    import threading,sys,getopt
    from threading import Semaphore
    import re,time,os
    import requests
    from bs4 import BeautifulSoup
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception as e:
    print('你有模块未安装，请使用pip3安装，再执行。')
    print(e)
    sys.exit()




nowTime=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
nowTime=str(nowTime).replace(' ','_').replace(':','-')

help="""nandM端口&服务极速扫描器 V1.3 by test502git  请确保系统中已安装了 nmap、masscan、sudo。
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
 
"""
if len(sys.argv)<2:
    print(help)
    sys.exit()
file=''
postlist = '1-65535'        #扫描的端口
rate = '2000'
ScanServiceNub=1           #调用nmap识别服务的线程
HttpAccess=0               # file
httplist=[]
try:
    opts, args = getopt.getopt(sys.argv[1:], "f:u:t:p:s:h", ["http","help"])
    for opt, arg in opts:
        if "-f" == opt:
            print('IP文件:' + arg)
            file=str(arg)
        elif '-u'==opt:
            print('扫描目标:' + arg)
            ipu=str(arg)
        elif '-t' == opt:
            print('发包线程:' + arg)
            rate=str(arg)
        elif '-p' == opt:
            print('扫描端口:' + arg)
            postlist=str(arg)
        elif '-s' == opt:
            ScanServiceNub=arg
            if int(arg)==0:
                print('此次不识别服务')
            else:
                print('识别服务线程:' + arg)
        if opt in ("--http"):
            print('此次扫描会对开放的端口进行http协议访问')
            print('is http')
            HttpAccess=1
        if opt in ("-h", "--help"):
            print(help)
            sys.exit(1)
except getopt.GetoptError as e:
    print ('参数解析发生了错误:' + e.msg)
    sys.exit(1)

if file=='':
    if ipu!='':
        print('\n开始扫描端口：\n'+'masscan ' + ipu + ' -p ' + postlist + ' --rate=' + rate + ' -oJ ' + nowTime + '.masccan\n')
        os.system('sudo masscan ' + ipu + ' -p ' + postlist + ' --rate=' + rate + ' -oJ ' + nowTime + '.masccan')
    else:
        sys.exit(1)
else:
    print('\n开始扫描端口：\n'+'sudo masscan   -iL '  +file+ '  -p ' + postlist + ' --rate=' + rate + ' -oJ ' + nowTime + '.masccan\n')
    os.system('sudo masscan  -iL ' + file + ' -p ' + postlist + ' --rate=' + rate + ' -oJ ' + nowTime + '.masccan')

count = 0
count2 = 0
da = open(nowTime + '.masccan', 'r', encoding='utf-8').read().split('\n')

if int(ScanServiceNub)==0:
    print('不扫描服务')
else:
    sem = Semaphore(int(ScanServiceNub))
    print('\n端口扫描完成，开启多线程识别服务: '+nowTime + '.masccan')
    if len(da) <= 1:
        print('没有扫到任何端口,退出~~~~')
        sys.exit()  # 程序退出

sem2 = Semaphore(8)





def GetIpInformation(ip,sem2,fileres='null'):
    global count2
    try:
        if 'http' not in ip:
            ip='http://'+ip
        req=requests.get(url=ip,verify=False,timeout=8,stream=True)
        req.encoding=req.apparent_encoding
        datalen=len(req.text)
        suop = BeautifulSoup(req.text, 'html.parser')
        try:
            title=str(suop.title.text).strip()
        except Exception as e:
            title='title:Null'
        res={
            'IP': ip,
            'StatusCode':str(req.status_code),
            'Title':title,
            'DataSize':str(datalen)
        }
        print('IP: '+res['IP'],' | StatusCode: '+res['StatusCode'],' | Title: '+res['Title'],' | DataSize: '+res['DataSize']+' | ')
        #r = open(fileres, 'w').write('IP:'+res['IP'],' | StatusCode: '+res['StatusCode'],' | Title: '+res['Title'],' | DataSize: '+res['DataSize']+' | '+'\n')
    except Exception as e:
        print(ip,e)
    sem2.release()
    count2=count2-1
def scanserive(ip,port,sem):
    global count
    print('nmap  -sS -sV  -Pn -p '+port+ ' '+ip+' -->'+nowTime+'.nmap')
    os.system('sudo nmap  -sS  -sV -Pn -p '+port+ ' '+ip+' >>'+nowTime+'.nmap')
    count = count - 1
    sem.release()
    return 0

def outinfo(strinfo,status=0):#输出不换行
    sys.stdout.write('\r识别服务线程，剩余'+str(strinfo)+'在执行中')
    sys.stdout.flush()


def retext(file,filename='r.txt'):
    f = open(file, 'r',encoding='utf-8')
    string = ""
    matchIp = re.compile(r'(?<![\.\d])((?:(?:2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(?:2[0-4]\d|25[0-5]|[01]?\d\d?))(?![\.\d])')
    matchPort = re.compile(r'\d+/tcp\s+open')
    matchSer = re.compile(r'open\s+\w+.+')
    for line in f.readlines():
        m = ''.join(matchIp.findall(line))
        n = ''.join(matchPort.findall(line))[:-4]
        s = ''.join(matchSer.findall(line))[6:]
        if (m != ''):
            string += "ip:" + m
        if (n != ''):
            string += 'port:' + n
        if (s != ''):
            string += s + '\n'
        if (m != '' or n != '' or s != ''):
            string += '\n'
    r = open(filename, 'w')
    print("\n\n端口服务扫描完成，结果已保存在 "+filename+" 中，打印结果如下：\n"+string)
    r.write(string)
    r.close()
    f.close()
for data in da:
    if data !='' and 'finished' not in data:
        try:
            data=data.replace('},','}')
            list1 = json.loads(data)
            ip=list1['ip']
            port=list1['ports'][0]['port']
            httplist.append(str(ip)+':'+str(port))

            if int(ScanServiceNub) != 0:
                sem.acquire()
                count = count + 1
                threading.Thread(target=scanserive,args=(str(ip),str(port),sem,)).start()
        except Exception as e:
            pass

while True:
    if int(ScanServiceNub) != 0:
        outinfo(str(count))
    time.sleep(1)
    if count==0:#代表nmap服务识别结束。
        if int(ScanServiceNub) != 0:
            print('hack')
            retext(nowTime+'.nmap',nowTime+'.res')
        if HttpAccess==1:
            print('\nHTTP访问结果如下：')
            for ah in httplist:
                sem2.acquire()
                count2=count2+1
                threading.Thread(target=GetIpInformation,args=(ah,sem2,nowTime+'.http',)).start()
            while True:
                if count2 == 0:
                    time.sleep(1)
                    if count2 == 0:
                        sys.exit()  # 程序退出
        else:
            sys.exit()  # 程序退出



