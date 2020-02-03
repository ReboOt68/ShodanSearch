# -*- coding:utf-8 -*-
import shodan
import os
import time
#参考：https://shodan.readthedocs.io/en/latest/tutorial.html#looking-up-a-host
#参考：https://www.cnblogs.com/csnd/p/11807796.html
#完成-2019-11-27：results_sth_msg实现输入任意关键字（例如apache）返回自定义信息
#完成-2019-11-27：results_ip_full_msg实现输入指定IP，自定义格式返回内容
#完成-2019-11-28、29：完成批量查询、IP下各端口详情的信息整合输出
#Version:1.0
#by:reboot
api=shodan.Shodan("XXXXXXX") #指定API_KEY,返回句柄

def get_sth_results(keyword):   #输入任意关键字进行查询
    try:
        results_sth_msg = api.search(keyword)  # 搜索关键字，返回 JSON格式的数据
        i=0
        for results_sth_msg in results_sth_msg['matches']:
            i=i+1
            print("关键字："+str(keyword))
            print("IP地址：" + str(results_sth_msg['ip_str']))
            print("域名：" + str(results_sth_msg['hostnames']))
            print("操作系统：" + str(results_sth_msg['os']))
            print("端口：" + str(results_sth_msg['port'])+ "\n")
        print("总数：" + str(i) + "个")
            #print("返回包：\n" + str(results_sth_msg['data'])) #返回包信息有的比较多有点乱，用处不大，需要的时候取消注释即可。
    except shodan.APIError as e:
        print('Error: {}'.format(e))


def get_ip_results(keyword):   #输入IP进行查询
    print("####当前查询IP：" + keyword + "\n" + "####总体详情####\n")
    try:
        results_sth_msg = api.host(keyword)  # api.host返回一个IP的详细信息，JSON格式
        #api.host所有的key: 遍历 for get_ip_results['data']
        print("IP地址："+str(keyword))
        print("国家：" + results_sth_msg['country_name'])
        print("组织：" + results_sth_msg['org'])
        if 'vulns' in results_sth_msg:
            print("CVE漏洞：" + str(results_sth_msg['vulns']))  # 有的IP不存在漏洞，没有该参数值,需要对这个做判断
        else:
            print("CVE漏洞：None")
        print("主机名：" + str(results_sth_msg['hostnames']))
        print("操作系统：" + str(results_sth_msg['os']))
        print("最后更新时间：" + str(results_sth_msg['last_update']))
        print("ASN：" + str(results_sth_msg['asn']))
        print("服务提供商ISP：" + str(results_sth_msg['isp']))
        print("端口：" + str(results_sth_msg['ports']) + "\n")
        #print("各端口对应详情：" + str(results_sth_msg['data']...))  待开发
        #开发端口——漏洞
        print("=====以下为各端口下的详情=====\n")
        lenth = len(results_sth_msg['data'])
        id = 0
        while id < lenth:
            print("端口：" + str(results_sth_msg['data'][id]['port']))
            print("域名：" + str(results_sth_msg['data'][id]['domains']).strip("['").strip("]'"))
            print("城市：" + str(results_sth_msg['data'][id]['location']['city']))
            if 'http' in results_sth_msg['data'][id].keys():
                print("服务：" + str(results_sth_msg['data'][id]['http']['server']))
            else:
                print("服务：None")
            print("CVE漏洞：")
            # if 'vulns' in results_sth_msg['data'][id]:
            #     for key in results_sth_msg['data'][id]['vulns'].keys():
            #         print("       " + key)
            #     print("---------------------------")
            # else:
            #     print("       None" + "\n" + "---------------------------")
            if 'vulns' in results_sth_msg['data'][id].keys():
                for key in results_sth_msg['data'][id]['vulns'].keys():
                    print("      " + key)
                print("---------------------------")
            else:
                print("      None\n" + "---------------------------")
            id += 1
            time.sleep(0.5)  # Shadon对请求频率有限制，超过1次/秒 太多次会报错，所以设置一个延迟时间（单位秒）。

    except shodan.APIError as e:
        print('Error: {}'.format(e))


if __name__ == '__main__':
    choice = input("请选择你要查询的方式：\nA--任意关键字\nB--指定单个IP\nC--批量IP\n")
    if choice == 'A':
        keyword = input('请输入查询的关键字：\n')
        get_sth_results(keyword)
    if choice == 'B':
        keyword = input('请输入查询的关键字：\n')
        get_ip_results(keyword)
    if choice == 'C':
        pwd = os.path.abspath('.')
        full_pwd = pwd + "/ips.txt"
        file = open(full_pwd,"r")
        for ip in file.readlines():
            ip = ip.strip()
            get_ip_results(ip)
