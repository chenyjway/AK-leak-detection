#!/usr/bin/python
# -*- coding: UTF-8 -*-
'''
@author bypass
@date 2023年04月20号
'''

import requests,re
import base64,time
import configparser
import pysyslogclient
from datetime import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
import smtplib
from email.mime.text import MIMEText
from email.header import Header
requests.packages.urllib3.disable_warnings()



url='https://api.github.com/search/code'

def api_request(url,payload=None,headers=None):
    headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0',
         'Accept':'application/vnd.github+json',
         'Authorization':'Bearer '+config_dict['token'],
         'X-GitHub-Api-Version':'2022-11-28',
    }
    try:
        r= requests.get(url,params=payload,headers=headers,timeout=30)
        return r.json()
    except Exception as e:
        print(e)
    

def request_search(q):
    result_list=[]    
    payload ={'q':q}
    res_json=api_request(url,payload) 
    if 'total_count' in res_json:
        total_count = int(res_json['total_count'])
        if total_count>0:   
            data_trunk = res_json['items']
            for i in range(len(data_trunk)):
                result={}
                data_unit =data_trunk[i]   
                result['name'] = data_unit['name']  
                result['url'] = data_unit['url']
                result['html_url'] = data_unit['html_url']
                result['path'] = data_unit['path']           
                result_list.append(result)
                
        config_dict['count']+=1
        if config_dict['count'] >= len(config_dict['accesssKeyId']):
            config_dict['count']=0
    else:
        print(res_json)
        time.sleep(20)
    return result_list
    

def request_data(url):
    result=api_request(url)
    content=str(base64.b64decode(result['content']))
    try:
        pattern = re.compile(r'accessKeyId.*?[A-Za-z0-9]{24}.*?accessKeySecret.*?[A-Za-z0-9]{24}\'',re.S)      
        items = pattern.findall(content)
        return(items[0])
    except Exception as e:
        return content
   
    
def Syslog(data):
    client = pysyslogclient.SyslogClientRFC5424(config_dict['ip'], config_dict['port'], proto=config_dict['proto'])
    for i in range(len(data)):
        keyValue =  ",".join(['{}={}'.format(*j) for j in data[i].items()])
        client.log(keyValue)



def SendMail(data):

    mail_user=config_dict['email']
    mail_pass=config_dict['authorize_code']
    mail_host=config_dict['mail_host']
    mail_port=config_dict['mail_port']
    
    sender="676707528@qq.com"
    receivers = ['hujinjian@anta.com'] 
    
    
    for i in range(len(data)):
        html_text = """
            <div class="page" style="margin-left: 15px">
                <div><span style="font-size: 16px; font-weight: bold; position: relative; top: 5px;">本次AK泄露检测到存在可疑的泄露事件，具体如下：</span></div>
                    <table style="width: 100%; border-spacing: 0px; border-collapse: collapse; border: none; margin-top: 10px;">
                        <tbody>
                            <tr style="height: 40px; background: #F6F6F6;">
                                <th style="border: 1px solid #DBDBDB; color: #666666; font-size: 14px; font-weight: normal; text-align: left; padding-left: 14px;">发现时间</th>
                                <th style="border: 1px solid #DBDBDB; color: #666666; font-size: 14px; font-weight: normal; text-align: left; padding-left: 14px;">文件名称</th>
                                <th style="border: 1px solid #DBDBDB; color: #666666; font-size: 14px; font-weight: normal; text-align: left; padding-left: 14px;">泄露信息</th>
                                <th style="border: 1px solid #DBDBDB; color: #666666; font-size: 14px; font-weight: normal; text-align: left; padding-left: 14px;">URL地址</th>
                            </tr>
                            <tr style="height: 40px;">
                                <td style="border: 1px solid #DBDBDB; font-size: 14px; font-weight: normal; text-align: left; padding-left: 14px;">{time}</td>
                                <td style="border: 1px solid #DBDBDB; font-size: 14px; font-weight: normal; text-align: left; padding-left: 14px;">{name}</td>
                                <td style="border: 1px solid #DBDBDB; font-size: 14px; font-weight: normal; text-align: left; padding-left: 14px;">{key}</td>
                                <td style="border: 1px solid #DBDBDB; font-size: 14px; font-weight: normal; text-align: left; padding-left: 14px;">
                                    <a style="color: #006eff; text-decoration: none;" href="{html_url}" target="_blank" rel="noopener">{html_url}</a>
                                </td>
                                            
                            </tr>
                        </tbody>
                    </table>
            </div> """.format(time=data[i]['time'],name=data[i]['name'],key=data[i]['key'],html_url=data[i]['html_url'])

        message = MIMEText(html_text, 'html', 'utf-8')
        message['From'] = Header(sender)  
        message['To'] =  Header(str(";".join(receivers))) 
        
        title="AK 泄露检测邮件告警"
        message['Subject'] = Header(title)
        try:
            smtpObj = smtplib.SMTP_SSL(mail_host,mail_port)
            smtpObj.login(mail_user,mail_pass)
            smtpObj.sendmail(sender, receivers, message.as_string())
            smtpObj.quit()
 
        except smtplib.SMTPException:
            return 0


def KeywordMonitor():
    q=config_dict['accesssKeyId'][config_dict['count']]    
    now_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print('%s Search the keyword：%s' %(now_time,q))
    data=request_search(q)   
    if data is not None:
        for i in range(len(data)):
            key = request_data(data[i]['url'])
            data[i]['key'] = key
            data[i]['time']= now_time
 
    #print(data)
    if len(data): 
        print(data)
        #Syslog(data)
        SendMail(data)
    
   
    
    
def config_read():
    global config_dict
    config_dict = {}
    config = configparser.ConfigParser()
    config.read('config.ini',encoding="utf-8")
    config_dict['token'] = config.get('personal_access_tokens','token')
    config_dict['count'] = config.getint('autocount','count')
    
    config_dict['ip'] = config.get('syslog','ip')
    config_dict['port'] = config.getint('syslog','port')
    config_dict['proto'] = config.get('syslog','proto')
    
    config_dict['email']=config.get('smtp','email')
    config_dict['mail_port']=config.getint('smtp','mail_port')
    config_dict['mail_host']=config.get('smtp','mail_host')
    config_dict['authorize_code']=config.get('smtp','authorize_code')
    msg = config.get('ak','accesssKeyId').split(',')
    config_dict['accesssKeyId']  = [i for i in msg if i != ""]
    return config_dict
    

if __name__ == '__main__':
    config_read()
    
    
    KeywordMonitor()
    
    

    
    scheduler = BlockingScheduler()
    scheduler.add_job(KeywordMonitor, "interval", seconds=10)
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown(wait=False)


