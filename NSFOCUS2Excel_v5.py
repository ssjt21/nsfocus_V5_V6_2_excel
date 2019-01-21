# -*- coding: utf-8 -*-

"""
@author:随时静听
@file: get_data_nsfoucs.py
@time: 2018/08/31

"""

import zipfile
import re
import os
import glob
from cprint import *

import xlsxwriter




def getZiplst(path='.'):
    zip_list=glob.glob1(path,'*.zip')
    return sorted( map(lambda filename:os.path.join(path,filename),zip_list))




def getContent(zipname):
    if os.path.exists(zipname):
        zf=zipfile.ZipFile(zipname)
        return zf.read('index.html')


with open('index.html') as f:
    content=f.read()
# print content

## 获取高中低漏洞数量
def getHMLnum(content):
    #获取 tbody
    # print content
    pattern = '<h3\s+?id=\'vulnview1003\'.*?>[\w\W]*?<tbody>([\w\W]*?)</tbody>'
    pattern = re.compile(pattern)
    tbody=pattern.search(content)
    if tbody:
        trlst=re.sub('\s+','',tbody.groups()[0])
        result=re.findall('<tr.*?>.*?(?P<high>\d+).*?(?P<mid>\d+).*?(\d+).*?</tr>',trlst)
        high,mid,low=zip(*result)
        print high,mid,low
        high=str(reduce(lambda x,y:int(x)+int(y),high))
        mid=str(reduce(lambda x,y:int(x)+int(y),mid))
        low=str(reduce(lambda x,y:int(x)+int(y),low))
        return (high,mid,low) #[(high,mid,low),(high,mid,low)...]


#获取弱口令的个数
def getweakpwdnum(content):
    weakpwd=re.search('<div id=\'accounts\'.*?>([\w\W]*?)</div>',content)
    weakpwd=weakpwd.groups()[0]
    h3_lst=re.findall('<h3.*?>.*?(\d+).*?</h3>',weakpwd)
    # print h3_lst
    return reduce(lambda x,y:int(x)+int(y),h3_lst)



def saveStatistics(datalst):
    if datalst:
        book=xlsxwriter.Workbook(u'漏洞统计结果.xlsx')
        sheet=book.add_worksheet()
        title_format={
            'bold':True,
            'align':'center',
            'valign':'vcenter',
            'font_size':12,
            'border':3,
            'border_color':'#708090',
            'font_name':u'仿宋',
        }
        body_format={

                # 'blod': True,
                'align': 'left',
                'valign': 'vcenter',
                'font_size': 10,
                'border': 2,
                'border_color': '#808080',
                'font_name': 'Courier New',

        }
        title_format=book.add_format(title_format)
        body_format=book.add_format(body_format)

        # 列宽设置
        col_w_lst=[8,30,10,10,10,10,10]
        for i,w in enumerate(col_w_lst):
            sheet.set_column(i,i,w)

        row=0
        for i,line in enumerate(datalst):
            if row==0:
                #标题格式写入
                for col,cel in enumerate(line):
                    sheet.write(row,col,cel,title_format)
                # break

            else:
                for col,cel in enumerate(line):
                    sheet.write(row,col,cel,body_format)
                    sheet.write(row,col+1,"",body_format)
            row+=1

        book.close()


def getlevel(value):
    try:
        value=int(value)
        return u'高' if value>=7 else u'中' if value>=4 else u'低'
    except:
        return False
    pass
print getlevel(5)
print getlevel(2)
print getlevel(9)
def getDetail(content):
    lines = []
    if content:

        pattern=re.compile('<table.*?id=\"vulDataTable\">[\w\W]+?<tbody>([\w\W]*?)</tbody>[\w\W]*?</table>[\w\W]*?</div>')

        tbody=pattern.search(content)
        tbody= tbody.group(1) if tbody else ''

        if not tbody:
            cprint.warn(u"[!] It is some error in HTML PAGE!\n")
            return []
        pattern=re.compile('<tr class=".*?[vh|vm|vl]"\s.*?>([\w\W]*?)</tr>[\w\W]*?start-->([\w\W]*?)<!--plugin')
        tr_lst=pattern.findall(tbody)
        msg=u'[-] 解析出数据: '+str(len(tr_lst))+u" 条"
        print msg
        for vuln,detail in tr_lst:
            vuln=re.findall('<a.*?>([\w\W]*?)</a>',vuln)
            vuln =vuln[0] if vuln else ""
            vuln=re.sub('\s+',' ',vuln)
            # print vuln

            detail=re.findall('<tr.*?>[\w\W]+?<td.*?>([\w\W]+?)</td>[\w\W]+?<td.*?>([\w\W]+?)</td>[\w\W]+?</tr>',detail)

            tags,values=zip(*detail)

            ip_lst=re.findall('<a.*?>(.*?)</a>',values[0])
            # print ip_lst
            desc=re.sub('\s+|<.*?>|(&lt;)','',values[1])
            desc=''.join(desc.split())
            # print desc
            solution=re.sub('\s+|<.*?>|(&lt;)','',values[2])
            solution=re.sub('-{3,}','--',solution)

            # print values[3]
            level=getlevel(values[3])
            if not level:

                solution=u'无'
                level=getlevel(values[2])

            # print level
            #如果需要提取别的数据请使用values列表中的数据获取
            # 漏洞名称，影响范围，漏洞描述，解决方案，漏洞等级
            lines.append([vuln,','.join(ip_lst),desc,solution,level])
    return lines
            # print values




        # cprint.info(msg.decode('utf-8'))


def getCoding(strInput):
    '''
    获取编码格式
    '''
    if isinstance(strInput, unicode):
        return "unicode"
    try:
        strInput.decode("utf8")
        return 'utf8'
    except:
        pass
    try:
        strInput.decode("gbk")
        return 'gbk'
    except:
        pass


def tran2UTF8(strInput):
    '''
    转化为utf8格式
    '''
    strCodingFmt = getCoding(strInput)
    if strCodingFmt == "utf8":
        return strInput
    elif strCodingFmt == "unicode":
        return strInput.encode("utf8")
    elif strCodingFmt == "gbk":
        return strInput.decode("gbk").encode("utf8")


def tran2GBK(strInput):
    '''
    转化为gbk格式
    '''
    strCodingFmt = getCoding(strInput)
    if strCodingFmt == "gbk":
        return strInput
    elif strCodingFmt == "unicode":
        return strInput.encode("gbk")
    elif strCodingFmt == "utf8":
        return strInput.decode("utf8").encode("gbk")



def saveDetail(lines,filename):
    print len(lines)
    if lines:
        book=xlsxwriter.Workbook(filename)
        sheet=book.add_worksheet (u'漏洞统计详情')
        tilte=[u'序号',u'漏洞名称',u'影响范围',u'漏洞描述',u'解决方案',u'危险等级']

        #格式设置可以写个函数降低代码量
        title_format={
            'bold':True,
            'align':'center',
            'valign':'vcenter',
            'font_size':12,
            'border':3,
            'border_color':'#708090',
            'font_name':u'仿宋',
        }
        title_format=book.add_format(title_format)
        body_format = {

            # 'blod': True,
            'align': 'left',
            'valign': 'vcenter',
            'font_size': 10,
            'border': 2,
            'border_color': '#808080',
            'font_name': 'Courier New',

        }
        body_format=book.add_format(body_format)
        high_format={
            'bold': True,
            'align': 'center',
            'valign': 'vcenter',
            'font_size': 10,
            'border': 2,
            'border_color': '#808080',
            'font_name': u'仿宋',
            'fg_color':'red',
        }
        high_format=book.add_format(high_format)
        mid_format={
            'bold': True,
            'align': 'center',
            'valign': 'vcenter',
            'font_size': 10,
            'border': 2,
            'border_color': '#808080',
            'font_name': u'仿宋',
            'fg_color': '#FFA500',
        }
        mid_format=book.add_format(mid_format)
        low_format={
            'bold': True,
            'align': 'center',
            'valign': 'vcenter',
            'font_size': 10,
            'border': 2,
            'border_color': '#808080',
            'font_name': u'仿宋',
            'fg_color': '#32CD32',
        }
        low_format=book.add_format(low_format)
        level_format={u'高':high_format,u'中':mid_format,u'低':low_format}
        row=0
        col_w_set=[10,30,40,50,50,10]
        for index,w in enumerate(col_w_set):
            sheet.set_column(index,index,w)
        for col,cel in enumerate(tilte):
            sheet.write(row,col,cel,title_format)
        row+=1
        #这里做修改可以改变输出的格式合并IP可以分开单独一个IP一个漏洞
        for line in lines:
            sheet.write(row, 0, str(row),body_format)

            for i,cel in enumerate(line):
                cel = tran2UTF8(cel)
                cel = cel.decode('utf-8').replace(u'\xa0', u' ')

                sheet.write(row,i+1,cel,level_format.get(cel,body_format))

            row+=1
        book.close()



def run():
    datalst=[]
    datalst.append([u"序号",u"系统名称",u"高危",u"中危",u"低危",u"弱口令",u"备注"])
    for i,filename in enumerate( getZiplst()):

        name=os.path.splitext( os.path.basename(filename))[0]

        name=name.decode('gbk')
        print name
        content=getContent(filename)
        weakpwdnum=getweakpwdnum(content)
        hmnumber=getHMLnum(content)
        datalst.append([str(i+1),name,str(hmnumber[0]),str(hmnumber[1]),hmnumber[2],str(weakpwdnum)])
        lines=getDetail(content)
        saveDetail(lines,(name+'.xlsx').encode('gbk'))
    saveStatistics(datalst)


if __name__ == '__main__':
    run()
    pass
