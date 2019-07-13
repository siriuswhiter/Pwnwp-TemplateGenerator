#!/usr/bin/env python

from pwn import *
from sys import *
import os,stat,re
import difflib

pwd = sys.path[0]
if len(argv)>1:
	if argv[1]=="-h":
                print "#such as: python genwp.py filename -l >> /dev/null#"
		exit(0)
	name = argv[1]
	flag = False
	for fi in os.listdir(pwd):
		if fi==name:
			flag=True
			break
	if not flag:
		print "#File doesn't exist!#"
		exit(0)	
		
else:
	print "#Lack of parameters, parameter one should be file name#"
	print "#such as: python genwp.py filename -l >> /dev/null    #"
	exit(0)	

def mk_new_file(WpName):
	if not os.path.exists(WpName):
		os.mknod(WpName)
		os.system("chmod 777 "+WpName)
#		os.chmod(WpName,stat.S_IXGRP)
	else:
		print 'File has exists ; Wanna cover it?(y/n)'
		#a = raw_input()
		if raw_input()[0] == 'y':
			pass
		else:
			print 'bye~'
			exit(0)

def find_local_libc(WpName):
	s="ldd "+name
	result=os.popen(s,'r')#.recvuntil("libc.so.6 => ")
	r=result.read()
	r=r.split('\n')
	for line in r:
		if "libc.so.6 => " in line:
			data=line.split(' ')
			return data[2]
						

def find_remote_libc():
	for li in os.listdir(pwd):
		if "libc" in li:
			return li	

	return ""

def find_libc(WpName):
	lolibc=find_local_libc(WpName)
        relibc=find_remote_libc()
	return lolibc,relibc

def __init_not_arm(WpName,link):
	global des
	des=open(WpName,'w')
        des.truncate()             # clear file
	if link:
		lolibc,relibc=find_libc(WpName)
	else:
		lolibc,relibc="",""
	
	s=["#!/usr/bin/env python2\n",
	"# -*- coding:utf-8 -*-\n\n",
	"import sys\n",
	"from pwn import *\n\n",
	"#context.log_level = 'debug'\n",
	"#context.terminal = ['gnome-terminal','-x','bash','-c']\n\n",
	"if len(sys.argv) > 1:\n",
	"	local = 0\n",
	"else:\n",
	"	local = 1\n\n",
	"if local:\n",
	"	sh = process('./"+name+"')\n",
	"	elf = ELF('./"+name+"')\n",
    "	libc = ELF('"+lolibc+"')\n",
	"else:\n",
	"	sh = remote('','')\n",
	"	elf = ELF('./"+name+"')\n"
	]
	des.writelines(s)
	if relibc:
		s=["",
		"	libc = ELF('"+relibc+"')\n\n\n"]
	else:
		s=["",
		"	#libc=ELF('')\n\n\n"]

	des.writelines(s)

def __init_arm(WpName,link):
	global des
	des=open(WpName,'w')
        des.truncate()           
	if link:
		libc = "	libc = ELF('/usr/arm-linux-gnueabi/lib/libc.so.6')\n"
	else:
		libc = ""

	s = [
		"from pwn import *\n",
		"import sys\n",
		"context.binary = '"+name+"'\n\n",

		"if len(sys.argv) > 1:\n",
		"	local = 0\n",
		"else:\n",
		"	local = 1\n\n",
		"if local:\n",
		"	sh = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi', '"+name+"'])\n",
		"	elf = ELF('./"+name+"')\n",
		libc,
		"else:\n",
		"	sh = remote('','')\n",
		"	elf = ELF('./"+name+"')\n"
	]
	des.writelines(s)


def get_menu():
	tmp = process(pwd+'/'+name)
	r = tmp.recv()
	tmp.close()
	return r
	

def find_func(funcname):
	io = process(pwd+'/'+name)
	ser = re.compile(funcname,re.IGNORECASE)
	r = get_menu().split('\n')
	for line in r:
		if re.search(ser,line):
			idx=re.findall('\d+',line)
			idx="".join(idx)	
			io.close()
			return idx
	io.close()
	return ""
	

def build_func(idx,funcname):
	s = ["def "+funcname+"():\n",
	"	sh.sendline('"+idx+"')\n"]
	des.writelines(s)
	
	check2=[['size'],['idx','index'],['content']]	
	
	for i in range(len(check2)):
                for j in range (len(check2[i])):
			io = process(pwd+'/'+name)
			io.recv()
			io.sendline(str(idx))
			r = io.recv()
			ser = re.compile(check2[i][j],re.IGNORECASE)
			if get_menu() in r:
				break
			elif re.search(ser,r):
				s = [
				"	sh.sendlineafter('"+r+"',"+check2[i][j]+")\n"]
				des.writelines(s)
				if i != 2:
					io.sendline('0')
					r = io.recv()
					if difflib.SequenceMatcher(None, get_menu(), r).quick_ratio()>0.6:
						des.writelines(["\n\n"])
                                		break
					else:
						s = [
                                		"       sh.sendlineafter('"+r+"',"+check2[i][j]+")\n\n\n"]
                                		des.writelines(s)
						break
	
	
	io.close()


def build_all_func():
	check=[['add','alloc','new'],
	['edit','fill','change'],
	['show','put','read','dump','list','print'],
	['dele','free','remove']]

	for i in range(len(check)):
                for j in range (len(check[i])):
                        funcname = check[i][j]
                        idx = find_func(funcname)
                        if idx!="":
                                build_func(idx,funcname)
                                break


#diff as Arm && not_Arm (True) ,statically && dynamically (True)
def check_file_type():
        s="file "+name
        result=os.popen(s,'r')#.recvuntil("libc.so.6 => ")
        r=result.read()
        if 'Arm' in r:
            if 'statically linked' in r:
                return False,False
            else:
                return False,True
        else:
            if 'dynamically linked' in r:
                return True,False
            else:
                return True,False


def main():
	WpName=name+'wp.py'
	mk_new_file(WpName)
        types , link = check_file_type()
        if(link):
            __init_not_arm(WpName,link)
        else:
			__init_arm(WpName,link)

	if len(argv)>2 and argv[2]=="-l":
		build_all_func()
	des.writelines(["sh.interactive()"])
	des.close()
	
if  __name__ == '__main__':
	main()




