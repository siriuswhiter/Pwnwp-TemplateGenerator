#!/usr/bin/env python

from pwn import *
from sys import *
import os,stat,re
import difflib

nowPath = sys.path[0]
if len(argv)>1:
	if argv[1]=="-h":
                print "#such as: python genwp.py filename -l >> /dev/null#"
		exit(0)
	name = argv[1]
	flag = False
	for fi in os.listdir(nowPath):
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

def mknew(desname):
	if not os.path.exists(desname):
		os.mknod(desname)
		os.system("chmod 777 "+desname)
#		os.chmod(desname,stat.S_IXGRP)

def findlolibc(desname):
	s="ldd "+name
	result=os.popen(s,'r')#.recvuntil("libc.so.6 => ")
	r=result.read()
	r=r.split('\n')
	for line in r:
		if "libc.so.6 => " in line:
			data=line.split(' ')
			return data[2]
						

def findrelibc():
	for li in os.listdir(nowPath):
		if "libc" in li:
			return li	

	return ""

def findlibc(desname):
	lolibc=findlolibc(desname)
        relibc=findrelibc()
	return lolibc,relibc

def init(desname):
	global des
	des=open(desname,'w')
        des.truncate()             # clear file

	lolibc,relibc=findlibc(desname)
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
	"	sh = process('"+name+"')\n",
	"	elf = ELF('"+name+"')\n",
        "	libc = ELF('"+lolibc+"')\n",
	"else:\n",
	"	sh = remote('','')\n",
	"	elf = ELF('"+name+"')\n"
	]
	des.writelines(s)
	if relibc:
		s=["",
		"	libc = ELF('"+relibc+"')\n\n\n"]
	else:
		s=["",
		"	#libc=ELF('')\n\n\n"]

	des.writelines(s)


def getmenu():
	tmp = process(nowPath+'/'+name)
	r = tmp.recv()
	tmp.close()
	return r
	

def findfunc(funcname):
	io = process(nowPath+'/'+name)
	ser = re.compile(funcname,re.IGNORECASE)
	r = getmenu().split('\n')
	for line in r:
		if re.search(ser,line):
			idx=re.findall('\d+',line)
			idx="".join(idx)	
			io.close()
			return idx
	io.close()
	return ""
	

def buildfunc(idx,funcname):
	s = ["def "+funcname+"():\n",
	"	sh.sendline('"+idx+"')\n"]
	des.writelines(s)
	
	check2=[['size'],['idx','index'],['content']]	
	
	for i in range(len(check2)):
                for j in range (len(check2[i])):
			io = process(nowPath+'/'+name)
			io.recv()
			io.sendline(str(idx))
			r = io.recv()
			ser = re.compile(check2[i][j],re.IGNORECASE)
			if getmenu() in r:
				break
			elif re.search(ser,r):
				s = [
				"	sh.sendlineafter('"+r+"',"+check2[i][j]+")\n"]
				des.writelines(s)
				if i != 2:
					io.sendline('0')
					r = io.recv()
					if difflib.SequenceMatcher(None, getmenu(), r).quick_ratio()>0.6:
						des.writelines(["\n\n"])
                                		break
					else:
						s = [
                                		"       sh.sendlineafter('"+r+"',"+check2[i][j]+")\n\n\n"]
                                		des.writelines(s)
						break
	
	
	io.close()


def buildAllFunc():
	check=[['add','alloc','new'],
	['edit','fill','change'],
	['show','put','read','dump','list','print'],
	['dele','free','remove']]

	for i in range(len(check)):
                for j in range (len(check[i])):
                        funcname = check[i][j]
                        idx = findfunc(funcname)
                        if idx!="":
                                buildfunc(idx,funcname)
                                break

		
def main():
	desname=name+'wp.py'
	mknew(desname)
	init(desname)
	if len(argv)>2 and argv[2]=="-l":
		buildAllFunc()
	des.writelines(["sh.interactive()"])
	des.close()
	
if  __name__ == '__main__':
	main()




