## STMCTF2018 pwn1 sorusu çözümü

Çoğu soruda olduğu gibi bir dosya verildi ve hemen altında sunucu adresi. Bağlantı için ise nc verilmiş. Sunucunun adresi şu an aklımda olmadığı için kısaca x.x.x.x kullanabiliriz. Tabi şu an için bağlantı mümkün olmadığı için biz local olarak sahte bir flag yapıp bunu kullanacağız.


Bu soruyu görünce hemen karşı sunucuda bu programın barındırdığı kodların çalıştığını anlıyoruz. local olarak çözüp sunucuyu pwn edeceğiz.

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/1.png)

Dosyaya hızlıca baktığımızda 32 bit linux ELF formatında olduğunu görüyoruz.

İlk önce hemen blind bir şekilde başlatıp ne yapıyor ne ediyor görelim.

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/2.png)

Hiç bişey olmadı. Basit ve ilk tahmin ile acaba overflow olabilir mi diye biraz uzun bir input girelim:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/3.png)

Evet! Overflow var. Hatta trace edelim:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/4.png)

Bundan sonrası pattern bulma. Input kısa olduğu için çok uğraşmaya gerek yok yarısı A olacak ve yarısı B olacak şekilde birkaç denemeden sonra patternin 28 olduğu ortaya cıkıyor. Yani 28 uzunluğunda pattern girdikten sonra return adresi verebiliyoruz. Test edelim:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/5.png)

Evet artık EIP bizim kontrolümüz altında. Öncelikle NX(Non-executable stack) var mı diye kontrol edebiliriz, fakat yarışma açısından konulmadığını tahmin etmek zor değil:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/6.png)

Şimdi biraz derine inelim ve neler olduğuna biraz bakalım. Bunun için gdb ile debug edip return adresinin olduğu noktada tam olarak register durumları nedir bakalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/7.png)

Bu resimden anladığımız önemli iki şey:

* ESP = EAX+ 28(pattern ‘A’) + RET(return address ‘B’)
* Girdiğimiz input EAX registerında saklanmış

Bu noktada aklımızda gelen şey EAX registerına atlasak yazdığımız kodlar çalışır. Shellcode yerleştirip oraya atlamalıyız. Bunun için ise bize bunu sağlayacak bir tür gadget lazım. Programın kendi içinde bir tür call varsa işimizi tamamen görür. Bir arama yapalım bu dosya üzerinde:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/8.png)

Tam da istediğimiz şey varmış. 0x8048373 adresi işimizi görür.

Şimdi şöyle bir durum var(yazının ilerleyen kısmında bunu da aşacağız) bizim elimizde 28 var sonra ise return address ordan kesiyor. Bize 28’den kısa bir shellcode lazım. Google’da “Linux x86 shellcode” diye aratırsak çok kısa shellcodelar olduğunu görürüz. Kendimiz de yazabiliriz fakat yarışmada her dakikanın önemli olduğunu hesaba katarsak Google daha hızlı.

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/shell.png)

Sadece 23 byte! Gayet güzel oldu. 

```c
    *****************************************************
    *    Linux/x86 execve /bin/sh shellcode 23 bytes    *
    *****************************************************
    *	  	  Author: Hamza Megahed		        *
    *****************************************************
    *             Twitter: @Hamza_Mega                  *
    *****************************************************
    *     blog: hamza-mega[dot]blogspot[dot]com         *
    *****************************************************
    *   E-mail: hamza[dot]megahed[at]gmail[dot]com      *
    *****************************************************

xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80

********************************
#include <stdio.h>
#include <string.h>
 
char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		  "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}
```

http://shell-storm.org/shellcode/files/shellcode-827.php

Shellcode test edelim:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/9.png)

Gayet güzel çalışıyor.
NOT: Test etmek için x86 kullanmak için -m32 parametresi ekledik sonuçta hedefimiz x86 ve yazının başında değindiğimiz nokta olan NX’i devre dışı bırakmak için -z execstack ekledik. Onu eklemezsek çalıştırdığımızda hata alırız. 

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/10.png)

Elimizde ihtiyacımız olan şeyler var şimdi payload build edelim. 

İlk önce shellcode yazıyoruz ve 5 byte padding ekliyoruz (23 + 5) ve sonra ise return adresi olarak “call eax” adresini verirsek oraya atlayıp hemen EAX’a atlayacak. Orda ise shellcode var. 

Shellcode + “A”*5 + 0x8048373

Not: little-endian dolayısıyla tersten yazmamız lazım.

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/11.png)

Test edelim:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/12.png)

Hata aldık! 

Bu konuda tecrübeli arkadaşlarımız zaten hemen nedenini anlamıştır. Yukarda da aslında ipucu vardı. Yazının yukarısında burda 2 önemli şey var demiştik. Bir tanesi ESP = EAX + 32. Yukarda shellcode fotoğrafında 5 adet push olduğunu görüyoruz. Bunu tam anlayamayan arkadaşlar debug edip A harflerini girdikten sonra memory set yaparlarsa exploiti manuel yerleştirip return adresini call eax yaparlarsa ve shellcode executiondan itibaren izlerlerse her push operationdan sonra shellcode’un geriden değiştiğini görürler. Bizim tek yapmamız gereken şey shellcode’un başına esp’ye eklemek:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/13.png)

```asm
section .text
	global _start

_start:

	add	esp,36
```

Bize lazım olan şey 3 byte ve artık shellcodemuz 23+3 = 26 byte uzunlukta. Yeni payload:

Addesp + shellcode + 2bytepadding + ret

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/14.png)

NOT: utf8 coding unutmayın.

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/15.png)

x.x.x.x girmek.

Üstünde oynamak

28 byte şekilli afilli birşey için kısa fakat bu durumu aşmak için lea kullanabiliriz. Return olduktan sonra call eax yapacak eğer ki biz oraya:

```asm
	lea	edx, [eax+40]
	call	edx
```

Gibi birşey yaparsak return adresinden sonraya atlarız oraya istediğimiz kadar şey yapabiliriz. 

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Pwn1/screenshots/16.png)

Flag.txt olduğunu bildiğimden flag.txt yazdım.
