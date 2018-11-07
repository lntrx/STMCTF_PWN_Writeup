## STMCTF2018 papapawn sorusu çözümü

Birinci soruda olduğu gibi yine bize dosya verilmiş ve aynı şekilde bu dosyayı analiz ederek sunucuyu pwn etmeye çalışacağız. Hızlıca göz atalım dosyaya:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/1.png)

Çalıştırıp biraz bakalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/2.png)

Resimden çıkarılan sonuç:

    • Overflow yok, çünkü bizim girdiğimiz inputu kırpıyor.

```bash
objdump -S papapawn -M intel
```

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/3.png)

Biraz dikkatlice main’e bakarsak zaten 0x40 yani 64 byte’lık bir yer ile aldığını anlıyoruz. 

Demek ki overflow yok o zaman biraz daha debug edelim:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/4.png)

Çok ilginç bişey oldu. Printf var ama ilk arg olarak girdiğimiz A değerlerini alıyor. Halbuki şöyle bişey olmalıydı:

```c
printf(“seciminiz : %s\n”, “AAAA...”)
```

Konuya hakim arkadaşlar hemen anlamıştır. Burda bir string format var. Bu cebimizde kalsın biz debug etmeye devam edelim. 

Yukarıdaki fotoda anlaşıldığı gibi yolumuza devam ettiğimizde checkPassword fonksiyonuna atlıyoruz. Orda ise çok ilginç bişey var:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/5.png)

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/6.png)

Burda 0x804b06c adresinden değer alıp EAX’a atıyor. Ondan hemen sonraki işleme geldik EAX’a baktığımızda değer 0 ve onu 0x2a ile karşılaştırıyor. Bu değer char olarak (*) yıldız işaretine denk geliyor. Eğer ki eşik değilse(jne -> jump not equal) +21’e atla o adres zaten fotoda gözüküyor ilk önce nop sonra leave, fakat eğer ki eşit ise paraYatir fonksiyonuna atlıyor. Oraya bir göz atalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/7.png)

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/8.png)

Anlaşıldığı üzere biz parola adresine(0x804b06c) yıldız işareti yazdırırsak /bin/dash calıştıracak ve işi bitirmiş olacağız. 

Bilmeyen arkadaşlar için string format hakkında birkaç şey söyleyelim. String bastırırken %s ve benzeri escape kullanmak gerekir, aksi halde yazdığınız risk altındadır. Eğer ki saldırgan input yerine %x, %p gibi karakterler girerse memoryden okuyabilir. Örnek:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/9.png)

Gördüğünüz gibi %x basmak yerine memoryden hex değerleri basıyor. String format atağı adreslere byte yazmak ile olur. %n spesifier var ve bu specifier verilen adrese byte yazdırır. Uzun uzun anlatmak yerine kısaca bir foto ve fotonun linkini veriyim:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/10.png)

https://stackoverflow.com/questions/3401156/what-is-the-use-of-the-n-format-specifier-in-c

Val değeri ikinci printf’de 5 olmuş bunun nedeni %n’den önce 5 byte var(blah kelimesi 4 + bir adet boşluk). Bizim yapmamız gereken şey %n ile o adrese yazdırmak ama önce o adresi başa direkt erişim sağlamalıyız ve bunun için ise %<pattern>$n vererek memorydeki ilk adrese değilde 15. Adrese yazdırabiliriz. Önce pattern bulalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/11.png)

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/12.png)

Noktalar arasını sayarsak girdiğimiz AAAA harflerinin karşılığı olan 0x41414141 değerleri 15. Yerde saklanıyor yani %15$n yaparsak 0x41414141 adresine yazdırmaya çalışacağız. Debug edelim:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/13.png)

Bir hata aldık hemen bakalım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/14.png)

ESI değerini EAX’ın içindeki adresin içine yazdırmak istiyor ama bu adres valid değil bu yüzden fault aldık. 0x41414141 adresi yerine parola adresi olsa ve ESI değerini ise yıldız işareti yani 0x2a yaparsak tamamdır. 0x2a decimal olarak 42 eder uzun olarak adres(4byte) + 38 tane a girebiliriz ama kolay yolu %u kullanmak. 

Exploitimiz:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/15.png)

```python
#!/usr/bin/python

address = "\x6c\xb0\x04\x08" #804b06c

number = "%38u%15$n" # 4 byte address + 38u

print "1"
print address + number
```

NOT: little-endian
NOT: ilk girdi için 1\n

Çalıştıralım:

![screenshot](https://github.com/lntrx/STMCTF_PWN_Writeup/blob/master/Papapawn/screenshots/16.png)

./papapawn yerine nc -vv x.x.x.x 7777 yazıp çalıştırırsanız shell alırsınız flag zaten o dizindeydi
