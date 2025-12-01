# CryptoLab - Kriptografi Eğitim Aracı

Bu proje, Sifreleme-Bilimi-ve-Sifreleme-Teknikleri konusundaki teorik bilgileri pratiğe dökmek için hazırlanmış interaktif bir CLI uygulamasıdır.

## Modüller ve Özellikler

### 1. Sezar Şifreleme (Klasik-Simetrik)
*   Metinleri belirli bir kaydırma miktarı (anahtar) ile şifreler ve çözer.
*   **Brute Force Modu:** Şifreli bir metnin anahtarını bilmiyorsanız, 1'den 25'e kadar tüm olasılıkları deneyerek anlamlı metni bulmanızı sağlar.

### 2. Hash Laboratuvarı (Özetleme)
*   Metinlerin MD5, SHA-1 ve SHA-256 özetlerini çıkarır.
*   Dosyaların değişip değişmediğini (Bütünlük Kontrolü) anlamak için dosya hashleme yapar. Dosya yolu belirtilmezse varsayılan olarak `files/test.txt` kullanılır.
*   **Salt (Tuzlama) Simülasyonu:** Girilen parolanın 3 farklı güvenlik seviyesindeki (Zayıf, Güvenli, Çok Güvenli) hash halini karşılaştırmalı olarak gösterir ve neden tuzlanarak saklanması gerektiğini anlatır.

### 3. RSA Laboratuvarı (Asimetrik)
*   Ders dökümanında anlatılan matematiksel formülleri (`pow(m, e, n)`) adım adım uygulamanızı sağlar.
*   Kendi küçük asal sayılarınızı (p, q) girerek Public ve Private anahtarların nasıl oluştuğunu görebilirsiniz.
*   **Otomatik Asallık Kontrolü:** Girdiğiniz sayıların asal olup olmadığını kontrol eder ve hata durumunda uyarır.
*   Sayısal mesajları şifreleyebilir, çözebilir ve dijital imza simülasyonu yapabilirsiniz.

## 💡 Teorik Bilgi: Tuzlama ve Hash Algoritmaları

Bu proje, modern parola saklama standartlarının temeli olan "Salting" ve "Key Stretching" kavramlarını içerir.

### Tuzlama Nedir ve Neden Yapılır?
Kullanıcı parolaları veritabanlarında asla açık metin (plaintext) olarak saklanmaz; hash'lenerek (özeti çıkarılarak) saklanır. Ancak, `123456` gibi yaygın parolaların hash değerleri (örn: SHA256) saldırganlar tarafından önceden hesaplanıp "Rainbow Table" adı verilen tablolarda tutulur.

Saldırgan veritabanını ele geçirirse, elindeki hash değerini bu tablolarda aratarak saniyeler içinde orijinal parolayı bulabilir. **Tuzlama**, bu saldırıyı engellemek için parolaya rastgele veri ekleme işlemidir.

### Programın Kullandığı Yöntemler

#### 1. Seviye: Tuzsuz SHA-256 (ZAYIF)
*   `Hash = SHA256(Parola)`
*   **Risk:** Rainbow Table saldırılarına karşı tamamen savunmasızdır.

#### 2. Seviye: Tuzlu SHA-256 (GÜVENLİ)
*   `Hash = SHA256(Parola + Tuz)`
*   **Avantaj:** Her kullanıcı için benzersiz bir tuz (rastgele veri) üretildiği için Rainbow Table tabloları işe yaramaz. Saldırganın her tuz değeri için tabloyu baştan hesaplaması gerekir.
*   **Eksik:** SHA-256 çok hızlı çalışan bir algoritmadır. Güçlü bir GPU saniyede milyarlarca deneme yaparak kısa parolaları kaba kuvvet (brute-force) ile yine de çözebilir.

#### 3. Seviye: PBKDF2 (ÇOK GÜVENLİ - Endüstri Standardı)
*   **Algoritma:** Password-Based Key Derivation Function 2
*   **Mantık:** Tuzlama işlemini binlerce kez (Bu projede 100,000 kez) tekrarlar.
*   **Neden Önemli?** "Key Stretching" (Anahtar Uzatma) denilen bu işlem, hash alma süresini bilinçli olarak yavaşlatır. Bir kullanıcı giriş yaparken 0.1 saniye beklemeyi önemsemez ama saniyede milyarlarca deneme yapmak isteyen saldırgan için bu yavaşlık, saldırı maliyetini astronomik seviyelere çıkarır.

### Tuz (Salt) Nasıl Üretilir?
Tuz, tahmin edilemez olmalıdır. Bu projede Python'un `os.urandom()` fonksiyonu kullanılmıştır. Bu fonksiyon, işletim sisteminin entropi havuzunu (klavye vuruşları, donanım gürültüsü vb.) kullanarak **Kriptografik Olarak Güvenli (CSPRNG)** rastgele değerler üretir.

## Kurulum ve Çalıştırma

Herhangi bir kütüphane kurulumuna gerek yoktur. Python 3 yüklü olması yeterlidir.

1.  CryptoLab dizinine gidin:
    ```bash
    cd CryptoLab
    ```

2.  Uygulamayı başlatın:
    ```bash
    python3 crypto_lab.py
    ```

## Örnek Test Senaryoları

### Senaryo 1: Sezar Şifresini Kırmak
1.  Programı açın ve **1. Sezar Şifreleme** seçin.
2.  **3. Brute Force** seçeneğini seçin.
3.  Şu şifreli metni girin: `merhaba` (veya programda şifrelediğiniz başka bir metin).
4.  Programın tüm olasılıkları listelediğini gözlemleyin.

### Senaryo 2: Dosya Bütünlük Kontrolü (Hash)
1.  `files` klasöründeki `test.txt` dosyasını kullanacağız (Yoksa oluşturun: `echo "gizli" > files/test.txt`).
2.  Programda **2. Hash Laboratuvarı** > **2. Dosya Hashle** seçin.
3.  Dosya yolu sorulduğunda **Enter**'a basarak varsayılanı (`files/test.txt`) kabul edin. SHA-256 özetini not edin.
4.  Dosyayı değiştirin: `echo "degisti" >> files/test.txt`
5.  Tekrar hash alın ve özetin tamamen değiştiğini (Avalanche Effect) gözlemleyin.

### Senaryo 3: RSA Şifreleme
1.  **3. RSA Laboratuvarı** seçin.
2.  Program sizden iki asal sayı isteyecektir. Önce asal olmayan bir sayı (örn: **10**) girerek hata mesajını test edin.
3.  Ardından geçerli asal sayılar (örn: **7** ve **19**) girin.
4.  Program `N=133`, `T=108`, `Public Key=(e, n)`, `Private Key=(d, n)` değerlerini hesaplayacaktır.
5.  **a. Şifrele** seçin ve **99** sayısını girin.
5.  Sonucun şifrelenmiş halini not edin ve **b. Şifre Çöz** ile geri dönüştürün.

### Senaryo 4: Güvenli Parola Saklama (Salting)
1.  **2. Hash Laboratuvarı** > **3. Parola Tuzlama Simülasyonu** seçin.
2.  Parola olarak çok bilinen `123456` girin.
3.  Program size 3 farklı çıktı sunacaktır:
    *   **1. Seviye (Tuzsuz):** Çıkan hash'i Google'da aratarak ne kadar kolay bulunduğunu görün.
    *   **2. Seviye (Tuzlu):** Hash'in tamamen değiştiğini gözlemleyin.
    *   **3. Seviye (PBKDF2):** Hash üretiminin algoritma tarafından nasıl yavaşlatıldığını ve sonucun karmaşıklığını inceleyin.
4.  Güvenlik seviyeleri arasındaki farkı not edin.
