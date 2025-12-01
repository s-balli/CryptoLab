import hashlib
import os
import random
import math
import sys

# --- YARDIMCI FONKSİYONLAR ---

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_input(prompt):
    return input(f"\033[94m{prompt}\033[0m")

def print_header(title):
    print("\n" + "="*60)
    print(f"   {title}")
    print("="*60)

def print_result(label, value):
    print(f"\033[92m{label}: \033[0m{value}")

def print_error(message):
    print(f"\033[91m[HATA] {message}\033[0m")

# --- 1. SEZAR ŞİFRELEME MODÜLÜ ---
class CaesarCipher:
    def encrypt(self, text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                # (Karakter Kodu - Başlangıç + Kaydırma) % 26 + Başlangıç
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result

    def decrypt(self, text, shift):
        return self.encrypt(text, -shift)

    def brute_force(self, text):
        print("\n--- Brute Force Saldırı Sonuçları ---")
        for shift in range(1, 26):
            decrypted = self.decrypt(text, shift)
            print(f"Anahtar {shift:02d}: {decrypted}")

# --- 2. HASH MODÜLÜ ---
class HashLab:
    def hash_text(self, text, algo='sha256'):
        if algo == 'md5':
            return hashlib.md5(text.encode()).hexdigest()
        elif algo == 'sha1':
            return hashlib.sha1(text.encode()).hexdigest()
        elif algo == 'sha256':
            return hashlib.sha256(text.encode()).hexdigest()
        else:
            return "Desteklenmeyen Algoritma"

    def hash_file(self, filepath, algo='sha256'):
        hash_func = getattr(hashlib, algo)()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    hash_func.update(byte_block)
            return hash_func.hexdigest()
        except FileNotFoundError:
            return None

    def generate_salt(self, length=16):
        """Rastgele hex string üretir (Tuz/Salt için)"""
        return os.urandom(length // 2).hex()

    def demonstrate_salting(self):
        print("\n--- PAROLA TUZLAMA (SALTING) VE GÜVENLİK SEVİYELERİ ---")
        print("AMAÇ: Parolaların veritabanında nasıl saklanması gerektiğini")
        print("ve güvenlik seviyeleri arasındaki farkları göstermektir.\n")
        
        password = get_input("Bir parola girin (Örn: 123456): ")
        salt = self.generate_salt(16) # 16 byte salt
        
        print("\n" + "-"*60)
        
        # SEVİYE 1: TUZSUZ (ZAYIF)
        unsalted = self.hash_text(password, 'sha256')
        print(f"\033[91m[1. SEVİYE - ZAYIF] Tuzsuz SHA-256\033[0m")
        print(f"   İşlem: SHA256('{password}')")
        print(f"   Sonuç: {unsalted}")
        print("   Yorum: Rainbow tablolarıyla anında kırılır. ASLA KULLANMAYIN.")
        
        print("-" * 60)

        # SEVİYE 2: TUZLU (GÜVENLİ)
        salted_input = password + salt
        salted_simple = self.hash_text(salted_input, 'sha256')
        print(f"\033[93m[2. SEVİYE - GÜVENLİ] Tuzlu (Salted) SHA-256\033[0m")
        print(f"   Tuz (Salt): {salt}")
        print(f"   İşlem: SHA256('{password}' + Tuz)")
        print(f"   Sonuç: {salted_simple}")
        print("   Yorum: Rainbow tablolarını engeller ancak kaba kuvvete (brute-force) karşı hala hızlı kırılabilir.")
        
        print("-" * 60)

        # SEVİYE 3: PBKDF2 (ÇOK GÜVENLİ - ENDÜSTRİ STANDARDI)
        iterations = 100000
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), iterations)
        pbkdf2_hash = dk.hex()
        
        print(f"\033[92m[3. SEVİYE - ÇOK GÜVENLİ] PBKDF2 (Tuzlu + İterasyonlu)\033[0m")
        print(f"   Algoritma: PBKDF2-HMAC-SHA256")
        print(f"   İterasyon: {iterations} kez döngü")
        print(f"   Sonuç: {pbkdf2_hash}")
        print("   Yorum: Yavaşlatma sayesinde saldırganın deneme hızını (Örn: Saniyede 1 milyar yerine 10 bin) düşürür.")
        print("-" * 60)

# --- 3. RSA EĞİTİM MODÜLÜ (Matematiksel Simülasyon) ---
class RSADemo:
    """
    Dökümandaki matematiksel temelleri gösteren basit RSA uygulaması.
    Not: Bu eğitim amaçlıdır, büyük sayılarla gerçek güvenlik sağlamaz.
    """
    def __init__(self):
        self.p = 0
        self.q = 0
        self.n = 0
        self.phi = 0
        self.e = 0
        self.d = 0
        self.public_key = None
        self.private_key = None

    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def is_prime(self, num):
        if num < 2:
            return False
        for i in range(2, int(math.sqrt(num)) + 1):
            if num % i == 0:
                return False
        return True

    def mod_inverse(self, e, phi):
        # d * e = 1 (mod phi) denklemini sağlayan d'yi bulur
        # Basit bir brute-force yaklaşımı (eğitim için yeterli küçük sayılarla)
        # Gerçek RSA'da Extended Euclidean algoritması kullanılır.
        for d in range(3, phi):
            if (d * e) % phi == 1:
                return d
        return None

    def generate_keys(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        
        # e seçimi: 1 < e < phi ve gcd(e, phi) = 1
        # Otomatik seçim veya dökümandaki gibi sabit bir değer denenebilir.
        # Biz 3'ten başlayarak uygun ilk sayıyı bulalım
        self.e = 2
        while self.e < self.phi:
            if self.gcd(self.e, self.phi) == 1:
                break
            self.e += 1
            
        self.d = self.mod_inverse(self.e, self.phi)
        
        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)
        
        return self.public_key, self.private_key

    def encrypt_number(self, message_int):
        # C = M^e mod n
        if message_int >= self.n:
            print_error(f"Mesaj ({message_int}), N ({self.n}) değerinden küçük olmalıdır!")
            return None
        return pow(message_int, self.e, self.n)

    def decrypt_number(self, cipher_int):
        # M = C^d mod n
        return pow(cipher_int, self.d, self.n)

    def sign_number(self, message_int):
        # İmza = M^d mod n (Gizli anahtarla şifreleme)
        return pow(message_int, self.d, self.n)

    def verify_signature(self, signature_int):
        # Doğrulama = S^e mod n (Açık anahtarla çözme)
        return pow(signature_int, self.e, self.n)

# --- ANA MENÜ ---

def main():
    caesar = CaesarCipher()
    hasher = HashLab()
    rsa = RSADemo()

    while True:
        print_header("CryptoLab - Kriptografi Eğitim Aracı")
        print("1. Sezar Şifreleme (Simetrik-Basit)")
        print("2. Hash Laboratuvarı (Özetleme)")
        print("3. RSA Laboratuvarı (Asimetrik-Matematiksel)")
        print("4. Çıkış")
        
        choice = get_input("Seçiminiz (1-4): ")

        if choice == '1':
            print("\n--- SEZAR ŞİFRELEME ---")
            print("1. Şifrele")
            print("2. Şifre Çöz")
            print("3. Brute Force (Saldırı Simülasyonu)")
            sub_choice = get_input("Seçim: ")
            
            text = get_input("Metin: ")
            
            if sub_choice == '1':
                shift = int(get_input("Kaydırma Miktarı (Örn: 3): "))
                print_result("Şifreli Metin", caesar.encrypt(text, shift))
            elif sub_choice == '2':
                shift = int(get_input("Kaydırma Miktarı: "))
                print_result("Çözülmüş Metin", caesar.decrypt(text, shift))
            elif sub_choice == '3':
                caesar.brute_force(text)

        elif choice == '2':
            print("\n--- HASH LABORATUVARI ---")
            print("1. Metin Hashle (MD5/SHA256)")
            print("2. Dosya Hashle")
            print("3. Parola Tuzlama (Salt) Simülasyonu")
            sub_choice = get_input("Seçim: ")
            
            if sub_choice == '1':
                text = get_input("Metin: ")
                print_result("MD5", hasher.hash_text(text, 'md5'))
                print_result("SHA-1", hasher.hash_text(text, 'sha1'))
                print_result("SHA-256", hasher.hash_text(text, 'sha256'))
            elif sub_choice == '2':
                path = get_input("Dosya Yolu (Varsayılan: files/test.txt): ") or "files/test.txt"
                res = hasher.hash_file(path, 'sha256')
                if res:
                    print_result("SHA-256", res)
                else:
                    print_error("Dosya bulunamadı.")
            elif sub_choice == '3':
                hasher.demonstrate_salting()

        elif choice == '3':
            print("\n--- RSA EĞİTİM SİMÜLASYONU ---")
            print("Dökümandaki matematiksel adımları uygular.")
            
            # Adım 1: Anahtar Üretimi
            print("\n[Adım 1] Anahtar Üretimi için iki ASAL sayı girin.")
            while True:
                try:
                    p = int(get_input("1. Asal Sayı (p) [Örn: 17, 23, 101, 211, 311, 401, 499...]: ") or 17)
                    q = int(get_input("2. Asal Sayı (q) [Örn: 37, 41, 151, 251, 353, 431, 491...]: ") or 37)
                    
                    if not rsa.is_prime(p):
                        print_error(f"{p} asal bir sayı değil. Lütfen asal bir sayı girin.")
                        continue
                    if not rsa.is_prime(q):
                        print_error(f"{q} asal bir sayı değil. Lütfen asal bir sayı girin.")
                        continue
                    if p == q:
                        print_error("p ve q farklı asal sayılar olmalıdır. Lütfen farklı asal sayılar girin.")
                        continue
                    
                    break # Geçerli p ve q alındıysa döngüden çık
                except ValueError:
                    print_error("Lütfen geçerli bir sayı girin.")
                    continue

            pub, priv = rsa.generate_keys(p, q)
            
            if not rsa.d:
                print_error("Uygun bir ters modül bulunamadı. Lütfen farklı asallar deneyin.")
                continue

            print("\n--- OLUŞTURULAN ANAHTARLAR ---")
            print(f"N (Modül) = {rsa.n} (p*q)")
            print(f"T (Totient) = {rsa.phi} ((p-1)*(q-1))")
            print_result("Genel Anahtar (Public Key - e, n)", pub)
            print_result("Özel Anahtar (Private Key - d, n)", priv)
            print("\n(Dökümandaki formül: D * E = 1 mod T)")
            
            # Adım 2: İşlemler
            while True:
                print("   RSA İşlemleri:")
                print("   a. Şifrele (Encrypt - Public Key ile)")
                print("   b. Şifre Çöz (Decrypt - Private Key ile)")
                print("   c. İmzala (Sign - Private Key ile)")
                print("   d. İmza Doğrula (Verify - Public Key ile)")
                print("   e. Ana Menüye Dön")
                
                op = get_input("   Seçim: ").lower()
                
                if op == 'a':
                    msg = int(get_input(f"   Şifrelenecek Sayı (MAX {rsa.n - 1}): "))
                    encrypted = rsa.encrypt_number(msg)
                    if encrypted is not None:
                        print_result("   Şifreli Veri (C)", encrypted)
                elif op == 'b':
                    cipher = int(get_input("   Şifreli Veri: "))
                    decrypted = rsa.decrypt_number(cipher)
                    print_result("   Çözülmüş Veri (M)", decrypted)
                elif op == 'c':
                    msg = int(get_input("   İmzalanacak Veri (Hash özeti varsayalım): "))
                    sign = rsa.sign_number(msg)
                    print_result("   Dijital İmza (S)", sign)
                elif op == 'd':
                    sign = int(get_input("   İmza Değeri: "))
                    verified = rsa.verify_signature(sign)
                    print_result("   Doğrulanan Orijinal Veri", verified)
                elif op == 'e':
                    break

        elif choice == '4':
            print("Çıkış yapılıyor...")
            break

if __name__ == "__main__":
    main()
