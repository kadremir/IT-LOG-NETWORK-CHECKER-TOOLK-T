import subprocess
import re
import requests
import socket
import os
import sys
import json
import logging
import ipaddress
from datetime import datetime
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from pathlib import Path
import hashlib
import urllib3

# SSL uyarılarını devre dışı bırak (production'da kaldır)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Konfigürasyon
YAPILANDIRMA = {
    'USOM_URL': 'https://www.usom.gov.tr/url-list.txt',
    'ZAMAN_ASIMI': 10,
    'MAKSIMUM_ISCI': 20,
    'LOG_SEVIYE': logging.INFO,
    'ONBELLEK_SURESI': 3600,  # 1 saat
    'SUPHE_ESIGI': {
        'basarisiz_giris': 5,
        'port_tarama': 10,
        'hata_orani': 0.1
    }
}

# Logging ayarları
logging.basicConfig(
    level=YAPILANDIRMA['LOG_SEVIYE'],
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('guvenlik_analizi.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class TehditIstihbarati:
    """Tehdit İstihbaratı entegrasyon sınıfı"""
    
    def __init__(self):
        self.usom_listesi = set()
        self.onbellek = {}
        self.onbellek_dosyasi = Path('.tehdit_onbellek.json')
        self._onbellek_yukle()
    
    def _onbellek_yukle(self):
        """Önbelleğe alınmış tehdit istihbaratı verilerini yükle"""
        if self.onbellek_dosyasi.exists():
            try:
                with open(self.onbellek_dosyasi, 'r', encoding='utf-8') as f:
                    veri = json.load(f)
                    if time.time() - veri.get('zaman_damgasi', 0) < YAPILANDIRMA['ONBELLEK_SURESI']:
                        self.onbellek = veri.get('onbellek', {})
                        logger.info(f"Önbellekten {len(self.onbellek)} kayıt yüklendi")
            except Exception as e:
                logger.warning(f"Önbellek yüklenemedi: {e}")
    
    def _onbellek_kaydet(self):
        """Tehdit istihbaratı önbelleğini kaydet"""
        try:
            onbellek_verisi = {
                'zaman_damgasi': time.time(),
                'onbellek': self.onbellek
            }
            with open(self.onbellek_dosyasi, 'w', encoding='utf-8') as f:
                json.dump(onbellek_verisi, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"Önbellek kaydedilemedi: {e}")
    
    def usom_listesi_getir(self):
        """USOM tehdit listesini yeniden deneme mekanizması ile getir"""
        maksimum_deneme = 3
        for deneme in range(maksimum_deneme):
            try:
                logger.info(f"USOM listesi getiriliyor (deneme {deneme + 1})")
                yanit = requests.get(
                    YAPILANDIRMA['USOM_URL'], 
                    timeout=YAPILANDIRMA['ZAMAN_ASIMI'],
                    headers={'User-Agent': 'Guvenlik-Analizor/1.0'}
                )
                yanit.raise_for_status()
                
                urller = set(yanit.text.splitlines())
                # URL'lerden IP'leri çıkar
                ip_deseni = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
                ipler = set()
                for url in urller:
                    eslesme = ip_deseni.findall(url)
                    ipler.update(eslesme)
                
                self.usom_listesi = ipler
                logger.info(f"USOM'dan {len(self.usom_listesi)} tehdit IP'si başarıyla getirildi")
                return True
                
            except Exception as e:
                logger.error(f"USOM listesi getirilemedi: {e}")
                if deneme == maksimum_deneme - 1:
                    logger.error("USOM getirmede maksimum deneme sayısı aşıldı")
                    return False
                time.sleep(2 ** deneme)  # Üstel geri çekilme
        
        return False
    
    def tehdit_durumu_kontrol(self, ip):
        """IP'nin tehdit listelerinde olup olmadığını kontrol et"""
        tehditler = []
        
        # USOM kontrolü
        if ip in self.usom_listesi:
            tehditler.append("USOM")
        
        # Özel IP kontrolü
        try:
            ip_objesi = ipaddress.ip_address(ip)
            if ip_objesi.is_private:
                return {"durum": "ozel", "tehditler": []}
        except ValueError:
            logger.warning(f"Geçersiz IP adresi: {ip}")
            return {"durum": "gecersiz", "tehditler": []}
        
        return {
            "durum": "zararli" if tehditler else "temiz",
            "tehditler": tehditler
        }
    
    def coğrafi_ip_sorgulama(self, ip):
        """Önbellekleme ile geliştirilmiş Coğrafi IP sorgulaması"""
        if ip in self.onbellek:
            return self.onbellek[ip]
        
        # Özel IP'leri atla
        try:
            if ipaddress.ip_address(ip).is_private:
                return {"hata": "Özel IP"}
        except ValueError:
            return {"hata": "Geçersiz IP"}
        
        try:
            # Birincil GeoIP servisi
            url = f"https://ipwho.is/{ip}"
            yanit = requests.get(url, timeout=5)
            yanit.raise_for_status()
            veri = yanit.json()
            
            if veri.get("success", False):
                cografi_bilgi = {
                    "ulke": veri.get("country"),
                    "sehir": veri.get("city"),
                    "bolge": veri.get("region"),
                    "asn": veri.get("connection", {}).get("asn"),
                    "isp": veri.get("connection", {}).get("isp"),
                    "organizasyon": veri.get("connection", {}).get("org"),
                    "saat_dilimi": veri.get("timezone", {}).get("id"),
                    "proxy_mi": veri.get("security", {}).get("is_proxy", False),
                    "tor_mu": veri.get("security", {}).get("is_tor", False)
                }
                self.onbellek[ip] = cografi_bilgi
                return cografi_bilgi
                
        except Exception as e:
            logger.error(f"{ip} için GeoIP sorgulaması başarısız: {e}")
        
        return {"hata": "Sorgulama başarısız"}

class AgAnalizci:
    """Ağ bağlantısı analizci"""
    
    def ag_baglantilari_al(self):
        """Detaylı bilgi ile ağ bağlantılarını al"""
        baglantilar = []
        
        try:
            # Windows ve Linux uyumlu netstat
            if sys.platform.startswith('win'):
                komut = "netstat -ano"
            else:
                komut = "netstat -tunap"
            
            sonuc = subprocess.run(
                komut.split(),
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if sonuc.returncode != 0:
                logger.error(f"Netstat başarısız: {sonuc.stderr}")
                return []
            
            # Netstat çıktısını ayrıştır
            satirlar = sonuc.stdout.split('\n')
            for satir in satirlar:
                if 'ESTABLISHED' in satir or 'LISTEN' in satir:
                    parcalar = satir.split()
                    if len(parcalar) >= 4:
                        yerel_adres = parcalar[1] if sys.platform.startswith('win') else parcalar[3]
                        uzak_adres = parcalar[2] if sys.platform.startswith('win') else parcalar[4]
                        durum = 'KURULDU' if 'ESTABLISHED' in satir else 'DİNLİYOR'
                        
                        # IP ve portu çıkar
                        try:
                            if ':' in uzak_adres and uzak_adres != '*:*':
                                ip = uzak_adres.rsplit(':', 1)[0]
                                port = uzak_adres.rsplit(':', 1)[1]
                                
                                # IP'yi doğrula
                                ipaddress.ip_address(ip)
                                
                                baglantilar.append({
                                    'yerel_adres': yerel_adres,
                                    'uzak_ip': ip,
                                    'uzak_port': port,
                                    'durum': durum,
                                    'protokol': 'TCP'  # Kurulmuş bağlantılar için TCP varsayıyoruz
                                })
                        except (ValueError, IndexError):
                            continue
            
            logger.info(f"{len(baglantilar)} ağ bağlantısı bulundu")
            return baglantilar
            
        except subprocess.TimeoutExpired:
            logger.error("Netstat komutu zaman aşımına uğradı")
        except Exception as e:
            logger.error(f"Ağ bağlantıları alınamadı: {e}")
        
        return []
    
    def benzersiz_ipler_cikar(self, baglantilar):
        """Bağlantılardan benzersiz uzak IP'leri çıkar"""
        ipler = set()
        for baglanti in baglantilar:
            ip = baglanti.get('uzak_ip')
            if ip and not ip.startswith(('127.', '0.', '255.')):
                ipler.add(ip)
        
        # Harici analiz için özel IP'leri filtrele
        harici_ipler = set()
        for ip in ipler:
            try:
                ip_objesi = ipaddress.ip_address(ip)
                if not ip_objesi.is_private:
                    harici_ipler.add(ip)
            except ValueError:
                continue
        
        return list(ipler), list(harici_ipler)

class LogAnalizci:
    """Güvenlik olayları için gelişmiş log analizci"""
    
    def __init__(self):
        # Farklı sistemler için log desenlerini tanımla
        self.desenler = {
            'ssh_basarisiz': [
                r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)',
                r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)',
                r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)',
                r'Başarısız şifre.*(\d+\.\d+\.\d+\.\d+)',
                r'Kimlik doğrulama hatası.*(\d+\.\d+\.\d+\.\d+)'
            ],
            'kaba_kuvvet': [
                r'message repeated \d+ times.*Failed password',
                r'Too many authentication failures for (\S+)',
                r'Çok fazla kimlik doğrulama hatası.*(\S+)'
            ],
            'port_tarama': [
                r'Port scan detected from (\d+\.\d+\.\d+\.\d+)',
                r'Possible port scan.*from (\d+\.\d+\.\d+\.\d+)',
                r'Port taraması tespit edildi.*(\d+\.\d+\.\d+\.\d+)'
            ],
            'zararlı_yazilim': [
                r'Malware detected.*from (\d+\.\d+\.\d+\.\d+)',
                r'Virus.*(\d+\.\d+\.\d+\.\d+)',
                r'Zararlı yazılım tespit edildi.*(\d+\.\d+\.\d+\.\d+)'
            ],
            'dos_saldiri': [
                r'DDoS.*from (\d+\.\d+\.\d+\.\d+)',
                r'Flooding detected.*(\d+\.\d+\.\d+\.\d+)',
                r'Sel saldırısı tespit edildi.*(\d+\.\d+\.\d+\.\d+)'
            ]
        }
        
        # Sisteme özgü log yolları
        if sys.platform.startswith('win'):
            self.log_yollari = [
                r'C:\Windows\System32\winevt\Logs\Security.evtx',
                r'C:\Windows\System32\winevt\Logs\System.evtx',
                r'C:\Windows\System32\LogFiles\W3SVC1\*.log'
            ]
        else:
            self.log_yollari = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/secure',
                '/var/log/messages',
                '/var/log/apache2/access.log',
                '/var/log/nginx/access.log',
                '/var/log/fail2ban.log'
            ]
    
    def loglari_analiz_et(self):
        """Kapsamlı log analizi"""
        sonuclar = {
            'basarisiz_girisler': defaultdict(int),
            'kaba_kuvvet': defaultdict(int),
            'port_taramalari': defaultdict(int),
            'zararli_yazilim_girisimleri': defaultdict(int),
            'dos_girisimleri': defaultdict(int),
            'suheli_ipler': set(),
            'hata_ozeti': Counter()
        }
        
        for log_yolu in self.log_yollari:
            if not os.path.exists(log_yolu):
                continue
            
            try:
                logger.info(f"Log dosyası analiz ediliyor: {log_yolu}")
                with open(log_yolu, 'r', encoding='utf-8', errors='ignore') as f:
                    for satir_no, satir in enumerate(f, 1):
                        self._log_satirini_analiz_et(satir, sonuclar)
                        
                        # Bellek sorunlarını önlemek için parçalar halinde işle
                        if satir_no % 10000 == 0:
                            logger.debug(f"{log_yolu} dosyasından {satir_no} satır işlendi")
                            
            except Exception as e:
                logger.error(f"{log_yolu} analiz edilemedi: {e}")
        
        # Eşiklere dayalı şüpheli IP'leri belirle
        for ip, sayi in sonuclar['basarisiz_girisler'].items():
            if sayi >= YAPILANDIRMA['SUPHE_ESIGI']['basarisiz_giris']:
                sonuclar['suheli_ipler'].add(ip)
        
        return sonuclar
    
    def _log_satirini_analiz_et(self, satir, sonuclar):
        """Tek log satırını analiz et"""
        # Başarısız giriş denemeleri
        for desen in self.desenler['ssh_basarisiz']:
            eslesmeler = re.finditer(desen, satir)
            for eslesme in eslesmeler:
                if len(eslesme.groups()) >= 2:
                    ip = eslesme.group(2)
                    sonuclar['basarisiz_girisler'][ip] += 1
                else:
                    ip = eslesme.group(1)
                    if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                        sonuclar['basarisiz_girisler'][ip] += 1
        
        # Kaba kuvvet tespiti
        for desen in self.desenler['kaba_kuvvet']:
            if re.search(desen, satir):
                ip_eslesmeler = re.findall(r'\d+\.\d+\.\d+\.\d+', satir)
                for ip in ip_eslesmeler:
                    sonuclar['kaba_kuvvet'][ip] += 1
        
        # Port tarama tespiti
        for desen in self.desenler['port_tarama']:
            eslesmeler = re.finditer(desen, satir)
            for eslesme in eslesmeler:
                ip = eslesme.group(1)
                sonuclar['port_taramalari'][ip] += 1
        
        # Zararlı yazılım tespiti
        for desen in self.desenler['zararlı_yazilim']:
            eslesmeler = re.finditer(desen, satir)
            for eslesme in eslesmeler:
                ip = eslesme.group(1)
                sonuclar['zararli_yazilim_girisimleri'][ip] += 1
        
        # DoS saldırısı tespiti
        for desen in self.desenler['dos_saldiri']:
            eslesmeler = re.finditer(desen, satir)
            for eslesme in eslesmeler:
                ip = eslesme.group(1)
                sonuclar['dos_girisimleri'][ip] += 1
        
        # Hata/Uyarı kategorilendirme
        if any(anahtar in satir.lower() for anahtar in ['error', 'warning', 'critical', 'alert', 'hata', 'uyarı', 'kritik']):
            # Servis adını çıkar
            parcalar = satir.split()
            if len(parcalar) > 4:
                servis = parcalar[4].rstrip(':')
                sonuclar['hata_ozeti'][servis] += 1

class GuvenlikAnalizci:
    """Ana güvenlik analizci orkestratörü"""
    
    def __init__(self):
        self.tehdit_istihbarati = TehditIstihbarati()
        self.ag_analizci = AgAnalizci()
        self.log_analizci = LogAnalizci()
    
    def analizi_calistir(self):
        """Kapsamlı güvenlik analizi çalıştır"""
        logger.info("Kapsamlı güvenlik analizi başlatılıyor")
        
        # Tehdit istihbaratını başlat
        logger.info("Tehdit istihbaratı başlatılıyor...")
        self.tehdit_istihbarati.usom_listesi_getir()
        
        # Ağ analizi
        logger.info("Ağ bağlantıları analiz ediliyor...")
        baglantilar = self.ag_analizci.ag_baglantilari_al()
        tum_ipler, harici_ipler = self.ag_analizci.benzersiz_ipler_cikar(baglantilar)
        
        # Log analizi
        logger.info("Güvenlik logları analiz ediliyor...")
        log_sonuclari = self.log_analizci.loglari_analiz_et()
        
        # Analiz için tüm IP'leri birleştir
        analiz_ipleri = set(harici_ipler) | log_sonuclari['suheli_ipler']
        
        logger.info(f"{len(analiz_ipleri)} benzersiz IP analiz ediliyor...")
        
        # Performans için threading ile IP'leri analiz et
        ip_analizi = {}
        with ThreadPoolExecutor(max_workers=YAPILANDIRMA['MAKSIMUM_ISCI']) as executor:
            gelecek_ip = {
                executor.submit(self._ip_analiz_et, ip): ip 
                for ip in analiz_ipleri
            }
            
            for gelecek in as_completed(gelecek_ip):
                ip = gelecek_ip[gelecek]
                try:
                    sonuc = gelecek.result()
                    ip_analizi[ip] = sonuc
                except Exception as e:
                    logger.error(f"IP {ip} analiz edilemedi: {e}")
                    ip_analizi[ip] = {"hata": str(e)}
        
        # Kapsamlı rapor oluştur
        self._rapor_olustur(baglantilar, log_sonuclari, ip_analizi)
        
        # Önbelleği kaydet
        self.tehdit_istihbarati._onbellek_kaydet()
        
        logger.info("Güvenlik analizi tamamlandı")
    
    def _ip_analiz_et(self, ip):
        """Tek IP adresini analiz et"""
        sonuc = {
            'ip': ip,
            'tehdit_durumu': self.tehdit_istihbarati.tehdit_durumu_kontrol(ip),
            'cografi_bilgi': self.tehdit_istihbarati.coğrafi_ip_sorgulama(ip),
            'risk_puani': 0
        }
        
        # Risk puanını hesapla
        if sonuc['tehdit_durumu']['durum'] == 'zararli':
            sonuc['risk_puani'] += 100
        
        cografi = sonuc['cografi_bilgi']
        if not cografi.get('hata'):
            if cografi.get('proxy_mi') or cografi.get('tor_mu'):
                sonuc['risk_puani'] += 50
            
            # Yüksek riskli ülkeler (örnek)
            yuksek_riskli_ulkeler = ['China', 'Russia', 'North Korea', 'Iran', 'Çin', 'Rusya', 'Kuzey Kore', 'İran']
            ulke = cografi.get('ulke', '')
            if any(riskli in ulke for riskli in yuksek_riskli_ulkeler):
                sonuc['risk_puani'] += 25
        
        return sonuc
    
    def _rapor_olustur(self, baglantilar, log_sonuclari, ip_analizi):
        """Kapsamlı güvenlik raporu oluştur"""
        print("\n" + "="*80)
        print("🔒 KAPSAMLI GÜVENLİK ANALİZ RAPORU")
        print("="*80)
        print(f"Analiz Zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Toplam Ağ Bağlantısı: {len(baglantilar)}")
        print(f"Analiz Edilen Benzersiz IP: {len(ip_analizi)}")
        
        # Tehdit Özeti
        print("\n📊 TEHDİT İSTİHBARATI ÖZETİ")
        print("-" * 40)
        zararli_sayi = sum(1 for analiz in ip_analizi.values() 
                          if analiz.get('tehdit_durumu', {}).get('durum') == 'zararli')
        yuksek_risk_sayi = sum(1 for analiz in ip_analizi.values() 
                              if analiz.get('risk_puani', 0) >= 50)
        
        print(f"🚨 Zararlı IP'ler: {zararli_sayi}")
        print(f"⚠️  Yüksek Riskli IP'ler: {yuksek_risk_sayi}")
        print(f"✅ Temiz IP'ler: {len(ip_analizi) - zararli_sayi}")
        
        # Detaylı IP Analizi
        print("\n🌐 DETAYLI IP ANALİZİ")
        print("-" * 40)
        
        # Risk puanına göre sırala
        sirali_ipler = sorted(ip_analizi.items(), 
                             key=lambda x: x[1].get('risk_puani', 0), 
                             reverse=True)
        
        for ip, analiz in sirali_ipler:
            risk_puani = analiz.get('risk_puani', 0)
            tehdit_durumu = analiz.get('tehdit_durumu', {})
            cografi_bilgi = analiz.get('cografi_bilgi', {})
            
            # Risk göstergesi
            if risk_puani >= 100:
                risk_gostergesi = "🚨 KRİTİK"
            elif risk_puani >= 50:
                risk_gostergesi = "⚠️  YÜKSEK"
            elif risk_puani >= 25:
                risk_gostergesi = "🔶 ORTA"
            else:
                risk_gostergesi = "✅ DÜŞÜK"
            
            print(f"\n--- {ip} [{risk_gostergesi} - Puan: {risk_puani}] ---")
            
            # Tehdit bilgisi
            if tehdit_durumu.get('tehditler'):
                print(f"   🛡️  Tehdit Listeleri: {', '.join(tehdit_durumu['tehditler'])}")
            
            # Coğrafi bilgi
            if not cografi_bilgi.get('hata'):
                ulke = cografi_bilgi.get('ulke', 'Bilinmiyor')
                sehir = cografi_bilgi.get('sehir', 'Bilinmiyor')
                isp = cografi_bilgi.get('isp', 'Bilinmiyor')
                asn = cografi_bilgi.get('asn', 'Bilinmiyor')
                
                print(f"   🌍 Konum: {sehir}, {ulke}")
                print(f"   🏢 ISP: {isp} (ASN {asn})")
                
                if cografi_bilgi.get('proxy_mi'):
                    print("   🔀 Proxy tespit edildi")
                if cografi_bilgi.get('tor_mu'):
                    print("   🧅 Tor çıkış düğümü tespit edildi")
        
        # Log Analizi Sonuçları
        print(f"\n📋 LOG ANALİZİ SONUÇLARI")
        print("-" * 40)
        print(f"Başarısız Giriş Denemeleri: {len(log_sonuclari['basarisiz_girisler'])}")
        print(f"Kaba Kuvvet Denemeleri: {len(log_sonuclari['kaba_kuvvet'])}")
        print(f"Port Tarama Denemeleri: {len(log_sonuclari['port_taramalari'])}")
        print(f"Zararlı Yazılım Girişimleri: {len(log_sonuclari['zararli_yazilim_girisimleri'])}")
        print(f"DoS Saldırı Girişimleri: {len(log_sonuclari['dos_girisimleri'])}")
        print(f"Loglardan Şüpheli IP'ler: {len(log_sonuclari['suheli_ipler'])}")
        
        if log_sonuclari['basarisiz_girisler']:
            print("\n🔐 EN ÇOK BAŞARISIZ GİRİŞ KAYNAKLARI:")
            sirali_basarisiz = sorted(log_sonuclari['basarisiz_girisler'].items(), 
                                    key=lambda x: x[1], reverse=True)[:10]
            for ip, sayi in sirali_basarisiz:
                durum = "🚨" if ip in [i for i, a in ip_analizi.items() 
                                     if a.get('tehdit_durumu', {}).get('durum') == 'zararli'] else "⚠️"
                print(f"   {durum} {ip}: {sayi} deneme")
        
        if log_sonuclari['kaba_kuvvet']:
            print("\n💥 KABA KUVVET SALDIRI KAYNAKLARI:")
            sirali_kaba_kuvvet = sorted(log_sonuclari['kaba_kuvvet'].items(), 
                                      key=lambda x: x[1], reverse=True)[:10]
            for ip, sayi in sirali_kaba_kuvvet:
                durum = "🚨" if ip in [i for i, a in ip_analizi.items() 
                                     if a.get('tehdit_durumu', {}).get('durum') == 'zararli'] else "⚠️"
                print(f"   {durum} {ip}: {sayi} saldırı")
        
        if log_sonuclari['port_taramalari']:
            print("\n🔍 PORT TARAMA KAYNAKLARI:")
            sirali_port_tarama = sorted(log_sonuclari['port_taramalari'].items(), 
                                       key=lambda x: x[1], reverse=True)[:10]
            for ip, sayi in sirali_port_tarama:
                durum = "🚨" if ip in [i for i, a in ip_analizi.items() 
                                     if a.get('tehdit_durumu', {}).get('durum') == 'zararli'] else "⚠️"
                print(f"   {durum} {ip}: {sayi} tarama")
        
        if log_sonuclari['zararli_yazilim_girisimleri']:
            print("\n🦠 ZARARLI YAZILIM GİRİŞİMLERİ:")
            sirali_zararli = sorted(log_sonuclari['zararli_yazilim_girisimleri'].items(), 
                                   key=lambda x: x[1], reverse=True)[:10]
            for ip, sayi in sirali_zararli:
                durum = "🚨" if ip in [i for i, a in ip_analizi.items() 
                                     if a.get('tehdit_durumu', {}).get('durum') == 'zararli'] else "⚠️"
                print(f"   {durum} {ip}: {sayi} girişim")
        
        if log_sonuclari['dos_girisimleri']:
            print("\n💣 DoS SALDIRI GİRİŞİMLERİ:")
            sirali_dos = sorted(log_sonuclari['dos_girisimleri'].items(), 
                               key=lambda x: x[1], reverse=True)[:10]
            for ip, sayi in sirali_dos:
                durum = "🚨" if ip in [i for i, a in ip_analizi.items() 
                                     if a.get('tehdit_durumu', {}).get('durum') == 'zararli'] else "⚠️"
                print(f"   {durum} {ip}: {sayi} saldırı")
        
        if log_sonuclari['hata_ozeti']:
            print("\n⚠️  EN ÇOK HATA VEREN SERVİSLER:")
            for servis, sayi in log_sonuclari['hata_ozeti'].most_common(10):
                print(f"   {servis}: {sayi} hata/uyarı")
        
        # Öneriler
        print(f"\n💡 GÜVENLİK ÖNERİLERİ")
        print("-" * 40)
        
        oneriler = []
        if zararli_sayi > 0:
            oneriler.append("🚫 Zararlı IP'leri derhal engelleyin")
        if yuksek_risk_sayi > 0:
            oneriler.append("🔍 Yüksek riskli IP bağlantılarını araştırın")
        if len(log_sonuclari['basarisiz_girisler']) > 10:
            oneriler.append("🛡️  Fail2ban veya benzeri koruma uygulayın")
        if len(log_sonuclari['port_taramalari']) > 0:
            oneriler.append("🔒 Firewall kurallarını gözden geçirin ve gereksiz portları kapatın")
        if len(log_sonuclari['kaba_kuvvet']) > 0:
            oneriler.append("🔐 Güçlü parola politikaları uygulayın")
        if len(log_sonuclari['dos_girisimleri']) > 0:
            oneriler.append("🛡️  DDoS koruma sistemleri kurun")
        
        oneriler.extend([
            "🔄 Gerçek zamanlı izlemeyi etkinleştirin",
            "📊 Otomatik uyarı sistemleri kurun",
            "🔐 Kimlik doğrulama mekanizmalarını gözden geçirin",
            "📝 Kapsamlı loglama uygulayın",
            "🔄 Düzenli güvenlik taramalarını planlayın",
            "👥 Güvenlik ekibi eğitimlerini düzenleyin",
            "📋 Olay müdahale planlarını güncelleyin",
            "🔍 Penetrasyon testleri yaptırın"
        ])
        
        for oneri in oneriler:
            print(f"   {oneri}")
        
        # Özet İstatistikler
        print(f"\n📈 ÖZET İSTATİSTİKLER")
        print("-" * 40)
        toplam_saldiri = (len(log_sonuclari['basarisiz_girisler']) + 
                          len(log_sonuclari['kaba_kuvvet']) + 
                          len(log_sonuclari['port_taramalari']) + 
                          len(log_sonuclari['dos_girisimleri']))
        
        print(f"📊 Toplam Saldırı Girişimi: {toplam_saldiri}")
        print(f"🎯 Risk Değerlendirme Puanı: {min(100, (zararli_sayi * 20) + (yuksek_risk_sayi * 10))}/100")
        
        if toplam_saldiri > 100:
            print("🔴 Güvenlik Durumu: KRİTİK")
        elif toplam_saldiri > 50:
            print("🟠 Güvenlik Durumu: YÜKSEK RİSK")
        elif toplam_saldiri > 10:
            print("🟡 Güvenlik Durumu: ORTA RİSK")
        else:
            print("🟢 Güvenlik Durumu: DÜŞÜK RİSK")
        
        print("\n" + "="*80)

def main():
    """Ana giriş noktası"""
    try:
        print("🚀 Gelişmiş Ağ Güvenlik Analiz Aracı başlatılıyor...")
        print("-" * 50)
        analizci = GuvenlikAnalizci()
        analizci.analizi_calistir()
        print("\n✅ Analiz başarıyla tamamlandı!")
    except KeyboardInterrupt:
        logger.info("Analiz kullanıcı tarafından durduruldu")
        print("\n⏹️  Analiz durduruldu.")
    except Exception as e:
        logger.error(f"Analiz başarısız: {e}")
        print(f"\n❌ Analiz hatası: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()