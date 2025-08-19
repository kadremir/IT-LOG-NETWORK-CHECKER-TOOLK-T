# IT-LOG-NETWORK-CHECKER-TOOLKİT
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success)](https://github.com)

## 🚀 Özellikler

### 📊 Tehdit İstihbaratı
- **USOM Entegrasyonu**: Türkiye USOM (Ulusal Siber Olayları Müdahale Merkezi) tehdit listesi ile otomatik kontrol
- **GeoIP Analizi**: IP adreslerinin coğrafi konumu, ISP bilgileri ve risk değerlendirmesi
- **Proxy/Tor Tespiti**: Anonimleştirilmiş trafik ve gizli servis kullanımının tespiti

### 🌐 Ağ Analizi
- **Gerçek Zamanlı Bağlantı İzleme**: Aktif ağ bağlantılarının detaylı analizi
- **Risk Puanlama Sistemi**: 0-100 arası otomatik risk puanı hesaplama
- **Çoklu Platform Desteği**: Windows ve Linux işletim sistemleri için optimize edilmiş

### 📋 Log Analizi
- **Güvenlik Olay Tespiti**: Başarısız giriş denemeleri, kaba kuvvet saldırıları
- **Saldırı Kategorilendirme**: Port tarama, zararlı yazılım, DoS saldırıları
- **Otomatik Pattern Matching**: Türkçe ve İngilizce log desenleri

### 🎯 Performans Optimizasyonu
- **Çoklu İş Parçacığı**: Paralel IP analizi ile hızlandırılmış performans
- **Akıllı Önbellekleme**: GeoIP sorguları için otomatik önbellek sistemi
- **Bellek Optimizasyonu**: Büyük log dosyaları için verimli işleme

## 📸 Örnek Çıktı

```
🚀 Gelişmiş Ağ Güvenlik Analiz Aracı başlatılıyor...
--------------------------------------------------
2025-08-20 02:43:36,227 - INFO - Kapsamlı güvenlik analizi başlatılıyor
2025-08-20 02:43:38,986 - INFO - USOM'dan 12480 tehdit IP'si başarıyla getirildi
2025-08-20 02:43:39,046 - INFO - 60 ağ bağlantısı bulundu

================================================================================
🔒 KAPSAMLI GÜVENLİK ANALİZ RAPORU
================================================================================
Analiz Zamanı: 2025-08-20 02:43:39
Toplam Ağ Bağlantısı: 60
Analiz Edilen Benzersiz IP: 19

📊 TEHDİT İSTİHBARATI ÖZETİ
----------------------------------------
🚨 Zararlı IP'ler: 0
⚠️  Yüksek Riskli IP'ler: 0
✅ Temiz IP'ler: 19

🌐 DETAYLI IP ANALİZİ
----------------------------------------
--- 172.64.148.235 [✅ DÜŞÜK - Puan: 0] ---
   🌍 Konum: San Francisco, United States
   🏢 ISP: Cloudflare, Inc. (ASN 13335)

💡 GÜVENLİK ÖNERİLERİ
----------------------------------------
   🔄 Gerçek zamanlı izlemeyi etkinleştirin
   📊 Otomatik uyarı sistemleri kurun
   🔐 Kimlik doğrulama mekanizmalarını gözden geçirin
   🟢 Güvenlik Durumu: DÜŞÜK RİSK
```

## 🛠️ Kurulum

### Gereksinimler
```bash
Python 3.7+
```

### Bağımlılıklar
```bash
pip install requests ipaddress
```

### Kurulum
```bash
git clone https://github.com/[username]/network-security-analyzer.git
cd network-security-analyzer
pip install -r requirements.txt
```

## 🚀 Kullanım

### Temel Çalıştırma
```bash
python guvenlik_analizi.py
```

### Yönetici Yetkisi ile Çalıştırma (Önerilen)
```bash
# Windows
runas /user:Administrator python guvenlik_analizi.py

# Linux
sudo python3 guvenlik_analizi.py
```

## 📊 Analiz Sonuçları

### Risk Seviyeleri
- 🚨 **KRİTİK** (100+ puan): Bilinen zararlı IP'ler
- ⚠️ **YÜKSEK** (50-99 puan): Proxy/Tor kullanımı, şüpheli aktivite
- 🔶 **ORTA** (25-49 puan): Risk ülkelerinden bağlantılar
- ✅ **DÜŞÜK** (0-24 puan): Temiz, güvenli bağlantılar

### Tespit Edilen Saldırı Türleri
- **Kaba Kuvvet Saldırıları**: Sistematik şifre deneme girişimleri
- **Port Tarama**: Açık port arama girişimleri
- **DoS/DDoS**: Hizmet durdurma saldırıları
- **Zararlı Yazılım**: Malware ve trojan aktiviteleri

## 🔧 Konfigürasyon

Aracın davranışını özelleştirmek için `YAPILANDIRMA` bölümünü düzenleyin:

```python
YAPILANDIRMA = {
    'USOM_URL': 'https://www.usom.gov.tr/url-list.txt',
    'ZAMAN_ASIMI': 10,
    'MAKSIMUM_ISCI': 20,
    'SUPHE_ESIGI': {
        'basarisiz_giris': 5,
        'port_tarama': 10,
        'hata_orani': 0.1
    }
}
```

## 📁 Dosya Yapısı

```
network-security-analyzer/
├── guvenlik_analizi.py          # Ana program dosyası
├── .tehdit_onbellek.json        # Önbellek dosyası (otomatik oluşur)
├── guvenlik_analizi.log         # Log dosyası (otomatik oluşur)
├── requirements.txt             # Python bağımlılıkları
└── README.md                   # Bu dosya
```

## 🔍 Log Analizi

Araç aşağıdaki log dosyalarını otomatik olarak analiz eder:

### Windows
- `C:\Windows\System32\winevt\Logs\Security.evtx`
- `C:\Windows\System32\winevt\Logs\System.evtx`

### Linux
- `/var/log/auth.log`
- `/var/log/syslog`
- `/var/log/secure`
- `/var/log/fail2ban.log`

## 🛡️ Güvenlik Özellikleri

### Güvenli Kod Uygulamaları
- ✅ **Input Validation**: Tüm girişler doğrulanır
- ✅ **Command Injection Koruması**: Güvenli subprocess kullanımı
- ✅ **Timeout Mekanizmaları**: Ağ isteklerinde zaman aşımı
- ✅ **Error Handling**: Kapsamlı hata yönetimi

### Gizlilik
- 🔒 **Yerel İşlem**: Tüm analizler yerel makinede yapılır
- 🔒 **Veri Saklama**: Kişisel veriler saklanmaz
- 🔒 **Önbellek Güvenliği**: Geçici veriler şifrelenmez ancak yerel kalır

## 🤝 Katkıda Bulunma

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/yeni-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik eklendi'`)
4. Branch'inizi push edin (`git push origin feature/yeni-ozellik`)
5. Pull Request oluşturun

## 📋 To-Do Listesi

- [ ] **Dashboard Arayüzü**: Web tabanlı görsel arayüz
- [ ] **Real-time Monitoring**: Gerçek zamanlı tehdit izleme
- [ ] **Email Alerting**: Otomatik email uyarıları
- [ ] **Database Integration**: PostgreSQL/MySQL entegrasyonu
- [ ] **API Endpoint**: RESTful API desteği
- [ ] **Docker Support**: Konteyner desteği
- [ ] **Multi-language**: İngilizce dil desteği

## ⚠️ Yasal Uyarı

Bu araç yalnızca **yasal** ve **etik** amaçlarla kullanılmalıdır:
- ✅ Kendi sistemlerinizin güvenlik analizi
- ✅ Yetkilendirilmiş penetrasyon testleri
- ✅ Güvenlik araştırmaları
- ❌ İzinsiz sistem taraması
- ❌ Saldırı amaçlı kullanım

## 🐛 Bilinen Sorunlar

### Windows Yetki Sorunu
```
ERROR - Permission denied: 'C:\Windows\System32\winevt\Logs\Security.evtx'
```
**Çözüm**: Programı yönetici yetkisi ile çalıştırın.

### Linux Log Erişimi
```
ERROR - /var/log/auth.log analiz edilemedi: Permission denied
```
**Çözüm**: `sudo` ile çalıştırın veya log dosyalarına okuma yetkisi verin.

## 📊 Performans Metrikleri

| Metrik | Değer |
|--------|--------|
| **IP Analiz Hızı** | ~50 IP/saniye |
| **Log İşleme** | ~10,000 satır/saniye |
| **Bellek Kullanımı** | <100MB (ortalama) |
| **USOM Sync** | ~12,000 tehdit IP'si |

## 🔗 Faydalı Bağlantılar

- [USOM Türkiye](https://www.usom.gov.tr/) - Ulusal Siber Olayları Müdahale Merkezi
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Security Guidelines](https://owasp.org/)

## 📄 Lisans

Bu proje MIT Lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

### 🌟 Projeyi Beğendiyseniz Yıldızlamayı Unutmayın!

```bash
⭐ Star this repository if you find it helpful!
```

---

**Son Güncelleme**: Ağustos 2025  
**Versiyon**: 1.0.0  
**Durum**: Aktif Geliştirme
