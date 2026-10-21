# Siber Blocklist

T.C. Siber Güvenlik Başkanlığı'nın herkese açık zararlı adres listelerini ([siberguvenlik.gov.tr/api](https://siberguvenlik.gov.tr/api/))
**saatte bir** çekip, güvenlik duvarlarının (FortiGate External Threat Feed, Palo Alto EDL) doğrudan okuyabileceği
düz metin dosyaları olarak GitHub Pages'te yayınlar.

## Dosyalar

Her dosyada **en fazla 120.000 satır**, satır başına bir kayıt; başlık ya da yorum satırı yok. Kayıtlar sıralı ve tekrarsız.

| Dosya | İçerik | Örnek |
|---|---|---|
| `ip-list-1.txt`, `ip-list-2.txt` | IPv4 adresleri | `1.12.37.113` |
| `ipv6-list-1.txt` | IPv6 adresleri | |
| `domain-list-1.txt` … `domain-list-6.txt` | Alan adları | `ornek-zararli.com` |
| `url-list-1.txt`, `url-list-2.txt` | URL'ler (şemasız) | `ornek.com/giris/index.php` |
| `status.json` | Son güncelleme, kayıt ve dosya sayıları | |

Liste büyüdüğünde güvenlik duvarı tanımları değişmesin diye dosya sayısı sabittir (domain için 6 = 720.000 kapasite);
kullanılmayan dosyalar boş durur. Boş dosyayı iki üretici de hatasız okur. Kapasite aşılırsa betik ek dosya
(`domain-list-7.txt` …) üretir — `status.json`'dan izlenebilir.
Bir tür sabit kapasitenin **%80'ine** ulaşınca depoda *"Liste kapasitesi dolmak üzere"* kaydı (issue) açılır,
depo sahibine e-posta gider: güvenlik duvarına yeni dosyayı ekleyip `cek.py` içindeki `SABIT_PARCA`'yı artırmak yeterli.

Adres: `https://<kullanıcı>.github.io/siber-blocklist/<dosya>`

## Güvenlik önlemleri

- API hatası, eksik sayfa ya da bir türde önceki yayına göre **%20'den fazla düşüş** olursa yayın yapılmaz;
  güvenlik duvarları son sağlam listeyi okumaya devam eder (GitHub iş akışı kırmızı görünür).
- Geçersiz IP / alan adı satırları atılır; URL'lerden `http://`, `https://` öneki kaldırılır.

## Güvenlik duvarı ayarı

**FortiGate:** Security Fabric → External Connectors → Threat Feeds → *IP Address* (`ip-list-*`),
*Domain Name* (`domain-list-*`), *FortiGuard Category* / URL (`url-list-*`). Her dosya ayrı bağlayıcı; yenileme 60 dk.

**Palo Alto:** Objects → External Dynamic Lists → Type: *IP List* / *Domain List* / *URL List*, Repeat: Hourly.
Sonra güvenlik ilkelerinde (IP), Anti-Spyware DNS politikasında (Domain) ve URL Filtering profilinde (URL) kullanılır.

## Yerelde çalıştırma

```
python cek.py          # site/ klasörüne yazar (~5 dk; yalnız Python standart kütüphanesi)
```

Elle güncelleme: Actions → *Listeleri güncelle* → Run workflow.
