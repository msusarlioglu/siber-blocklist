#!/usr/bin/env python3
"""
T.C. Siber Güvenlik Başkanlığı zararlı adres listeleri -> güvenlik duvarı besleme dosyaları.

Kaynak : https://siberguvenlik.gov.tr/api/  (GET /api/address/index?type=ip|domain|url|ip6, herkese açık)
Çıktı  : site/ altında, her dosyada en fazla 120.000 satır (bir satıra bir kayıt, başlık/yorum yok):
           ip-list-1.txt ..      IPv4 adresleri
           ipv6-list-1.txt ..    IPv6 adresleri
           domain-list-1.txt ..  alan adları
           url-list-1.txt ..     URL'ler (şemasız: "alanadi.com/yol")
         + status.json (sayılar, zaman) ve index.html (dosya listesi).

Güvenlik duvarı tarafındaki tanımlar değişmesin diye her tür için en az SABIT_PARCA kadar dosya
üretilir; ihtiyaç yoksa dosya boş kalır. Kayıtlar sıralanır, böylece parçalar kararlıdır.

Koruma: API arızalı/eksik veri dönerse güvenlik duvarındaki liste boşalmasın diye, bir türün
kayıt sayısı önceki yayına göre DUSUS_SINIRI'ndan fazla düşerse betik hata verir ve yayın yapılmaz.
Yalnızca Python standart kütüphanesi kullanılır.
"""
import ipaddress
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://siberguvenlik.gov.tr/api/address/index"
SAYFA_BOYU = 9999                 # API'nin izin verdiği en yüksek değer
MAX_SATIR = 120_000               # güvenlik duvarı başına dosya sınırı
SABIT_PARCA = {"ip": 2, "ipv6": 1, "domain": 6, "url": 2}
DUSUS_SINIRI = 0.20               # önceki yayına göre %20'den fazla düşüş -> yayınlama
UYARI_ORANI = 0.80                # sabit dosyaların %80'i dolunca uyar (güvenlik duvarına yeni dosya eklenmeli)
CIKTI = os.environ.get("CIKTI_KLASORU", "site")
ONCEKI_DURUM_URL = os.environ.get("ONCEKI_DURUM_URL", "")   # yayındaki status.json (koruma için)
UA = "Marmara-Blocklist/1.0 (+https://github.com/msusarlioglu)"

ALAN_ADI = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))*\.[a-z0-9-]{2,63}$")


def getir(url, deneme=4):
    for i in range(deneme):
        try:
            istek = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(istek, timeout=120) as y:
                return json.loads(y.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            if i == deneme - 1:
                raise
            bekle = 5 * (i + 1)
            print(f"  uyarı: {e} - {bekle} sn sonra yeniden denenecek", file=sys.stderr)
            time.sleep(bekle)


def tur_cek(tur):
    """Bir türün bütün sayfalarını çeker; (kayıtlar, API'nin bildirdiği toplam)."""
    ilk = getir(f"{API}?type={tur}&per-page={SAYFA_BOYU}&page=1")
    toplam, sayfa_sayisi = int(ilk.get("totalCount") or 0), int(ilk.get("pageCount") or 0)
    kayitlar = [m.get("url", "") for m in ilk.get("models", [])]
    for sayfa in range(2, sayfa_sayisi + 1):
        time.sleep(0.5)  # kaynağı yormamak için
        kayitlar += [m.get("url", "") for m in getir(f"{API}?type={tur}&per-page={SAYFA_BOYU}&page={sayfa}").get("models", [])]
    return kayitlar, toplam


def temiz_ip(deger, surum):
    try:
        a = ipaddress.ip_address(deger.strip())
        return str(a) if a.version == surum else None
    except ValueError:
        return None


def temiz_alan(deger):
    d = deger.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    return d if ALAN_ADI.match(d) else None


def temiz_url(deger):
    u = deger.strip()
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", u)   # şema kaldırılır (güvenlik duvarları şemasız ister)
    if not u or any(c.isspace() for c in u):
        return None
    host, ayrac, yol = u.partition("/")
    host = host.lower()
    return host + ayrac + yol if host else None


def yaz_parcalar(ad, kayitlar, parca_min):
    os.makedirs(CIKTI, exist_ok=True)
    parca = max(parca_min, math.ceil(len(kayitlar) / MAX_SATIR) if kayitlar else 0)
    dosyalar = []
    for i in range(parca):
        dilim = kayitlar[i * MAX_SATIR:(i + 1) * MAX_SATIR]
        yol = os.path.join(CIKTI, f"{ad}-list-{i + 1}.txt")
        with open(yol, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(dilim) + ("\n" if dilim else ""))
        dosyalar.append({"dosya": f"{ad}-list-{i + 1}.txt", "satir": len(dilim)})
    return dosyalar


def onceki_durum():
    if not ONCEKI_DURUM_URL:
        return None
    try:
        return getir(ONCEKI_DURUM_URL, deneme=2)
    except Exception as e:  # ilk yayında henüz yok
        print(f"önceki status.json alınamadı ({e}); koruma bu çalıştırmada atlanıyor", file=sys.stderr)
        return None


def main():
    t0 = time.time()
    ham = {}
    for tur in ("ip", "ip6", "domain", "url"):
        kayitlar, toplam = tur_cek(tur)
        ham[tur] = (kayitlar, toplam)
        print(f"{tur:7} API toplamı {toplam:>8,} | gelen {len(kayitlar):>8,}")

    listeler = {
        "ip": sorted({x for x in (temiz_ip(v, 4) for v in ham["ip"][0]) if x}, key=lambda s: ipaddress.ip_address(s)),
        "ipv6": sorted({x for x in (temiz_ip(v, 6) for v in ham["ip6"][0]) if x}, key=lambda s: ipaddress.ip_address(s)),
        "domain": sorted({x for x in (temiz_alan(v) for v in ham["domain"][0]) if x}),
        "url": sorted({x for x in (temiz_url(v) for v in ham["url"][0]) if x}),
    }
    # API sayfalama sırasında yeni kayıt eklenirse kayma olabilir: gelen benzersiz kayıt API toplamının çok altındaysa dur
    for ad, kaynak in (("ip", "ip"), ("ipv6", "ip6"), ("domain", "domain"), ("url", "url")):
        bekl = ham[kaynak][1]
        if bekl and len(set(ham[kaynak][0])) < bekl * 0.98:
            sys.exit(f"HATA: {ad} eksik geldi ({len(set(ham[kaynak][0]))} / {bekl}); yayın yapılmadı")

    onceki = onceki_durum()
    if onceki:
        for ad, liste in listeler.items():
            eski = (onceki.get("turler", {}).get(ad) or {}).get("kayit", 0)
            if eski >= 100 and len(liste) < eski * (1 - DUSUS_SINIRI):
                sys.exit(f"HATA: {ad} {eski:,} -> {len(liste):,} (%{100 - len(liste) * 100 // eski} düşüş); yayın yapılmadı, eski liste korunuyor")

    durum = {
        "guncelleme_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kaynak": "https://siberguvenlik.gov.tr/api/",
        "max_satir_dosya_basina": MAX_SATIR,
        "turler": {},
    }
    for ad, liste in listeler.items():
        dosyalar = yaz_parcalar(ad, liste, SABIT_PARCA[ad])
        durum["turler"][ad] = {"kayit": len(liste), "atilan_gecersiz_tekrar": len(ham["ip6" if ad == "ipv6" else ad][0]) - len(liste), "dosyalar": dosyalar}
        print(f"{ad:7} yazıldı {len(liste):>8,} kayıt -> {', '.join(d['dosya'] + ' (' + format(d['satir'], ',') + ')' for d in dosyalar)}")
    durum["kapasite_uyarilari"] = []
    for ad, v in durum["turler"].items():
        kapasite = SABIT_PARCA[ad] * MAX_SATIR
        if v["kayit"] >= kapasite * UYARI_ORANI:
            mesaj = (f"{ad}: {v['kayit']:,} kayıt, sabit {SABIT_PARCA[ad]} dosyanın kapasitesi {kapasite:,} "
                     f"(%{v['kayit'] * 100 // kapasite}). Güvenlik duvarına {ad}-list-{SABIT_PARCA[ad] + 1}.txt eklenmeli "
                     f"ve cek.py içindeki SABIT_PARCA artırılmalı.")
            durum["kapasite_uyarilari"].append(mesaj)
            print(f"::warning::{mesaj}")
    if durum["kapasite_uyarilari"] and os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write("kapasite_uyarisi<<SON\n" + "\n".join(durum["kapasite_uyarilari"]) + "\nSON\n")
    durum["sure_sn"] = round(time.time() - t0, 1)
    with open(os.path.join(CIKTI, "status.json"), "w", encoding="utf-8") as f:
        json.dump(durum, f, ensure_ascii=False, indent=1)
    index_yaz(durum)
    print(f"tamam: {durum['sure_sn']} sn")


def index_yaz(durum):
    satirlar = "".join(
        f"<tr><td>{ad}</td><td>{v['kayit']:,}</td><td>" + " ".join(f'<a href="{d["dosya"]}">{d["dosya"]}</a> ({d["satir"]:,})' for d in v["dosyalar"]) + "</td></tr>"
        for ad, v in durum["turler"].items())
    html = f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zararlı adres listeleri</title><style>body{{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#14284b}}table{{border-collapse:collapse}}td,th{{border:1px solid #d9dee6;padding:6px 10px;text-align:left;font-size:14px}}th{{background:#f4f6fa}}small{{color:#5b6573}}</style></head>
<body><h1>Zararlı adres listeleri</h1><p>Kaynak: <a href="{durum['kaynak']}">T.C. Siber Güvenlik Başkanlığı API</a> · saatlik güncellenir · dosya başına en fazla {durum['max_satir_dosya_basina']:,} satır</p>
<p><small>Son güncelleme (UTC): {durum['guncelleme_utc']} · <a href="status.json">status.json</a></small></p>
<table><tr><th>Tür</th><th>Kayıt</th><th>Dosyalar</th></tr>{satirlar}</table></body></html>"""
    with open(os.path.join(CIKTI, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)


if __name__ == "__main__":
    main()
