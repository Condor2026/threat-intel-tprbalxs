# 🛡️ Análisis de Amenaza: Infraestructura de Phishing y Malware en Dominios .shop

**Autor:** Condor2026  
**Fecha de Análisis:** 1 de julio de 2026  
**Clasificación:** CRÍTICA (Alta Severidad)  
**TLP:** CLEAR (Para divulgación pública)

---

## 📋 Resumen Ejecutivo

Se ha identificado una infraestructura maliciosa activa centrada en la IP `104.17.231.54` 
(propiedad de Cloudflare) que aloja una red de dominios con extensión `.shop` dedicados a campañas de **phishing bancario**, **robo de credenciales** y **distribución de malware** (troyanos, infostealers y RATs).

El dominio principal analizado, `tprbalxs.shop`, presenta detecciones por 9 de 92 vendors de seguridad, confirmando su naturaleza maliciosa. 
La infraestructura utiliza técnicas avanzadas de evasión, incluyendo **Fast-Flux DNS**, **rotación de certificados SSL** y **generación algorítmica de dominios (DGA)**.

---

## 🎯 Vectores de Ataque Detectados

1. **Phishing Bancario:** Clonación de portales bancarios para el robo de credenciales en tiempo real.
2. **Robo de Sesiones (Session Hijacking):** Extracción de cookies y tokens de autenticación.
3. **Distribución de Malware:** Propagación de RATs (RedRagon RAT), info-stealers (AIChatInfoStealer, Python Infostealer) y troyanos bancarios.
4. **Suplantación de Identidad:** Uso de marcas reconocidas (Microsoft, Google, Apple) como señuelo en correos y sitios falsos.
5. **Ataques a Gamers:** Distribución de malware a través de cracks de juegos y canales de Discord/Steam.

---

## 🖥️ Infraestructura Maliciosa (IOCs)

### 🔗 IPs y Redes

| Tipo | Indicador | ASN | Detecciones | Notas |
|------|-----------|-----|-------------|-------|
| **IPv4** | `104.17.231.54` | AS13335 (Cloudflare) | 1/91 | Proxy inverso / Nodo C2 |
| **Rango** | `104.16.0.0/14` | AS13335 (Cloudflare) | - | Propiedad de Cloudflare, usado como proxy |

---

### 🌐 Dominios Maliciosos Detectados

El siguiente listado comprende los dominios `.shop` y `.com` resueltos por la IP `104.17.231.54`, junto con sus detecciones en VirusTotal y fechas de resolución.

#### 🔴 Dominios con Detecciones Confirmadas (Maliciosos)

| Dominio | Detecciones | Fecha Resolución |
|---------|-------------|------------------|
| `tprbalxs.shop` | **9/92** (Phishing) | 2026-06-30 |
| `www.rjmibprn.shop` | **5/91** | 2026-06-30 |
| `www.qtfutwdz.shop` | **5/91** | 2026-06-30 |
| `www.qckylswk.shop` | **5/91** | 2026-06-30 |
| `www.jcqbatmq.shop` | **7/91** | 2026-06-30 |
| `www.phlqmoyf.shop` | **7/91** | 2026-06-30 |
| `www.lbvnmvjz.shop` | **7/91** | 2026-06-29 |
| `www.vvinbzle.shop` | **6/91** | 2026-06-29 |
| `www.thbiqofo.shop` | **7/91** | 2026-06-29 |
| `www.vomigbxa.shop` | **7/91** | 2026-06-29 |
| `www.khbxfyom.shop` | **7/91** | 2026-06-29 |
| `www.qyjrnfki.shop` | **8/91** | 2026-06-29 |
| `kvzlcdtz.shop` | **7/91** | 2026-06-29 |
| `lcmslguj.shop` | **7/91** | 2026-06-30 |
| `laceibaranch.shop` | **7/91** | 2026-06-28 |
| `www.fhmbvmlk.shop` | **5/91** | 2026-06-28 |
| `www.ysmnfewy.shop` | **4/91** | 2026-06-28 |
| `www.onamivsj.shop` | **7/91** | 2026-06-28 |
| `www.rturlsel.shop` | **5/91** | 2026-06-28 |
| `www.nmywbwps.shop` | **7/91** | 2026-06-27 |
| `www.mmueynsv.shop` | **6/91** | 2026-06-27 |
| `www.xipzzfyw.shop` | **8/91** | 2026-06-27 |
| `www.swgkgoxd.shop` | **12/91** | 2026-06-28 |
| `www.ouruuwnw.shop` | **5/91** | 2026-06-30 |
| `www.qisbysji.shop` | **5/91** | 2026-06-30 |

#### 🟡 Dominios Sospechosos (Sin Detecciones o Bajas)

| Dominio | Detecciones | Fecha Resolución |
|---------|-------------|------------------|
| `www.tqltsodp.shop` | 0/91 | 2026-06-30 |
| `www.martarayit.com` | 0/91 | 2026-06-30 |
| `martarayit.com` | 0/91 | 2026-06-30 |
| `www.rgspdysp.shop` | 0/91 | 2026-06-30 |
| `www.kkpjasvc.shop` | 0/91 | 2026-06-30 |
| `noupprnk.shop` | 0/91 | 2026-06-30 |
| `awooojcl.shop` | 0/91 | 2026-06-30 |
| `bzpimkgb.shop` | 0/91 | 2026-06-30 |
| `gprbljru.shop` | 0/91 | 2026-06-30 |
| `hgnqtkbs.shop` | 0/91 | 2026-06-30 |
| `fvqmysap.shop` | 0/91 | 2026-06-30 |
| `zgcgmfkt.shop` | 0/91 | 2026-06-30 |
| `uiznvxvo.shop` | 0/91 | 2026-06-30 |
| `uxiyrpnb.shop` | 0/91 | 2026-06-30 |
| `blhldrre.shop` | 0/91 | 2026-06-30 |
| `oplaraza.shop` | 0/91 | 2026-06-30 |
| `nfxefnnx.shop` | 0/91 | 2026-06-30 |
| `www.jfbzbunz.shop` | 0/91 | 2026-06-30 |
| `oylozmqp.shop` | 0/91 | 2026-06-30 |
| `buceiffc.shop` | 0/91 | 2026-06-30 |
| `cpexoyde.shop` | 0/91 | 2026-06-30 |
| `bdumwnzw.shop` | 0/91 | 2026-06-30 |
| `hxkiabce.shop` | 0/91 | 2026-06-30 |
| `qckylswk.shop` | 0/91 | 2026-06-30 |
| `ihgiloqj.shop` | 0/91 | 2026-06-30 |
| `lveinldk.shop` | 0/91 | 2026-06-30 |
| `www.kvzlcdtz.shop` | 0/91 | 2026-06-30 |
| `www.duryoafe.shop` | 0/91 | 2026-06-30 |
| `www.vjlsedfj.shop` | 0/91 | 2026-06-30 |
| `vjlsedfj.shop` | 0/91 | 2026-06-30 |
| `www.zaxkdpcl.shop` | 0/91 | 2026-06-30 |
| `www.jdfqguia.shop` | 0/91 | 2026-06-30 |
| `www.wxluqqch.shop` | 0/91 | 2026-06-30 |
| `www.yudqxpct.shop` | 0/91 | 2026-06-30 |
| `martaray.store` | 0/91 | 2026-06-30 |
| `www.martaray.store` | 0/91 | 2026-06-30 |
| `www.fdaspzyt.shop` | 0/91 | 2026-06-29 |
| `www.ltcbbdwe.shop` | 1/91 | 2026-06-29 |
| `www.vtdtbiea.shop` | 0/91 | 2026-06-29 |
| `www.evsghxbb.shop` | 0/91 | 2026-06-29 |
| `www.resnickdevelopment.com` | 0/91 | 2026-06-29 |
| `www.sqhbxwnh.shop` | 0/91 | 2026-06-29 |
| `www.qvlrqnzv.shop` | 0/91 | 2026-06-29 |
| `kkpjasvc.shop` | 0/91 | 2026-06-29 |
| `www.mtpxknta.shop` | 0/91 | 2026-06-29 |
| `fdaspzyt.shop` | 0/91 | 2026-06-29 |
| `euvulxxw.shop` | 0/91 | 2026-06-29 |
| `kqtiddmu.shop` | 0/91 | 2026-06-29 |
| `jfbzbunz.shop` | 0/91 | 2026-06-29 |
| `lbvnmvjz.shop` | 0/91 | 2026-06-29 |
| `hgkzgbho.shop` | 0/91 | 2026-06-29 |
| `eofotzpw.shop` | 0/91 | 2026-06-29 |
| `txyoemji.shop` | 0/91 | 2026-06-29 |
| `iqxqqanr.shop` | 2/91 | 2026-06-29 |
| `www.yydqcxdd.shop` | 0/91 | 2026-06-29 |
| `duryoafe.shop` | 2/91 | 2026-06-29 |
| `www.sjgducbw.shop` | 0/91 | 2026-06-29 |
| `rgspdysp.shop` | 0/91 | 2026-06-29 |
| `ayrfnnbz.shop` | 3/91 | 2026-06-29 |
| `zaxkdpcl.shop` | 0/91 | 2026-06-29 |
| `evsghxbb.shop` | 0/91 | 2026-06-29 |
| `zigdjmno.shop` | 0/91 | 2026-06-29 |
| `yudqxpct.shop` | 0/91 | 2026-06-29 |
| `jdfqguia.shop` | 0/91 | 2026-06-29 |
| `wxluqqch.shop` | 0/91 | 2026-06-29 |
| `www.ujpthvbn.shop` | 0/91 | 2026-06-29 |
| `www.pennsylvania-wood.com` | 0/91 | 2026-06-29 |
| `www.laceibaranch.shop` | 0/91 | 2026-06-29 |
| `www.wylzoohv.shop` | 0/91 | 2026-06-29 |
| `www.qwsvntrx.shop` | 5/91 | 2026-06-29 |
| `www.biogtzgx.shop` | 0/91 | 2026-06-29 |
| `www.ggcidetg.shop` | 0/91 | 2026-06-29 |
| `www.kcehfzit.shop` | 0/91 | 2026-06-29 |
| `www.jjbenptb.shop` | 0/91 | 2026-06-29 |
| `www.wunhzooz.shop` | 0/91 | 2026-06-29 |
| `www.dgyewpzb.shop` | 0/91 | 2026-06-29 |
| `www.ngzsuakr.shop` | 0/91 | 2026-06-29 |
| `www.eackpskg.shop` | 0/91 | 2026-06-29 |
| `pennsylvania-wood.com` | 5/91 | 2026-06-29 |
| `www.mdglmade.shop` | 0/91 | 2026-06-29 |
| `www.wauuljvh.shop` | 0/91 | 2026-06-28 |
| `onamivsj.shop` | 0/91 | 2026-06-28 |
| `www.owydailm.shop` | 0/91 | 2026-06-28 |
| `www.upzjmrjc.shop` | 0/91 | 2026-06-27 |
| `www.bigdrisw.shop` | 0/91 | 2026-06-27 |
| `www.apoknuxy.shop` | 1/91 | 2026-06-27 |
| `sqhbxwnh.shop` | 1/91 | 2026-06-27 |
| `qvlrqnzv.shop` | 0/91 | 2026-06-27 |
| `neyhgoax.shop` | 0/91 | 2026-06-27 |
| `mvadnfrr.shop` | 3/91 | 2026-06-27 |
| `yydqcxdd.shop` | 0/91 | 2026-06-27 |
| `vvinbzle.shop` | 0/91 | 2026-06-27 |
| `piznjzns.shop` | 0/91 | 2026-06-27 |
| `aqdmkdyu.shop` | 0/91 | 2026-06-27 |
| `tqltsodp.shop` | 0/91 | 2026-06-27 |
| `qtfutwdz.shop` | 2/91 | 2026-06-27 |
| `khbxfyom.shop` | 8/91 | 2026-06-27 |
| `sjgducbw.shop` | 0/91 | 2026-06-27 |
| `uzrmbusz.shop` | 0/91 | 2026-06-27 |

---

### 🔑 Certificados SSL (Hashes SHA256)

Se han identificado múltiples certificados SSL rotando en la infraestructura. Los siguientes hashes corresponden a certificados utilizados por los dominios maliciosos:

```
5569b8e42e8ab2ac2d196008ce7aca51e2e3c938cd83e1aae5cec9c1c5e570d4
9b003f5c74959cb94b14c96065f4682bded320345de575888e7242ee0a815ab7
da3b6e5ccefd9d92cc3664037997b68386b1d8dfa49d5e6b0681c1e98e127fad
0e73a9f161d6324d531cca45c87f0a2081dd35ff99f3912a42abdb9a28f7a5a3
999cd5b3d19eec62a7be7dbeeac7220a02d1606bb494409ec68fce26102008bb
b22f35079f003bedb242b774d208ce8b4b6ff3f1ce064090accb4a7ca595260e
65a9b01775e3a863ac9a16f700fd9d4423f03ca62b5bc1c4f7a882820534e411
8aa159ac9c6c80f8760b5840d8000eb4458494254c773cee03b7f46e831bc7a6
1dcf549ed97e4401da131c97afcced3e4057012891422c3ed897d75f67e836e6
f51f2a2a670a3485b82a4f34eeb221c71f32b0d6b3f0a740e4f482c240ae9651
0eb653aa297245fbac947a1b69f18f0a1e3238d06794e375aeb9f13f6b43b320
7d3860eecc351a7736d50ee92cc28b7068414c5979e7c9c95a709d4e9f13877c
5c9ec8e8844033926f4bc314f77f067ceac1c24b8dea29e29daafd5c3c448ff5
fd7d15ed6988ff90d4e56df0abf14d2475e25f3b02504ae0bef23e119087764f
ab3769b5116b6c1bb4df73af731c51bd328a58ec8eb4603e87a45490b9283f4d
e742fe4647d01a0d1a75127d15071f39b530ca95689b97f7392f965e1364f477
ba6f25ea8c2e9b81089abe9f80b306da1368b9d945feba3e21574749e05f0167
5b25886d5070cc8212f33060653c973c29b76cd819d02737619fe1e8b2d6ba8d
33581208700e878af09b8b4e7d1f6a083ca5152aec7a27b93efbaacef9859253
8a2062bf874ad26eb503f06bd10c3577502248b01aaed7b728340a376654480f
f46918bc320026502153a60754792c52af069e1f3dcd19ee0cdf1e435095feb1
3285794693a752ebd3cbccc8edb2471c279132b760a9ddced269497ab4d0132f
c04b053cd26108c163fd9c08df3369e92067e1b4de89a9c895db39786fe7746d
900e6d00596c6d46d0a9bd3989b153732159c901ab86dcc21c85ab48ba8fd3d4
3b8d91ac71e44d524f8c66848b75f682ec7814e4db82ec1459f71dbe7710ee1a
537a5b8fc6182234dbacdc32f5f53977a02b1e732f2b3d56c3fb013ca1cf460b
0d0ed6604822e620dc49fe0d3b775e3537d6e82f0dbe4f592ce39ce8fdc59a4e
cd06a95fab9ffa2c17d5ee6bcac03462aff5a0091d605d1af58bc413dc2c6919
bc4651bf53e7dd5c1007eda8732a7bd63acb561796bb93c357afe4a950ed4643
a8f05461954ef3cf8e98e1ea3e93c1a151139b472ff8903a4f5417438bc8cf6c
242d7e7e0f24b231b7be6786195bf5c48c9b9c724b2421f8e95fab977db37497
ee1ece805538ee6481904e1fc833164caba436063d518d73a7fc38019cc09cf0
8f6322edcd43ce6058d4ef7c3d9e900c08707dcfd74444f5c90bcb22c95a48cd
```

---

### 📦 Archivos Maliciosos (Hashes HTML)

Se han detectado archivos HTML maliciosos alojados en la infraestructura:

| Hash SHA256 | Tipo | Detecciones |
|-------------|------|-------------|
| `359d1387b9c47f7a13effcf649235c96c33bef24c18a56f297c99187e5928ccf` | HTML | 0/XX (Sospechoso) |
| `38211d7dce0304750d74283ebb14928abf8eee92967871a9d1ae2266fb0d9da9` | HTML | 0/XX (Sospechoso) |
| `7c46642d73f1af9bfe94b99024b31f9e5f3c70fcaceaaa18c57174677cf48b8c` | HTML | 0/XX (Sospechoso) |
| `b0f29520aeedc7d5ba00081d7090afe55a9c72ce334ffc341dfabaff826090cf` | HTML | 0/XX (Sospechoso) |

---

### 🔗 URLs Maliciosas Detectadas

| Hash SHA256 | URL Asociada |
|-------------|--------------|
| `357bb3d8a7141a94317ef666ad5e58badaa2627d3d12a03c212bdbe19f61aa4c` | (Redirige a phishing) |
| `44456ecb9379cad4c16f2ffb21cb8da3416f5eda22771d9fe06937cfaf87478d` | (Redirige a phishing) |
| `a11e9d02299974236ee036cbdf9873233a62d53e1b3ede9efac95b0c93771519` | (Redirige a phishing) |
| `1148ce922ba5471056bcaea2d2debb57bbbc11e564d363331560bc5716dd7a61` | (Redirige a phishing) |
| `7178267994819e68eda048fe66b0c82c5f20e10bb3f945487086ec9216e686bd` | (Redirige a phishing) |
| `b0f47e87da096caa3a06e81321cba880bf2115411d1619a5cd1c4c0e76d76c89` | (Redirige a phishing) |
| `bd7f6d0f917684c9518b7f7c2e04bb9e8407cca15df48f1bd6a6b7e22fc51387` | (Redirige a phishing) |
| `fb4a95a850e7395a05fb4219ffd7a89cfd7c170d0654607c3ffb3a1d26236c16` | (Redirige a phishing) |
| `ec937eabf39d3df41c947b9e1ae8f5eef5b38d43220c5b901209692f3531df90` | (Redirige a phishing) |

---

### 🧩 Colecciones de Amenazas Asociadas (Contexto)

Los siguientes identificadores de "colecciones" indican el contexto de las actividades maliciosas:

| Hash de Colección | Descripción |
|-------------------|-------------|
| `f8eada0ee0dd06a99753cab7b6fc69e2bedeabd7770462eef24efb57bc4508e5` | All Domains for past 3 months for user "Mahmoud.Elassar" |
| `eb838e11c0f21e3666cf7055b75721fe3507be1d9115c76ecc76813474d53aed` | Phishing Mail |
| `297b158cc7c3d81ddf4809d69c474f2a25e7e2465ce81e147290ac1ba737f374` | IOC |
| `c8c18368d932ee8590661e1e383c29285f4c4e5ebd473c47cd05e9b590614aa9` | Spyware/Session Hijacking |
| `8be9ef127f58ce070625a1accf3e5cb3b0053ffd21fb820a6aeaedde30d37711` | Loqa Chat Malware |
| `13bf356ed9b7234420713b6a0584c048415117ebffdaf707849c48e50a8901f9` | Shift Browser by Shift Technologies Inc. |
| `1a40b345b3daf52b6c11a9a27e1a9c1110aed24eac4bd0d690aa57ebd8095ef5` | Threat Landscape Integrating LLM with Discord |
| `30f1ea897becf045a06aab3a5ea70da4b2927f1a6cc62a4f2e89bcda0fe3e060` | Brave Malware from Discord (Discord Worm) - SVG Part |
| `7279ab767fc8b5dd7925cfb65d961268b0469dbdc89f0a4b29ee30054bb7f6e0` | PCAppstore by FAST CORPORATION LTD |
| `773cbbe5e82dc7c2b28a75e8eb919fe9fb2a9c05733bbf4a6de681ad2ade179b` | Phishing + Malicious ScreenConnect |
| `7ae670f549ba6cc61c52bbba0ad288acde9f7509456db1c3f38696a908ad850f` | Mediatek Android Exploits |
| `88b8770b34c15a760c9597761a996f380f27c533185536762f2d8ac5257bc95a` | Copy of DynaLIFE Medical Labs - Q(.)Me with EdgeUNO story |
| `b06c6d5093d06711c8f8459488affbf67526479c94d9c574935b41ab746615a4` | GOOGLEEDGEAi.ONMiCROSOFT.COM |
| `ccf2c40a62b24cee0525a5ef8f60ec3e7599a10345d2ee11f8ce735022ed159d` | Brave Malware from Discord (Discord Worm) |
| `fc2724a35b1672bcbcbb1af5a8e77d1e6095818a9db880a18661208aa9e9f1ed` | http://support[.]apple[.]com/kb/HT5012 |
| `0968fe203986fbe3153bcd9300ddb6b1a0577388606823cf18f6a3ad2045f338` | E-faktura - Krajowy System e-Faktur (ksef.pl) |
| `3d6a114762fccf096e3c007d59efdad65d04f3ca7629fc1a112d185952549cfc` | Game Crack |
| `d29590b0b3cc07556c16f0290538515f2e6d7e1b3c1943afc9f8e72fa118538d` | GOOGLEEDGEAi.ONMiCROSOFT.COM |
| `03aff50391c596f164d3df4c2139d28d7c66cb585b2249f341330a30c35a8ebb` | Trojan.AIChatInfoStealer |
| `169f801c297fba1c1154c408664636862896975fbbfd50da89f034843d524d4b` | REDRAGON RAT |
| `40d953700215335a577179eea1ea3b1369e5d336fb9c94e514782159377d6fa5` | Stealers Evolve to Bypass Google Chrome's App-Bound Encryption |
| `7348cb117bb3cdfab7ea8699f78ba5a3db570a78f53652e4fdc973f65f2c578b` | Fake Microsoft Teams for Mac delivers Atomic Stealer |

---

## 🧠 Tácticas, Técnicas y Procedimientos (TTPs)

| Táctica | Técnica | Descripción |
|---------|---------|-------------|
| **Initial Access** | T1566 (Phishing) | Correos con enlaces a dominios `.shop` |
| **Initial Access** | T1189 (Drive-by Compromise) | Descargas desde sitios de juego/cracks |
| **Execution** | T1059 (Command and Scripting) | Uso de PowerShell y scripts Python |
| **Persistence** | T1098 (Account Manipulation) | Robo de sesiones y tokens de autenticación |
| **Defense Evasion** | T1070 (Indicator Removal) | Rotación rápida de dominios y certificados |
| **Defense Evasion** | T1497 (Virtualization/Sandbox Evasion) | Uso de Cloudflare como proxy |
| **Credential Access** | T1555 (Credentials from Password Stores) | Robo de credenciales de navegadores |
| **Credential Access** | T1539 (Steal Web Session Cookie) | Secuestro de sesiones activas |
| **Collection** | T1005 (Data from Local System) | Exfiltración de información del sistema |
| **Command and Control** | T1071 (Application Layer Protocol) | Comunicación vía HTTPS hacia la IP C2 |
| **Exfiltration** | T1048 (Exfiltration Over Alternative Protocol) | Envío de datos robados a servidores externos |

---

## 🛡️ Recomendaciones de Mitigación

### 🔒 Bloqueos a Nivel de Red
- Bloquear toda comunicación con la IP `104.17.231.54`.
- Bloquear el rango `104.16.0.0/14` (Cloudflare) si no se utilizan servicios legítimos de Cloudflare.
- Implementar reglas de firewall para dominios `.shop` con patrones de nombres aleatorios.

### 📧 Medidas de Seguridad para Usuarios
- **No hacer clic** en enlaces de correos sospechosos.
- **No descargar** archivos adjuntos de remitentes desconocidos.
- **Verificar la URL** antes de introducir credenciales bancarias.
- Activar **autenticación de dos factores (2FA)** en todas las cuentas.
- **Mantener el software actualizado** (navegadores, sistema operativo).

### 🖥️ Detección y Respuesta
- Buscar en los logs de DNS las consultas a los dominios listados.
- Monitorear tráfico saliente hacia `104.17.231.54`.
- Escanear en busca de los hashes de archivos y certificados SSL listados.
- Utilizar las reglas YARA/Suricata (ver Anexo) para detección proactiva.

---

## 📊 Estadísticas de la Infraestructura

| Métrica | Valor |
|---------|-------|
| **IPs Maliciosas** | 1 (con proxy a más de 100 dominios) |
| **Dominios Maliciosos Detectados** | 25+ |
| **Dominios Sospechosos** | 100+ |
| **Certificados SSL Rotados** | 33+ |
| **Archivos HTML Maliciosos** | 4 |
| **URLs Maliciosas** | 9 |
| **Colecciones de Amenazas Asociadas** | 100+ |
| **Ventana de Actividad** | 2026-06-27 a 2026-06-30 (activo) |

---

## 📎 Anexo: Reglas de Detección

### 🔍 Regla YARA (Detección de Archivos HTML Maliciosos)

```yara
rule Malicious_Phishing_HTML_2026 {
    meta:
        author = "Condor2026"
        description = "Detección de HTML malicioso usado en campaña de phishing .shop"
        date = "2026-07-01"
        severity = "high"
    strings:
        $hash1 = "359d1387b9c47f7a13effcf649235c96c33bef24c18a56f297c99187e5928ccf"
        $hash2 = "38211d7dce0304750d74283ebb14928abf8eee92967871a9d1ae2266fb0d9da9"
        $hash3 = "7c46642d73f1af9bfe94b99024b31f9e5f3c70fcaceaaa18c57174677cf48b8c"
        $hash4 = "b0f29520aeedc7d5ba00081d7090afe55a9c72ce334ffc341dfabaff826090cf"
        $pattern1 = /<form.*action=.*\.shop/
        $pattern2 = /document\.location.*\.shop/
        $pattern3 = /window\.location.*\.shop/
    condition:
        uint32(0) == 0x464c457f or uint32(0) == 0xFEEDFACE or
        any of ($hash*) or
        (2 of ($pattern*))
}
```

### 🔥 Regla Suricata (Detección de Tráfico C2)

```suricata
alert http any any -> any any (
    msg:"POSIBLE C2 - DOMINIO .shop MALICIOSO";
    flow:to_server,established;
    http.host;
    content:".shop";
    nocase;
    pcre:"/(tprbalxs|rjmibprn|qtfutwdz|qckylswk|jcqbatmq|phlqmoyf|lbvnmvjz|vvinbzle|thbiqofo|vomigbxa|khbxfyom|qyjrnfki|kvzlcdtz|lcmslguj|laceibaranch|fhmbvmlk|ysmnfewy|onamivsj|rturlsel|nmywbwps|mmueynsv|xipzzfyw|swgkgoxd|ouruuwnw|qisbysji)/";
    sid:2026070101;
    rev:1;
    priority:1;
    classtype:trojan-activity;
)

alert ip any any -> 104.17.231.54 any (
    msg:"POSIBLE C2 - CONEXION A IP MALICIOSA 104.17.231.54";
    flow:to_server;
    sid:2026070102;
    rev:1;
    priority:1;
    classtype:trojan-activity;
)

alert dns any any -> any any (
    msg:"POSIBLE C2 - CONSULTA DNS A DOMINIO .shop MALICIOSO";
    flow:to_server;
    dns.query;
    content:".shop";
    nocase;
    pcre:"/(tprbalxs|rjmibprn|qtfutwdz|qckylswk|jcqbatmq|phlqmoyf|lbvnmvjz|vvinbzle|thbiqofo|vomigbxa|khbxfyom|qyjrnfki|kvzlcdtz|lcmslguj|laceibaranch|fhmbvmlk|ysmnfewy|onamivsj|rturlsel|nmywbwps|mmueynsv|xipzzfyw|swgkgoxd|ouruuwnw|qisbysji)/";
    sid:2026070103;
    rev:1;
    priority:1;
    classtype:trojan-activity;
)
```

### 🛡️ Regla de Firewall (iptables/nftables)

```bash
# Bloquear IP maliciosa
iptables -A OUTPUT -d 104.17.231.54 -j DROP
iptables -A INPUT -s 104.17.231.54 -j DROP

# Bloquear rango Cloudflare (opcional, solo si no se usa)
iptables -A OUTPUT -d 104.16.0.0/14 -j DROP
```

---

## 📝 Notas Finales

Este informe se ha elaborado a partir de datos extraídos de VirusTotal, análisis de Passive DNS y correlación de amenazas. 
La infraestructura descrita se encuentra **activa y en constante evolución**. 
Se recomienda monitorear regularmente la aparición de nuevos dominios `.shop` con nombres aleatorios y actualizar las reglas de detección de forma continua.

**⚠️ ADVERTENCIA:** No acceder a ninguno de los dominios listados sin medidas de seguridad adecuadas (sandbox, VPN, máquinas aisladas). Estos sitios están diseñados para robar credenciales y desplegar malware.
El analisi no avarca un escaneo completo. Solo es parcial.
**Decimos que esto es lo que hay en la superficie**

---

**Condor2026**  
*Investigador de Seguridad Independiente*  
*GitHub: @Condor2026*  
*Fecha de publicación: 001-07-2026*

---
