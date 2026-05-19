# 🔍 TechDetector

A lightweight **Wappalyzer clone** built in Python that detects technologies used on a website along with **version detection** and **basic vulnerability checking**.

## ✨ Features

- Detects CMS, Frameworks, Servers, CDNs, Libraries, etc.
- Extracts version numbers (where available)
- Shows potential vulnerabilities
- CLI + Web Interface (Streamlit)
- Beautiful output with Rich
- JSON report export

## 🛠️ Technologies Detected

- WordPress, Shopify, React, Vue.js, Angular, Laravel, Django, etc.
- jQuery, Bootstrap, Cloudflare, Google Analytics, and more.

## 🚀 Installation

```bash
git clone https://github.com/YOUR_USERNAME/TechDetector.git
cd TechDetector
pip install -r requirements.txt

## 📸 Demo


✅ Analysis Complete: https://overthewire.org/ | Size: 0 KB

           TechDetector v1.2.0 - Technology Detection            
┏━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Technology ┃ Version ┃ Risk ┃ Categories    ┃ Evidence        ┃
┡━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ Cloudflare │ Unknown │ Safe │ Security, CDN │ Header: Server, │
│            │         │      │               │ Header:         │
│            │         │      │               │ Report-To       │
└────────────┴─────────┴──────┴───────────────┴─────────────────┘


✅ Analysis Complete: https://abhinavbharati.co.in/ | Size: 84 KB

           TechDetector v1.2.0 - Technology Detection            
┏━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Technology ┃ Version ┃ Risk ┃ Categories ┃ Evidence           ┃
┡━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ WordPress  │ 6.9.4   │ Safe │ CMS        │ Header: Link,      │
│            │         │      │            │ Version: 6.9.4,    │
│            │         │      │            │ HTML: wp-includes, │
│            │         │      │            │ HTML: wp-content   │

└────────────┴─────────┴──────┴────────────┴────────────────────┘

##🛠️ Technologies Used

Python
Requests + BeautifulSoup4
Rich (for beautiful CLI)
Streamlit

##📌 What I Learned

Web fingerprinting techniques
Regex pattern matching for version detection
Building CLI tools with argparse
Basic vulnerability assessment logic

##⚠️ Disclaimer
This tool is made for educational purposes only. Use it only on websites you have permission to scan.
