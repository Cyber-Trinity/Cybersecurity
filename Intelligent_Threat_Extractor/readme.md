# Intelligent Threat Extractor

![Threat Extractor illustration](src/project-2.jpg)

This project provides a Threat Analysis Tool for extracting actionable intelligence from documents. Using advanced Natural Language Processing (NLP) and Named Entity Recognition (NER), this script identifies Indicators of Compromise (IoCs), malware names, threat actors, targeted entities, and Tactics, Techniques, and Procedures (TTPs) from PDFs, DOCX, and TXT files.

The goal is to automate threat intelligence gathering and help security teams quickly identify potential risks in corporate or research documents.

---

## 🗂️ Project Structure
crime-in-los-angeles/
<br>
├── src/ # Project files
<br>
├── requirements.txt # Dependencies for running the script
<br>
├── Report_Intelligent_Threat_Extractor.pdf # Summary report of findings.
<br>
└── README.md # Project description (this file)

---

## 📊 Script Features

### 1. Multi-format Document Support

- PDF, DOCX, TXT

- Single file or directory processing with multi-threading

### 2. Threat Intelligence Extraction

- IoCs: IPs, MAC addresses, domains, hashes, emails, URLs, registry keys, file paths, GUIDs, filenames

- Malware: Known malware detection & VirusTotal metadata

- TTPs: MITRE ATT&CK tactics and techniques mapping

- Threat Actors: Identifies potential attackers mentioned in documents

- Targeted Entities: Organizations or locations targeted by threats

### 3. Automated Processing

- Multi-threaded execution for large document collections

- Outputs structured JSON files for easy integration into dashboards or SIEM tools

---

## 🛠️ Tools & Libraries

- Python 3.10+
- PyMuPDF
- docx2txt
- spacy
- transformers
- torch
- PyMuPDF (fitz)
- tqdm
- Werkzeug
- requests

---

## 📌 How to Run

1. **Clone this project**

`git clone https://github.com/Cyber-Trinity/Data-Analysis.git`

`cd Data-Analysis/Intelligent_Threat_Extractor`

2. **Install dependencies**

`pip install -r requirements.txt`


3. **Run the script**

`python threat_analysis.py`

---

## 📑 Report

A detailed project report is included as [Report_Intelligent_Threat_Extractor.pdf](https://github.com/Cyber-Trinity/Data-Analysis/blob/main/Crime%20in%20Los%20Angeles/Report_Crime_Analysis.pdf)
It contains methodology, extraction workflows, and key insight.

---