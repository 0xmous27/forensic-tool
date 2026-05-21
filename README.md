# Automated Digital Forensic Tool
## NTFS Timestamp Forgery Detection using Timeline Correlation and Evidence Scoring

**Final Year Project — Group 15**
Department of Computer Science and Engineering
University of Dodoma (UDOM) | Academic Year 2025/2026

**Supervisor:** Mr. Ona Nixon

---

## Project Overview

This tool is a web-based automated digital forensic system that detects timestamp forgery in Windows NTFS disk images. It extracts forensic artifacts from multiple sources, correlates timestamps across those sources, computes evidence-based forgery scores, and generates structured forensic reports.

---

## Features

- **Disk Image Upload** — Upload NTFS disk images (.img, .dd, .raw, .e01, .001, .vmdk) with integrity hash verification (MD5, SHA-1, or SHA-256)
- **Artifact Extraction** — Extracts timestamps from:
  - `$MFT` STANDARD_INFORMATION (SI) and FILE_NAME (FN) attributes
  - `$UsnJrnl` (Update Sequence Number Journal)
  - `$LogFile` (NTFS transaction log)
  - Windows Registry hive files
  - Windows Event Logs (EVTX)
- **MACB Timestamps** — Modified, Accessed, Changed (MFT entry), Born (Created) — all normalized to UTC
- **Timeline Reconstruction** — Unified chronological timeline from all artifact sources
- **Correlation Engine** — Detects anomalies:
  - SI vs FN timestamp mismatch (primary timestomping indicator)
  - Impossible timestamps (modified before created)
  - Zero sub-second precision (timestomping artifact)
  - Future timestamps
  - USN journal vs SI mismatch
- **Evidence Scoring** — Forgery likelihood score (0–100) with reliability-weighted anomaly contributions
- **File Classification** — Genuine / Suspicious / Forged
- **Report Generation** — PDF (ReportLab) and HTML reports with timeline, anomalies, scores, and verdict
- **Interactive UI** — Bootstrap 5 interface with Plotly charts and filtering

---

## Installation (Kali Linux)

### Quick Setup

```bash
git clone https://github.com/0xmous27/forensic-tool.git
cd forensic_tool
bash setup.sh
```

### Manual Setup

```bash
# 1. Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv python3-dev \
    libssl-dev libffi-dev build-essential \
    libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0 libcairo2

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Apply migrations
python manage.py makemigrations
python manage.py migrate

# 5. Create admin user
python manage.py createsuperuser

# 6. Run the server
python manage.py runserver
```

---

## Usage

1. Open `http://127.0.0.1:8000` in your browser
2. **Upload** an NTFS disk image (the image is processed read-only)
3. **Extract Artifacts** — Click "Start Extraction" to extract timestamps from all sources
4. **Run Analysis** — Correlate timestamps and detect anomalies
5. **Run Scoring** — Compute forgery likelihood scores
6. **View Results** — Browse the timeline, forgery results, and file details
7. **Generate Report** — Download PDF or HTML forensic report

---

## Folder Structure

```
forensic_tool/
├── core/               # Shared models (DiskImage, ForensicArtifact, TimelineEntry, ForgeryResult)
├── ingestion/          # Disk image upload, validation, artifact extraction (NTFSExtractor)
├── analysis/           # Correlation engine, timeline views, forgery results
├── scoring/            # Evidence scoring engine (0–100 scale)
├── reporting/          # PDF and HTML report generation
├── templates/          # HTML templates (Bootstrap 5)
├── static/             # CSS, JS, images
├── media/uploads/      # Uploaded disk images (read-only processing)
├── logs/               # Application logs
├── requirements.txt    # Python dependencies
├── setup.sh            # Automated setup script
└── manage.py           # Django management script
```

---

## Scoring Logic

| Score Range | Classification | Meaning |
|-------------|---------------|---------|
| 0 – 30      | Genuine       | No significant anomalies |
| 31 – 60     | Suspicious    | Some anomalies, inconclusive |
| 61 – 100    | Forged        | Strong evidence of manipulation |

**Anomaly weights:**
- CRITICAL (impossible timestamps): 40 × reliability
- HIGH (SI/FN mismatch, USN mismatch): 25 × reliability
- MEDIUM (zero sub-second precision): 15 × reliability

**Source reliability weights:**
- VSS: 0.95 | USN: 0.90 | LogFile: 0.88 | EVTX: 0.80 | MFT_FN: 0.85 | Registry: 0.75 | MFT_SI: 0.60

---

## Example Workflow

```
Upload disk.img → Hash verified (MD5/SHA-1/SHA-256)
  ↓
Extract Artifacts → 15,432 artifacts from MFT, USN, LogFile, Registry, EVTX
  ↓
Run Analysis → 3 files flagged: SI/FN mismatch, impossible timestamps
  ↓
Run Scoring → suspicious.exe: score 87.5 (FORGED)
  ↓
Generate Report → forensic_report_disk.img.pdf
```

---

## Admin Interface

Access the Django admin at `http://127.0.0.1:8000/admin`
Default credentials: `admin` / `admin123`

---

## Screenshots

*(Screenshots to be added after deployment)*

- Dashboard overview
- Disk image upload page
- Forensic timeline with Plotly chart
- Forgery results table with score bars
- File detail with anomaly breakdown
- PDF report sample

---

## Group Members

| Name | Registration |
|------|-------------|
| Sarafina W. Mgani | T22-03-01712 |
| Elifuraha S. Kiangi | T22-03-08062 |
| Mathias M. George | T22-03-07128 |
| Mughutari S. Mbwana | T22-03-10581 |
| Noel D. Kweka | T22-03-07117 |

---

## License

Academic use only. University of Dodoma, 2025/2026.
