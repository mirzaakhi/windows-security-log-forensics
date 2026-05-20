# Windows Security Event Log Forensics | Brute-Force Attack Simulation

This repository supports reproducible forensic analysis of Windows Security Event Logs. It simulates a brute-force authentication attack on a Windows 11 host and parses the resulting Security.evtx file using EvtxECmd. EvtxECmd is an open-source Windows Event Log parser developed by Eric Zimmerman that converts binary .evtx files into structured CSV output, enabling downstream analysis with standard data processing tools. It analyses EventID 4625 failed logon records through a Python-based triage and timeline visualisation pipeline.

## Repository Structure

| File | Description |
|------|-------------|
| `evtx_triage.py` | Automated triage of EvtxECmd CSV output. Flags one-minute time intervals with anomalous failed logon counts (threshold: 10 failures/min; observed baseline: below 3 failures/min) and classifies each flagged interval as CRITICAL, HIGH, or LOW based on whether a successful logon (EventID 4624) or process creation (EventID 4688) was recorded on the same host within five minutes after the failed logon burst. |
| `evtx_timeline.py` | Temporal visualisation of EventID 4624 (successful logon) and EventID 4625 (failed logon) activity across a 24-hour window. Outputs a forensic timeline figure with a detection threshold line, observed baseline annotation, and attack annotations. |
| `README.md` | Reproduction guide and documentation. |

---

## Requirements

### System
- Windows 11 (the experiment targets the local Windows Security Event Log)
- PowerShell (run as Administrator)

### Tools
- [EvtxECmd v2026+](https://ericzimmerman.github.io/#!index.md) — Windows Event Log parser by Eric Zimmerman
- Python 3.7 or later

### Python packages
```
pip install pandas matplotlib
```
---
## Target EventIDs

| EventID | Meaning |
|---------|---------|
| 4624 | Successful logon |
| 4625 | Failed logon attempt |
| 4688 | New process created |

---

## Step-by-Step Reproduction

### Step 1 — Download and extract EvtxECmd

Download EvtxECmd from Eric Zimmerman's tools page:
```
https://ericzimmerman.github.io/#!index.md
```

Extract the zip file. Note: `$env:USERPROFILE` automatically resolves to your 
Windows user home directory (e.g. `C:\Users\YourUsername`):

```powershell
Expand-Archive -Path "$env:USERPROFILE\Downloads\EvtxECmd.zip" `
    -DestinationPath "$env:USERPROFILE\Downloads\EvtxECmd" -Force
```

Navigate into the folder:
```powershell
cd "$env:USERPROFILE\Downloads\EvtxECmd\EvtxECmd"
```

---

### Step 2 — Copy the Security.evtx file

Windows locks `Security.evtx` while the Event Log service is running. Copy it first:
```powershell
Copy-Item "C:\Windows\System32\winevt\Logs\Security.evtx" `
    -Destination "C:\Users\$env:USERNAME\Downloads\Security_baseline.evtx" -Force
```

---

### Step 3 — Simulate a brute-force attack

Run the following loop in Administrator PowerShell to generate 20 failed logon attempts (EventID 4625) within approximately 6 seconds:
```powershell
1..20 | ForEach-Object {
    net use \\localhost\IPC$ /user:fakeattacker wrongpassword123 2>$null
    net use \\localhost\IPC$ /delete 2>$null
    Start-Sleep -Milliseconds 400
}
```

This generates 20 EventID 4625 records within approximately 6 seconds, consistent with an automated rapid burst brute-force attack pattern. In this experiment, records were captured between 18:07:28 and 18:07:34 on 20 May 2026. Timestamps will reflect the time of your own simulation.

---

### Step 4 — Re-export Security.evtx after simulation

Immediately after the simulation completes, re-copy the log to capture the new events:
```powershell
Copy-Item "C:\Windows\System32\winevt\Logs\Security.evtx" `
    -Destination "C:\Users\$env:USERNAME\Downloads\Security_attack.evtx" -Force
```

---

### Step 5 — Parse with EvtxECmd

Run EvtxECmd on the copied file (ensure you are in the EvtxECmd folder):
```powershell
.\EvtxECmd.exe -f "C:\Users\$env:USERNAME\Downloads\Security_attack.evtx" --csv output
```

The CSV output will be saved to the `output\` folder with a timestamped filename, for example:
```
output\20260520180919_EvtxECmd_Output.csv
```

---
### Step 6 — Verify the export

Confirm that EventID 4625 records were captured in the new CSV:
```powershell
python -c "
import pandas as pd, glob, os
csv = max(glob.glob('./output/*.csv'), key=os.path.getmtime)
print('Using:', csv)
df = pd.read_csv(csv, low_memory=False)
df['TimeCreated'] = pd.to_datetime(df['TimeCreated'], infer_datetime_format=True, errors='coerce')
fails = df[df['EventId']==4625]
print('Total 4625 records:', len(fails))
print(fails['TimeCreated'].to_string())
"
```

You should see 20 EventID 4625 records with timestamps clustered within approximately 6 seconds of each other, confirming the simulation was captured successfully.

---
### Step 7 — Copy the Python scripts

Copy `evtx_triage.py` and `evtx_timeline.py` into the EvtxECmd folder:
```powershell
copy "$env:USERPROFILE\Downloads\evtx_triage.py" "."
copy "$env:USERPROFILE\Downloads\evtx_timeline.py" "."
```

---

### Step 8 — Run the triage script

Replace the filename with your actual CSV filename:
```powershell
python evtx_triage.py --csv "./output/YourCSVFilename_EvtxECmd_Output.csv"
```

**Expected output:**
```
[+] Loading: ./output/YourCSVFilename_EvtxECmd_Output.csv
[+] Filtered rows (target EventIDs): ...
=== Event Count by Type ===
  EventID 4624 (Successful logon): ...
  EventID 4625 (Failed logon): 20
  EventID 4688 (Process created): ...
=== Flagged Windows (threshold >= 10 failures/min) ===
TimeCreated
YYYY-MM-DD HH:MM:00    20
=== Enriched Triage Summary ===
        WindowStart  FailureCount  SuccessFollowed  ProcessFollowed Severity
YYYY-MM-DD HH:MM:00            20            False            False      LOW
```
---

### Step 9 — Run the timeline visualisation script

```powershell
python evtx_timeline.py --csv "./output/YourCSVFilename_EvtxECmd_Output.csv"
```

**Expected output:**
- A matplotlib window displaying the 24-hour EventID frequency 
  timeline for the experiment day
- `fig_event_timeline.pdf` saved in the current folder
- `fig_event_timeline.png` saved in the current folder

---

## Citation

If you use these scripts in your research, please cite:

```bibtex
@misc{akhi_forensic_github,
  author       = {Akhi, Mirza},
  title        = {Windows Security Event Log Forensics},
  year         = {2026},
  publisher    = {GitHub},
  howpublished = {\url{https://github.com/mirzaakhi/windows-security-log-forensics}},
  note         = {Accessed: 2026}
}
```

---

## Research Context
This repository is part of a research paper on log analysis and security operations, which incorporates original experiments in Windows Security Event Log forensics. The research was carried out as part of a module led by Dr. Lubna Luxmi Dhirani at the University of Limerick.

---

## Licence

MIT
