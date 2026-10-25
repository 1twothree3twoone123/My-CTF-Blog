---
title: HTB Sherlocks - CrownJewel-1 Writeup
published: 2026-10-25
tags: [HTB Sherlocks, Blue Team , Writeups]
category: Writeups
draft: false
---
# CrownJewel-1

## Examining the Evidence

Here's the attachment from the challenge:

```
.
├── C
│   └── $MFT
├── Microsoft-Windows-NTFS.evtx
├── SECURITY.evtx
└── SYSTEM.evtx
```

Then, I did some research about these files and Google told me these:

**SYSTEM.evtx** records operating system and main system component events like service status changes and system startup or shutdown activities

**SECURITY.evtx** records security audit events, like account activity, group enumeration, process creation, and other security events.

**Microsoft-Windows-NTFS.evtx** records NTFS file system events.

**$MFT** stores metadata about files and directories on an NTFS volume like filenames, timestamps, file sizes, and parent directory references.

---

## Question 1

The first question asked when the Volume Shadow Copy service entered a running state.

We should be able to find it in `SYSTEM.evtx` because all service status changes are recorded in the System.

At first, I searched for Event ID `7036` which records events are from Service Control Manager. But there were too many 7036 records, so I searched for `Volume Shadow Copy` instead.

This gave me a single relevant result:

```
<EventID>7036</EventID>
<TimeCreated SystemTime="2024-05-14T03:42:16.783105Z">
<Data Name="param1">Volume Shadow Copy</Data>
<Data Name="param2">running</Data>
```

This gave me the first flag.

**Q1:** `2024-05-14 03:42:16`

---

## Question 2

The second question asked which two user groups the Volume Shadow Copy process queried and which machine account performed the queries.

I first searched for Event ID `4799` which records the enumeration of security-enabled local group membership.

I still found the same issue which is there were too many 4799 records so I tried searching for `Volume Shadow Copy` like last time, but I didn't find any results.

Then, I searched for `VSS` and found eight matching records and the first two were the records I wanted

The first record was:

```
<EventID>4799</EventID>
<TimeCreated SystemTime="2024-05-14T03:42:16.793460Z">
<Data Name="TargetUserName">Administrators</Data>
<Data Name="TargetDomainName">Builtin</Data>
<Data Name="SubjectUserName">DC01$</Data>
<Data Name="SubjectDomainName">FORELA</Data>
<Data Name="CallerProcessId">0x1190</Data>
<Data Name="CallerProcessName">C:\Windows\System32\VSSVC.exe</Data>
```

And the second record was:

```
<EventID>4799</EventID>
<TimeCreated SystemTime="2024-05-14T03:42:16.794484Z">
<Data Name="TargetUserName">Backup Operators</Data>
<Data Name="TargetDomainName">Builtin</Data>
<Data Name="SubjectUserName">DC01$</Data>
<Data Name="SubjectDomainName">FORELA</Data>
<Data Name="CallerProcessId">0x1190</Data>
<Data Name="CallerProcessName">C:\Windows\System32\VSSVC.exe</Data>
```

The `TargetUserName` fields showed the two groups as `Administrators` and `Backup Operators`. The `SubjectUserName` field showed the machine account as `DC01$`.

Therefore, the flag were:

**Q2:** `Administrators, Backup Operators, DC01$`

---

## Question 3

The third question asked for the Process ID of the Volume Shadow Copy service process in decimal.

While reading the two Event ID `4799` records, I noticed these:

```
<Data Name="CallerProcessId">0x1190</Data>
<Data Name="CallerProcessName">C:\Windows\System32\VSSVC.exe</Data>
```

The PID was recorded in hexadecimal, so I converted it to decimal:

```
0x1190 = 4496
```

**Q3:** `4496`

---

## Question 4

The fourth question asked for the Volume ID/GUID assigned to the shadow copy when it was mounted.

I moved to `Microsoft-Windows-NTFS.evtx` and I searched for `Volume Shadow Copy` and `VSS`, but neither search returned the result I needed.

Then, I searched for `shadow`, which led me to Record 124:

```
<EventID>4</EventID>
<TimeCreated SystemTime="2024-05-14T03:44:22.812931Z">
<Data Name="VolumeCorrelationId">06C4A997-CCA8-11ED-A90F-000C295644F9</Data>
<Data Name="DeviceName">\Device\HarddiskVolumeShadowCopy1</Data>
```

That showed the flag to the question 4.

**Q4:** `{06c4a997-cca8-11ed-a90f-000c295644f9}`

---

## Question 5

The fifth question asked for the full path of the dumped NTDS database.

I started by exporting the MFT data to JSON format:

```
mft_dump -o jsonl '$MFT' > mft.jsonl
```

Then I checked the structure of the records with:

```
grep -i 'ntds' mft.jsonl | head -1 | jq .
```

After that, I used this Python script:

```
import json
names = {}
def find(o):
    if isinstance(o, dict):
        if "name" in o and isinstance(o.get("parent"), dict):
            yield o
        for v in o.values():
            yield from find(v)
    elif isinstance(o, list):
        for v in o:
            yield from find(v)
for line in open("mft.jsonl"):
    r = json.loads(line)
    for a in r["attributes"]:
        if a["header"]["type_code"] == "FileName":
            for f in find(a):
                if f.get("namespace") != "DOS":
                    names[r["header"]["record_number"]] = (f["name"], f["parent"]["entry"])
e, p = 42, []
while e != 5 and e in names:
    n, e = names[e]
    p.append(n)
print(p[::-1])
```

The script printed:

```
['Users', 'Administrator', 'Documents', 'backup_sync_dc']
```

The database filename for NTDS should be `ntds.dit`, so I added it into the directory path.

**Q5:** `C:\Users\Administrator\Documents\backup_sync_dc\ntds.dit`

---

## Question 6

The sixth question asked when the newly dumped `ntds.dit` file was created on disk.

While checking the MFT data for question 5, I found the output contained the following information about `ntds.dit`:

```
{
  "created": "2024-05-14T03:44:22.813756Z",
  "name": "ntds.dit"
}
```

This shows when the ntds.dit was created

**Q6:** `2024-05-14 03:44:22`

---

## Question 7

The final question asked which registry hive was dumped alongside the NTDS database and what its file size was in bytes.

I also found SYSTEM within the same place as question 6.

`SYSTEM` is a Windows registry hive. I compared its timestamps with those of `ntds.dit`:

|File|Modified Time|Created Time|
|---|---|---|
|`ntds.dit`|`2023-03-27`|`2024-05-14 03:44:22`|
|`SYSTEM`|`2023-03-25`|`2024-05-14 03:44:42`|

Both files had modification dates earlier than their creation dates on the volume.

The MFT record for `SYSTEM` showed a file size of `17563648` bytes.

So, the final answer was:

**Q7:** `SYSTEM, 17563648`

---

# Final Answers

|Question|Answer|
|---|---|
|Q1|`2024-05-14 03:42:16`|
|Q2|`Administrators, Backup Operators, DC01$`|
|Q3|`4496`|
|Q4|`{06c4a997-cca8-11ed-a90f-000c295644f9}`|
|Q5|`C:\Users\Administrator\Documents\backup_sync_dc\ntds.dit`|
|Q6|`2024-05-14 03:44:22`|
|Q7|`SYSTEM, 17563648`|