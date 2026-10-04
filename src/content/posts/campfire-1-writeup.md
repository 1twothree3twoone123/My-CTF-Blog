---
title: HTB Sherlocks - Campfire-1 Writeup
published: 2026-10-04
tags: [HTB Sherlocks, Writeups]
category: Writeups
draft: false
---
# Campfire-1

Here's the attachment from the challenge:

```
Domain Controller/
└── SECURITY-DC.evtx

Workstation/
└── 2024-05-21T033012_triage_asset  
└── Powershell-Operational.evtx
```

I started with the **Domain Controller**, because that was what the task 1 asked.

I used the command:

```
evtx_dump SECURITY-DC.evtx > dc_log.txt
```

## Finding the Kerberoasting activity

The first question asked when is the Kerberoasting activity, so I started by searching for **Event ID 4769**, which records Kerberos service ticket requests.

There were sixteen 4769 events, so I needed a way to narrow them down.

First, I didn't want any computer accounts ending in `$`. Those are machine accounts such as `DC01$` and they aren't the interesting targets here.

I also didn't want `krbtgt`, because that account generates a lot of normal Kerberos-related activity.

I also needed the encryption type `0x17` which is RC4-HMAC.

Finally, I only wanted the request to have succeeded which the status was 0x0.

Then I found this:

```
Record 256
<EventID>4769</EventID>
<TimeCreated SystemTime="2024-05-21T03:18:09.459682Z">
<Data Name="TargetUserName">alonzo.spire@FORELA.LOCAL</Data>
<Data Name="ServiceName">MSSQLService</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="IpAddress">::ffff:172.17.79.129</Data>
<Data Name="Status">0x0</Data>
```

This gave me the first three flags.

**Q1:** `2024-05-21 03:18:09 UTC`

**Q2:** `MSSQLService`

**Q3:** `172.17.79.129`

---

## Moving to the workstation

The next questions mentioned PowerShell logs, so I moved to the **Workstation**.

I knew that PowerShell Script Block uses Event ID `4104`, so I started with those events.

There were 29 of them.

The first one was:

```
powershell -ep bypass
```

This command meant not blocking any scripts or displaying warnings.

I guessed that the next step would probably be executing some scripts. As I expected, I found this next:

```
Record 15
<EventID>4104</EventID>
<TimeCreated SystemTime="2024-05-21T03:16:32.588340Z">
<Data Name="ScriptBlockText">#requires -version 2
...
</Data>
<Data Name="Path">C:\Users\alonzo.spire\Downloads\powerview.ps1</Data>
```

I found the flag 4 and 5:

**Q4:** `powerview.ps1`

**Q5:** `2024-05-21 03:16:32 UTC`

---

## Looking at Prefetch

Then I went here for the taks 6

```
/Workstation/2024-05-21T033012_triage_asset/C/Windows/prefetch
```

I found RUBEUS.EXE-5873E24B.pf. Rubeus is a well-known Kerberos/Active Directory tool, and I didn't really think it was suppose to be at a normal business environment.

I checked the Prefetch metadata:

```
Executable filename : RUBEUS.EXE
Run count           : 1

Last run time:
May 21, 2024 03:18:08.972822200 UTC
```

The Prefetch data also showed:

```
\VOLUME{01d951602330db46-52233816}\USERS\ALONZO.SPIRE\DOWNLOADS\RUBEUS.EXE
```

which was:

```
C:\Users\alonzo.spire\Downloads\Rubeus.exe
```

That was the flag 6:

**Q6:** `C:\Users\alonzo.spire\Downloads\Rubeus.exe`

The Prefetch timestamp also gave me the answer to the final flag:

```
2024-05-21 03:18:08 UTC
```

So:

**Q7:** `2024-05-21 03:18:08 UTC`

---

# Final Answers

| Question | Answer                                       |
| -------- | -------------------------------------------- |
| Q1       | `2024-05-21 03:18:09 UTC`                    |
| Q2       | `MSSQLService`                               |
| Q3       | `172.17.79.129`                              |
| Q4       | `powerview.ps1`                              |
| Q5       | `2024-05-21 03:16:32 UTC`                    |
| Q6       | `C:\Users\alonzo.spire\Downloads\Rubeus.exe` |
| Q7       | `2024-05-21 03:18:08 UTC`                    |