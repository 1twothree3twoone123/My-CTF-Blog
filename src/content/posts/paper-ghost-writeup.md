---
title: HTB Holmes CTF 2026 - Paper Ghost Writeup
published: 2026-10-04
tags: [Holmes CTF 2026, Writeups]
category: Writeups
draft: false
---

# PaperGhost

Here's the attachment structure from the challenge:

```text
PaperGhost.zip
├── Holmes CTF 2026 - Sherlock 04 - The False Employee.pdf
└── PaperGhost/
    └── Triage/
        ├── ConsoleLog
        ├── CopyLog
        ├── SkipLog
        └── C/
            ├── Windows/System32/config/
            │   ├── SAM
            │   ├── SECURITY
            │   ├── SOFTWARE
            │   └── SYSTEM
            ├── Windows/System32/SRU/
            │   └── SRUDB.dat
            ├── ProgramData/Microsoft/search/data/applications/windows/
            │   └── Windows.edb
            └── Users/cvoss/
                ├── NTUSER.DAT
                └── AppData/
                    └── ...
```



---

## USB

I didn't really know where to start, so I just followed the questions. The Q1 mentioned the USB, so I started with the SYSTEM hive:

```bash
hivexsh SYSTEM
```

Then I went into:

```text
ControlSet001\Enum\USB
```

There were quite a few devices, but these were all the devices that is plugged on the PC. They weren't necessarily the USB.

So I moved to:

```text
ControlSet001\Enum\USBSTOR
```

There was only one actual USB storage device:

```text
Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00
```

Then, I went one level deeper:

```text
Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00
└── RS200000000627E4&0 
```

So I "accidentally" had my first answer:

**Q2: `RS200000000627E4&0`**

This made me more confident that I can find the answer to Q1.

---

### Finding the first USB connection

Inside the device's `Properties`, I checked all the properties and I found this:

```text
{83da6326-97a6-4088-9453-a1923f573b29}
```

It contained several numbered values:

```text
0003
000A
0064
0065
0066
0067
```

I checked the values from `0064` to `0067`.

The two important time were:

```text
0064 = c6 f8 c6 69 f0 2f dd 01
0065 = c6 f8 c6 69 f0 2f dd 01
```

These decoded to:

```text
2026-08-19 15:35:50.428691 UTC
```

`0064` and `0065` are installing data and first installing data, so this gave me the first USB connection time:

**Q1: `2026-08-19 15:35:50`**

---

## Finding the DIOGENES asset tag

Then I realized I might also be able to find the flag to Q5

I knew the USB identifier I had just found should be useful as a keyword, so instead of continuing to manually browse the SYSTEM, I searched the whole hive

I used:

```bash
reglookup SYSTEM 2>/dev/null | grep -i RS200000000627E4 | grep -vi '/Enum/USB'
```

This gave me another reference to the same device under:

```text
ControlSet001/Enum/SWD/WPDBUSENUM/
```

And I found it in the `FriendlyName`:

```text
FriendlyName = CO-USB-0091
```

**Q5: `CO-USB-0091`**

---

# Following the Payload

Then I decided to search for what actually happened after the USB was connected (Possible flags to Q3 and Q4).&#x20;

There was only one user in the collection:

```text
C:\Users\cvoss
```

So I opened the user's `NTUSER.DAT`:

```bash
hivexsh NTUSER.DAT
```

Explorer keeps UserAssist information about programs that have been launched, so I started with it.

I went to:

```text
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```

There were nine GUIDs.

Instead of manually opening every single one, I exported the whole thing:

```bash
reglookup -p '/Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist' ./NTUSER.DAT 2>/dev/null > /tmp/all.txt
```

Only `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` and `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` were not empty.

I checked both, but it turned out `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` wasn't useful for this challenge, so I started checking `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}`.

Then I noticed one strange UserAssist entry:

```text
"R:\\PB-YG-0469 hcqngr cnpxntr\\hcqn...rkr"
```

After decoding it:

```text
E:\CO-LT-0469 update package\update.exe
```

This is the payload full path:

**Q3: `E:\CO-LT-0469 update package\update.exe`**

---

### Execution timestamp

The same UserAssist entry also contained the execution metadata.

The important part was the 8 bytes at offset 60:

```text
90 b5 cd 7e f0 2f dd 01
```

After decoded I got:

```text
2026-08-19 15:36:25 UTC
```

I found the flag to Q4

**Q4: `2026-08-19 15:36:25`**

---

## Microphone and Webcam

I looked at Q6 and Q7. They were pretty similar, they were all hardwares.

Which means we could find both of them in one place:

```text
SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore
```

There were entries like:

```text
microphone
webcam
location
camera-related applications
...
```

I believed the Q6 would be in microphone and Q7 would be in webcam

---

## Microphone

Under:

```text
ConsentStore\microphone\NonPackaged
```

I found:

```text
E:#CO-LT-0469 update package#update.exe
```

Inside it:

```text
"LastUsedTimeStart"=hex(11):17,f5,d7,bb,f0,2f,dd,01
```

The `LastUsedTimeStart` decoded to:

```text
2026-08-19 15:38:08.113 UTC
```

This is the flag to Q6

**Q6: 2026-08-19 15:38:08**

---

## Webcam

I checked the same location under:

```text
ConsentStore\webcam\NonPackaged
```

And again, the exact same file appeared:

```text
E:#CO-LT-0469 update package#update.exe
```

This time the timestamps were:

```text
"LastUsedTimeStart"=hex(11):69,84,27,57,f1,2f,dd,01
"LastUsedTimeStop"=hex(11):24,36,d7,a2,f1,2f,dd,01
```

The difference was approximately:

```text
126.98 seconds
```

So:

**Q7: `127 `**

---

# Exfil volume

The next question asked how much data was sent.

That made me think about **SRUM**.

It records all the network traffic and data usage

So I exported it:

```bash
esedbexport -t /tmp/srum C/Windows/System32/SRU/SRUDB.dat
```

The database contained a lot tables.

After some researching, I found that `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}.9` was the network usage table.&#x20;

The only problem was that table didn't contain program names.

It only contained IDs.

So I have to find the ID in another table called `SruDbIdMapTable.4`

I tried to find it with `grep update`. It didn't work because the strings were stored as hexadecimal-encoded UTF-16LE text.&#x20;

I decoded the values with:

```bash
tail -n +2 SruDbIdMapTable.4 | awk -F'\t' '$3!=""{print $2"\t"$3}' \
| while IFS=$'\t' read id hex; do
    printf '%s\t%s\n' "$id" "$(echo "$hex" | xxd -r -p | iconv -f UTF-16LE -t UTF-8 2>/dev/null | tr -d '\0')"
  done > /tmp/idmap_decoded.tsv
```

Then I searched the decoded data for `update.exe`.

Unfortunately, I got three results:

```text
430    !!update.exe!2010/04/14:22:06:53!3b283!
436    \device\harddiskvolume5\co-lt-0469 update package\\update.exe
438    \Device\HarddiskVolume5\CO-LT-0469 update package\\update.exe
```

I searched the network table for all three IDs.

Luckily, only one of them actually appeared:

```text
228    Aug 19, 2026 15:49:59.231231208    436    374    172064531    615595
```

That gave me the flag.

ID `436` pointed to:

```text
\Device\HarddiskVolume5\CO-LT-0469 update package\update.exe
```

and the bytes sent were: `172,064,531`

The question wanted decimal MB, so:

```text
172064531 / 1000000 = 172.064531 MB
```

**Q8: `172.064531`**

---

# The Last flag

There was only one flag left:

**What developer credentials were leaked?**

This one took much longer than I expected.

I checked several different files and I couldn't find anything.

After searching throught almost all the useful files, I actually started thinking I might have to give up on Q9.

Then I remembered one file that I didn't deeply investigate earlier:

```text
C:\ProgramData\Microsoft\Search\data\applications\windows\Windows.edb
```

The file was too huge. So I didn't want to start a lot of time on it at start, but now I had to do it because the credentials couldn't be at any other files.

Just as what Holmes said," When you have eliminated the impossible, whatever remains, however improbable, must be the truth."

So I went back to it.

---

## Windows.edb

I exported the database:

```bash
esedbexport -t /tmp/winedb C/ProgramData/Microsoft/search/data/applications/windows/Windows.edb
```

There were many tables but I think it's most likely in `PropertyStore` table

I spent a long time reading this table.&#x20;

It was really tiring but finally, I found something:

```text
EXT-0419.pdf
```

It contained:

```text
Username:           tainsworth
Password:           D10g3n3s_T1ckets#2026
```

That was the last flag:

**Q9: `tainsworth:D10g3n3s_T1ckets#2026`**

---

# Final Answers

| Question | Answer                      |
| -------- | --------------------------- |
| Q1       | `2026-08-19 15:35:50`    |
| Q2       | `RS200000000627E4&0`        |
| Q3       | `E:\CO-LT-0469 update package\update.exe` |
| Q4       | `2026-08-19 15:36:25`    |
| Q5       | `CO-USB-0091`               |
| Q6       | `2026-08-19 15:38:08`    |
| Q7       | `127`                       |
| Q8       | `172.064531`                |
| Q9       | `tainsworth:D10g3n3s_T1ckets#2026` |
