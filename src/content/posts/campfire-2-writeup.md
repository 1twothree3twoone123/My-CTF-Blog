---
title: HTB Sherlocks - Campfire-2 Writeup
published: 2026-10-15
tags: [HTB Sherlocks, Blue Team , Writeups]
category: Writeups
draft: false
---
# Campfire-2

Here's the attachment from the challenge:

```
Security.evtx
```

I started with extracting the Windows Security Event Log into a text file so I could easily search through the events.

I used the command:

```
evtx_dump Security.evtx > campfire-2.txt
```

## Finding the AS-REP Roasting activity

The first question mentioned about **AS-REP Roasting attack** and **Kerberos ticket**, so I started searching for **Event ID 4768** which is Kerberos authentication service requests.

There were eleven 4768 events, so I needed a way to narrow them down.

For AS-REP Roasting, I looked for a ticket that was requested without Kerberos pre-authentication. I was thinking that the attacker probably asked for an encrypted ticket that could be cracked offline, so I was looking for the RC4-HMAC encryption type:

```
TicketEncryptionType = 0x17
```

I searched for `0x17` and found only one result:

```
Record 74
<EventID>4768</EventID>
<TimeCreated SystemTime="2024-05-29T06:36:40.246362Z">
<Data Name="TargetUserName">arthur.kyle</Data>
<Data Name="TargetDomainName">forela.local</Data>
<Data Name="TargetSid">S-1-5-21-3239415629-1862073780-2394361899-1601</Data>
<Data Name="ServiceName">krbtgt</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="PreAuthType">0</Data>
<Data Name="IpAddress">::ffff:172.17.79.129</Data>
```

This record gave me the first four flags.

**Q1:** `2024-05-29 06:36:40`

**Q2:** `arthur.kyle`

**Q3:** `S-1-5-21-3239415629-1862073780-2394361899-1601`

**Q4:** `172.17.79.129`

---

## Finding the account used to perform the attack

The final question asked for the **account used to help the AS-REP Roasting attack**.

Since I already had the internal IP address from the previous event, I decided to search the Security log for:

```
172.17.79.129
```

This led me to another Kerberos event:

```
Record 75
<EventID>4769</EventID>
<TimeCreated SystemTime="2024-05-29T06:37:49.227372Z">
<Data Name="TargetUserName">happy.grunwald@FORELA.LOCAL</Data>
<Data Name="TargetDomainName">FORELA.LOCAL</Data>
<Data Name="ServiceName">DC01$</Data>
<Data Name="TicketEncryptionType">0x12</Data>
<Data Name="IpAddress">::ffff:172.17.79.129</Data>
<Data Name="Status">0x0</Data>
```

The important part was:

```
TargetUserName = happy.grunwald@FORELA.LOCAL
```

So, the final flag was:

**Q5:** `happy.grunwald`

---

# Final Answers

|Question|Answer|
|---|---|
|Q1|`2024-05-29 06:36:40`|
|Q2|`arthur.kyle`|
|Q3|`S-1-5-21-3239415629-1862073780-2394361899-1601`|
|Q4|`172.17.79.129`|
|Q5|`happy.grunwald`|