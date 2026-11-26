# Windows failed logons (event 4625)

Day 2 of my learning log. In IT support a failed logon is a user who "can't sign in". In a SOC it's how you spot someone guessing passwords. This is a small PowerShell script that sums up failed logons, plus a made-up sample file so it runs anywhere.

The useful fields in a 4625:
- TargetUserName - the account that was tried
- LogonType - how (network, RDP, service...)
- IpAddress - where it came from
- SubStatus - why it failed

Files:
- `Get-FailedLogons.ps1` - the script
- `sample-4625-events.csv` - 17 made-up failed logons, invented names and IPs, not real data
- `sample-output.txt` - what the summary looks like for that sample

Run it:
```
.\Get-FailedLogons.ps1 -Sample        # sample mode, works anywhere
.\Get-FailedLogons.ps1 -Hours 24      # real log, needs Windows + admin
```

The sample data tells a little story on purpose: one user types a wrong password once (normal), a service account fails because its password expired, and one outside IP tries `administrator` 8 times in three minutes, then moves to names that don't exist. That last pattern is password guessing, and it's what the "worth a closer look" section is for.

Codes worth knowing:
- logontype 2 = interactive (keyboard), 3 = network (file share), 5 = service, 10 = RDP
- substatus 0xC0000064 = no such user, 0xC000006A = wrong password, 0xC0000234 = locked out, 0xC0000071 = password expired, 0xC0000072 = disabled

What I learned:
- one 4625 on its own is noise. grouped by user, IP and reason it turns into a story
- 0xC0000064 vs 0xC000006A tells you if they're guessing names or passwords
- a burst that ends in 0xC0000234 means the lockout policy just did its job
- `Get-WinEvent -FilterHashtable` is the way to go - windows does the filtering instead of powershell reading every event
- the fields live in the event's XML. read them by name, don't guess array positions

How I'd explain it in an interview: "event 4625 is a failed logon. I'd group failures by account and source IP - one or two is a typo, a burst from one address is guessing. the substatus matters too: 0xC000006A means the account exists but the password was wrong, 0xC0000064 means the account name doesn't exist."

Not covered: linking 4625 to the 4624 success that might follow a good guess, Kerberos events 4768/4771, sending this somewhere central like a SIEM.
