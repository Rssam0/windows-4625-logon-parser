# Windows failed logons (event 4625) parser

Day 2 of my learning log. In IT support a failed logon is a user who "can't sign in". In a SOC, event 4625 is how you spot someone guessing passwords. This repo is a small PowerShell script that summarizes failed logons, plus made-up sample data so the logic can be tried on any machine.

## What event 4625 is
Windows writes Security event 4625 every time a logon fails. The useful fields are:

- `TargetUserName` - the account that was tried
- `LogonType` - how the logon was attempted (network, RDP, service, ...)
- `IpAddress` - where the attempt came from
- `Status` / `SubStatus` - why it failed

## Files
- `Get-FailedLogons.ps1` - the script
- `sample-4625-events.csv` - 17 made-up failed logons (invented names and addresses, not real data)
- `sample-output.txt` - the summary the script prints for that sample data

## How to run
Sample mode, any machine, no admin rights:
```
.\Get-FailedLogons.ps1 -Sample
```
Real mode, on Windows with PowerShell as administrator:
```
.\Get-FailedLogons.ps1 -Hours 24
```

## What the sample data shows
The made-up data tells a small story: one user typed a wrong password once (normal), a service account is failing because its password expired, and one outside address tried `administrator` eight times in three minutes, then moved on to a user name that does not exist. That second pattern is password guessing, and it is what the "worth a closer look" section is for.

## Codes worth knowing
| LogonType | Meaning |
|---|---|
| 2 | Interactive (keyboard) |
| 3 | Network (file share, SMB) |
| 5 | Service |
| 10 | RemoteInteractive (RDP) |

| SubStatus | Meaning |
|---|---|
| 0xC0000064 | user name does not exist |
| 0xC000006A | correct user, wrong password |
| 0xC0000234 | account locked out |
| 0xC0000071 | password expired |
| 0xC0000072 | account disabled |

## What I learned
- A single 4625 is noise. Grouped by user, source and reason, it becomes a story.
- `0xC0000064` (no such user) versus `0xC000006A` (wrong password) shows whether someone is guessing names or passwords.
- A burst of failures that ends in `0xC0000234` means the lockout policy just did its job.
- `Get-WinEvent -FilterHashtable` is the right tool: Windows does the filtering, instead of PowerShell reading every event.
- The event's fields live in its XML, and reading them by name beats guessing array positions.

## How I'd explain it in an interview
"Event 4625 is a failed logon. I'd group failures by account and source IP: one or two is a typo, a burst from one address is guessing. The SubStatus code matters too. 0xC000006A means the account exists and the password was wrong; 0xC0000064 means the account name itself doesn't exist."

## Not covered yet
Correlating 4625 with the 4624 success that can follow a correct guess, Kerberos events 4768/4771, and sending the summary somewhere central like a SIEM.
