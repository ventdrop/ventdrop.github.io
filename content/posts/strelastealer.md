---
title: "Strela Stealer [IR/Malware Analysis]"
date: 2024-02-25T23:10:37+11:00
draft: false
---

## Strela Stealer
I decided to grab a random malware sample from [any.run](http://any.run) and have a bit of a poke around. The file I chose from public submissions has the following details:
- MD5: 09a3293c8e85921340f2e75cf398b0a5
- FileName: 2585747226036.zip
- Extracted FileName: 2585747226036.js

This file showed as [no threats detected in the sandbox](https://app.any.run/tasks/fd24f96b-532b-422e-90b8-bdc4b4adfe14/#). Despite it showing no malicious activity (note the .dll error message box below which may be a deception technique or a legitimate error), a quick look at the AnyRun process tree shows some interesting things; we’ll keep this in mind for our analysis. The .zip file not present in VirusTotal, however the extracted file is (as we will see shortly).

![AnyRun Process Tree](/static/strelastealer/Untitled.png)
![Potential decoy messagebox or legitimate error](/static/strelastealer/Untitled%201.png)

When we extract the file using 7zip, we are presented with a JavaScript (.js) file with an MD5 hash of 99FE12C3063214D993A90D154D3D0BC7. This file has [10/60 detections in VirusTotal at time of writing](https://www.virustotal.com/gui/file/9f3e1183f281b1961fc3fe8c96ab39a9a66ffb0c179eaf7c76af0b9cbc5333c2/detection)

![The two files, .js extracted from .zip](/static/strelastealer/Untitled%202.png)
![Getting the file hash via PowerShell](/static/strelastealer/Untitled%203.png)
![VirusTotal results, 10/60](/static/strelastealer/Untitled%204.png)

## Script Analysis

Taking a look at this file in VSCode, we are met with 1844 lines:
![Big wall of text in the script content, filled with junk](/static/strelastealer/Untitled%205.png)

To clean this up a bit, we see variables being set at the top of the file to form what looks to be an alphabet (note 26 lines). We can `CTRL + F` to find and replace all of these with the value assigned to the right, for example, `plausiblewristsidewalksincere` simply becomes `h`.
![Using find + replace to fix it up a bit](/static/strelastealer/Untitled%206.png)

This could be scripted or done using regex to save time, however I have chosen to do it manually as there aren’t that many. Once this is completed we see some strings such as `cd %temp% & echo` and `findstr /V`. Once these variables have been replaced, we can copy everything to a new file and delete lines 1-27.
![We can delete lines 1-27 now as they are redundant](/static/strelastealer/Untitled%207.png)

Something that jumps out straight away here to me is on line 30 (now line 3), notably the string `TVqQAAMAAA` and so on. You may be familiar with this value, as it is the Base64 representation of the ‘magic bytes’ ‘MZ’, see: [https://en.wikipedia.org/wiki/DOS_MZ_executable](https://en.wikipedia.org/wiki/DOS_MZ_executable)
This is interesting and likely indicates that content from line 30 down will contain a full Windows executable, see below a Base64 decode in CyberChef: 
![MZ header as represnted in Base64 in CyberChef](/static/strelastealer/Untitled%208.png)

Scrolling down, we see that this Base64 likely ends on line 1814 (1787 if you deleted lines 1-27), as we start to see human readable words on line 1815. Selecting everything from the beginning of line 30 (or 3) until the end of line 1814 (or 1787) and copying it into our CyberChef Recipe, we are indeed presented with a Portable Executable file of size 733,419 bytes:
![Copying our content](/static/strelastealer/Untitled%209.png)
![Decoding from Base64 in CyberChef gets us a .dll](/static/strelastealer/Untitled%2010.png)

We will investigate this shortly. Deleting the Base64 contents out of the script to save space, we now see the following. We note here that the interesting values appear to stop with the first instance of `/*hfjbm*/`. 
![More junk in the script taking up space](/static/strelastealer/Untitled%2011.png)

If we search for this string using `CTRL + F` we can see that these values don’t do anything and appear outside the main code, therefore we can conclude (after scrolling to the bottom) that this was likely included as an anti-analysis functionality and to waste our time decoding. 
![Some more Find + Replace](/static/strelastealer/Untitled%2012.png)
![Matching the junk content and replacing](/static/strelastealer/Untitled%2013.png)

Using the same search/replace window, we can input the string `hfjbm*.\/\/[*]*`, change the find mode to ‘*Use Regular Expression*’ and leave the ‘*Replace*’ field blank, then hit ‘*Replace All*’. 
![Using regex matching](/static/strelastealer/Untitled%2014.png)

Then we can manually delete the remaining `*/hfjbm/` string (this was not captured by our regex as it has a singular leading forward slash. We see in our remaining script a very similar behaviour as we saw on lines 1-27. The script is now declaring an empty array with the variable name `plausiblewrist` (same name as before) and will then store each subsequent key value pair within it. After replacing our values in a similar fashion to the first time (or in a scripted/regex fashion), we end up with something like the following (note that some of the `%` characters have been cleaned up for readability:
![Script cleaned up a little bit](/static/strelastealer/Untitled%2015.png)

We can still tidy this up a bit, first by modifying the `.toUpperCase` characters and second by removing the concatenation characters `+`. Cleaned up, we get something like the below:
![Fully cleaned up script](/static/strelastealer/Untitled%2016.png)

## Static DLL Analysis

.dll SHA256: BE64FBFEF667455CDE44ADC8EDF213F195F1052B0CC41747A82B41E5A0D257F8
No matches in VirusTotal. 
[https://hybrid-analysis.com/sample/be64fbfef667455cde44adc8edf213f195f1052b0cc41747a82b41e5a0d257f8](https://hybrid-analysis.com/sample/be64fbfef667455cde44adc8edf213f195f1052b0cc41747a82b41e5a0d257f8)

Hybrid Analysis initially showed as clean but now shows the following (after a refresh) at time of writing. 
![Hybrid Analysis AV results](/static/strelastealer/Untitled%2017.png)

I sent this to Hybrid Analysis for dynamic execution, results can be seen [here](https://hybrid-analysis.com/sample/be64fbfef667455cde44adc8edf213f195f1052b0cc41747a82b41e5a0d257f8/65d7282fff04d6a733004d38).
This doesn’t appear to give us a full set of IOC’s to work with, so we will do our own analysis from here. 

We can rename our .dll file to `ringsbeef.dll` as we know this to be the filename from above script analysis and then open it in PEStudio for some initial static analysis. We note quite a number of suspicious ‘indicators’. 
![PEStudio results](/static/strelastealer/Untitled%2018.png)
![PEStudio Indicators](/static/strelastealer/Untitled%2019.png)

We note that there is a singular export, named `h` (screenshots below from PEBear). We also note the unusual amount of PE Sections (18, also noted above in PEStudio).
![PEBear Exports](/static/strelastealer/Untitled%2020.png)
![PEBear Sections, note there are lots](/static/strelastealer/Untitled%2021.png)

The Raw and Virtual section headers don’t match up, which may potentially indicate packed or encrypted contents:
![Raw v Virtual section headers in PEBear](/static/strelastealer/Untitled%2022.png)

By looking at the main export `h` we can see the .dll appears to be performing all sorts of arithmetic to operands, presumably to avoid easy static analysis; these will likely go through a decryption routine and resolve themselves dynamically. The `h` function is quite large (more than 1000 nodes) and contains what appears to be many unnecessary arithmetic operations for no other reason than to make it look more complicated and take up resources. 
![IDA disassembly version of 'h'](/static/strelastealer/Untitled%2023.png)
![IDA graph view of 'h', unusually long function](/static/strelastealer/Untitled%2024.png)

Looking at the strings window in IDA, it looks like the strings are indeed encoded or encrypted:
![Encrypted strings in IDA](/static/strelastealer/Untitled%2025.png)

## Dynamic DLL Analysis

The quickest way we can analyse this sample and gather IOC’s will be with dynamic execution. To do this, we can load `rundll32.exe` into our debugger (x64dbg), select `File -> Change Command Line`, then provide a path to the malicious .dll and it’s first ordinal export (#1), the first ordinal refers to `h` that we saw earlier in our screenshot from PEBear.
![Change Command Line in x64dbg to execute our 'h' function](/static/strelastealer/Untitled%2026.png)

Pressing `F9` to reload rundll32.exe, then `F9` again to break on the EntryPoint of rundll32. The next two F9’s will hit the TLS Callback’s for ringsbeef.dll, we have now entered ringsbeef.dll instead of rundll32.exe—this will be indicated at the top of the application, note in the below that it now says Module: ringsbeef.dll. Note: you can also select `Options -> Preferences -> Events -> Break on -> Dll Entry` if you wish to break at DllMain in ringsbeef instead. 
![We are now in ringsbeef.dll](/static/strelastealer/Untitled%2027.png)

If we run this again without any breakpoints, debugging will stop and the program will disappear; there is something happening in the execution after this point that appears to be causing the program to terminate; this could be anti-debugging or it could be something else. In order to get around this in a timely fashion, we can set a breakpoint on VirtualAlloc by typing in the Command window: `bp VirtualAlloc` (note that this needs to be done within the context of ringsbeef.dll and not rundll32.exe). We then hit `F9` again until we come to VirtualAlloc. Once here, we hit enter to enter this call and then click the button for `Execute till return` twice. Execution should now continue without terminating; this will allow us to inspect the memory of the rundll32.exe process using Process Hacker. Opening up Process Hacker as an administrator, then right clicking rundll32.exe and selecting properties, we click the `Memory` tab. Once in here, we can select `strings...` tab. 
![rundll32.exe strings section of Process Hacker](/static/strelastealer/Untitled%2028.png)

Once here, we can now see the deobfuscated/decrypted strings in memory from ringsbeef.dll. Note here that we now have some network IOC’s in the form of:
`91[.]215[.]85[.]209/server.php` and `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36` 

Looking at the below strings alone, it looks like ringsbeef.dll may be looking to steal Outlook and Thunderbird data.
![rundll32.exe strings in memory](/static/strelastealer/Untitled%2029.png)

Looking on [VirusTotal](https://www.virustotal.com/gui/url/c08944d41d1d9d61088d5a01740e1594e8c1d3ce0369667b75cb9d53c32ffdca), we find 14/91 detections at time of writing for this IP + uri path. The community notes mention that this indicator was found in a report, which can be seen [here:](https://asec.ahnlab.com/en/53158/) - this appears to be `Strela Stealer` malware. This IP address is also referenced in a write-up [here](https://research.openanalysis.net/strelastealer/stealer/2023/05/07/streala.html) by OALabs,  and also in a great technical write-up .pdf [here from Basque CyberSecurity Centre](https://www.ciberseguridad.eus/sites/default/files/2023-08/BCSC-Malware-Strela-TLPClear.pdf)(note, the source is written in Spanish).
After reading various sources, Strela appears to be focused on stealing Outlook and Thunderbird data from users and sending it back to the attacker via HTTP.

## Mitigation and Detection Ideas

- Consider changing the default interpreter for `.js` files from `Microsoft Windows Based Script Host` to be `Notepad` or similar. [This can be done via Group Policy](https://www.csoonline.com/article/570197/how-to-block-malicious-javascript-files-in-windows-environments.html) and can prevent malicious or accidental execution. 
- Monitor, alert or block command line execution from `rundll32.exe` which includes files located in `%TEMP%` or `%USERPROFILE%` (Sysmon/EDR)
- Monitor, alert or block network traffic to newly seen IP addresses
- Threat hunt for usage of suspicious or abnormal User Agents
- See above linked pdf from Basque CyberSecurity Centre for comprehensive MITRE ATTACK mappings and further recommendations

We can also use [Splunk’s Attack Range](https://github.com/splunk/attack_range) to detonate the malicious file and review some Windows Event Logs:
![Our malicious files on Splunk AR desktop](/static/strelastealer/Untitled%2030.png)

Taking a look at `4688` process creation WinEventLogs with a query like the following (note that I have targeted the relevant processes we are expecting to see) and we get a nice visual representation of the attack chain as we saw earlier in the original .js script:

```python
index=win host=aliens-win-dc EventCode=4688
| where match(CommandLine,"(rundll32|wscript|7|cmd.exe|certutil|findstr)")
| where NOT match(ParentProcessName,"splunkd.exe|svchost.exe")
| table _time, ParentProcessName, NewProcessName, CommandLine
| sort -_time
```

![Results of our process creation WinEventLog search in Splunk](/static/strelastealer/Untitled%2031.png)
We can also do something similar with Sysmon Process Creation - Event Type 1 logs:

```python
index=win host=aliens-win-dc source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 NOT taskmgr.exe
| where NOT match(ParentImage,"(splunkd|svchost)")
| table _time, EventCode, ParentImage, ParentCommandLine, Image, CommandLine, User
| sort -_time
```

![Results of our Sysmon process creation search in Splunk](/static/strelastealer/Untitled%2032.png)

Worth also looking at Sysmon Type 11, File Creation logs:
![Sysmon type 11 logs in Splunk](/static/strelastealer/Untitled%2033.png)

## Appendix

I decided to [run the extracted .dll in the same sandbox][https://app.any.run/tasks/4e61bb73-e920-488d-98c2-514c0dabca70] with the correct command line parameters to see if we could get any further information; unfortunately execution was not successful. Would love to hear from anyone who decides to statically analyse this sample :)
