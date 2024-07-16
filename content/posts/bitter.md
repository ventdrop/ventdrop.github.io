---
title: "Bitter [IR/Malware Analysis]"
date: 2024-07-15T18:24:57+10:00
tags: ['reverse_engineering', 'DFIR', 'Threat Hunting']
draft: false
---

## Bitter (APT)
Saw a tweet with a `.chm` file showing 0 detections on VT and decided to check it out. TL;DR - I learned that the malware does nothing additional that the tweet didn't already show, but here's how I manually looked at it anyway.
- File Name: "CamScanner 10-07-2024 10.40.chm"
- MD5: 16807cb880073b1c21009f7749c8fe7f
- SHA-1: 2f4c75347aada1894e6b90d1162374ef3ce7bedf
- SHA-256: 1dd50966db005e30f7a69b6d16dfe8b9810dba3cdbe43bebb136f8786d027ed1

Note: [VT Detection Rate is now: 2/64](https://www.virustotal.com/gui/file/1dd50966db005e30f7a69b6d16dfe8b9810dba3cdbe43bebb136f8786d027ed1/detection). The file is also detected by [DocGuard](https://app.docguard.io/1dd50966db005e30f7a69b6d16dfe8b9810dba3cdbe43bebb136f8786d027ed1/d331da0f-3143-4611-841c-b6f5443f72c8/0/results/dashboard)

![VirusTotal as of 14 Jul, 2024](/static/bitter/Untitled.png)

![Link to original tweet](/static/bitter/Untitled%201.png)

[Link to original tweet](https://x.com/doc_guard/status/1812141457655976164)

![Link to original tweet reply](/static/bitter/Untitled%202.png)

[Link to tweet reply](https://x.com/StrikeReadyLabs/status/1811034367856161254)

## Static Analysis and Some History
Our sample  is a `.chm` file, which is a [Microsoft HTML Help file](https://en.wikipedia.org/wiki/Microsoft_Compiled_HTML_Help) containing a collection of HTML content. Essentially, this is Microsoft's way of packaging a webpage containing HTML files into a single file for offline viewing; typically designed to provide help for an application, but also abused by malicious actors to deliver malware. This file format being used for malicious purposes appears to date as far back as 2000 (possibly earlier). 
Here is [another good blog post](https://unit42.paloaltonetworks.com/malicious-compiled-html-help-file-agent-tesla/) from Unit42 that shows how this file format is being abused in modern malware. 

![.chm file](/static/bitter/Untitled%203.png)

The easiest way for us to manually inspect this content is to simply unzip it using a tool like 7zip:

![Unzipping the .chm file using 7zip](/static/bitter/Untitled%204.png)
We can now see a bunch of different files listed; most of these are undocumented and irrelevant pieces of info to us, but some work has been done to explain the various components in [this post](https://www.nongnu.org/chmspec/latest/index.html).

![Extracted contents](/static/bitter/Untitled%205.png)

The most important file listed is the `doc.htm` file, which contains the HTML content that will be rendered to the viewer. When we open this file up in a text editor, we see the following:

![doc.htm file contents](/static/bitter/Untitled%206.png)

This is mostly readable to us, however we can clean up and beautify the important info by utilising [CyberChef's](https://gchq.github.io/CyberChef/) 'From HTML Entity' recipe:

![decoding doc.htm contents using CyberChef](/static/bitter/Untitled%207.png)

## More Static Analysis
So far, just by looking at the decoded content, we know that the execution of this `.chm` file will:
- Spawn `conhost.exe` using the `--headless` parameter to hide child process `cmd.exe` window [Reference](https://lolbas-project.github.io/lolbas/Binaries/Conhost/)
- `Timeout` to delay execution for 5 seconds
- Create a scheduled task named `SystemDriverUpdate` using `schtasks` that runs every 16 minutes
- This scheduled task will run `conhost`, spawning a hidden `cmd` window with a call to `curl`, generating a file at `C:\Users\public\documents\dfk.dh` that is downloaded from `mxmediasolutions[.]co./chry.php?cl=%computername%_%username%` 
Note: `%computername%` and `%username` are local environment variables from the target machine passed to the URI, likely to identify the victim
- This will be executed using the `more` command on the content of that newly downloaded file piped to `cmd`

## Getting the Second Stage Payload
- File Name: "dfk.dh"
- MD5: 93ca00eca61c7cd072f19884c09f446e
- SHA1: 6ec1edf2d9e8b67060310262aa46c6d0e7f3a0ec
- SHA256: 5bd70d602b0f3810662103e2005b6db2735ca99062d941e2bf3eb1647ea9daab

The resulting file that is downloaded using curl wasn't available for us to download on VirusTotal at the time of writing, so we can simply download it ourselves for analysis. To do that, we change our malware VM to 'NAT' and use curl in a similar way to the original command.  

![Downloading the file using curl](/static/bitter/Untitled%208.png)

This produces a file named `dfk.dh` in the `C:\Users\public\documents\` folder as desired. We can now analyse this file. After running `file` and confirming this is 'ASCII text', we can open in a text editor. 

![Opening the second stage in VSCode](/static/bitter/Untitled%2010.png)

We see here another bunch of commands that we know to be executed using `cmd` from previous anaylsis. This script is:
- Using [WMIC (Windows Management Instrumentation Command Line)](https://en.wikipedia.org/wiki/Windows_Management_Instrumentation) to determine the target system’s AntiVirus product
- It gathers the target system environment variables `%userprofile` and `%username`
- Then it enumerates more system information via the `systeminfo` command
- It then lists the contents of `Downloads` , `Documents` and `Desktop` of the `%USERPROFILE` user using `dir` and also lists the contents of `C:\Users`
- It directs this information using `>` to a file created at `C:\Users\public\Music\mki.txt`
- It then uses `curl` to send a `POST` request containing this file to `hXXps[:]//www[.]mxmediasolutions[.]com/chry_zen.php?cl=%computername%_%username%`
- Finally, it deletes this previously created file using `del`

There does not appear to be any additional functionality from this malware. It appears to be designed to steal information and send to attacker controlled infrastructure. The replies to the original tweet appear to attribute this to [Bitter](https://attack.mitre.org/groups/G1002/). 

## Logging and Artifacts
By the time I got to writing this part, the malicious site was serving a 404. To counteract this, I copy pasted the contents of `dfk.dh` from a pre-existing file and executed manually. As expected, we see some useful logging, mainly from process command line auditing. This part could be extended out to include forensic artifacts, however this is a quick blog post and I will save those for another day. 

- 4688 process execution logs (WinEvtLog - 'Security'), note `hh.exe` as the Parent Process. 4688 logs by default do not log command lines, but [can be enabled to do so](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)

![Process creation logs 1](/static/bitter/Untitled%2012.png)

- Sysmon (Event 1) Process Creation logs. Shown below is the `curl` POST request commandline:

![Process creation logs 2](/static/bitter/Untitled%2011.png)

- 4698, 'A scheduled task was created' (WinEvtLog - 'Security'), we also see the maliciously created task in Task Scheduler 

## Mitigation, Threat Hunting and Detection Ideas 
This would probably light most modern EDR's up like a Christmas tree, but in case you are reading this and don't have a big budget:

- Check out the 'Crowdsourced Sigma Rules' section for the sample on VT (you will need to log in)
- Consider blocking `.chm` files from your enterprise e-mail gateway, although Outlook should already block this attachment by default
- Investigate usage of `hh.exe`, paying attention to suspiciously named files and file locations. Consider writing detections with `hh.exe` and other LOLBIN child processes
- Monitor creation of files in and under `C:\Users\Public`, this is unusual 
- Detect the creation of `conhost.exe` process with the `--headless` parameter. Existing Sigma detection from The DFIR Report can be found [here](https://github.com/The-DFIR-Report/Sigma-Rules/blob/main/rules/windows/process_creation/proc_creation_win_conhost_headless.yml)
- Investigate outbound `curl` POST requests


