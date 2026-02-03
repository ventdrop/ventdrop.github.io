---
title: "DLL Sideloading - JRTools.dll"
date: 2026-02-03T17:12:41+11:00
tags: ['DFIR','Threat Hunting','dll sideloading']
draft: false
---

## Overview

Just a quick blog post to provide research for a [HijackLibs](https://hijacklibs.net/) submission. The software `J River Media Center`, which can be downloaded from [here](https://www.jriver.com/download.html) contains an executable (`JRService.exe`) that is vulnerable to DLL sideloading. DLL sideloading matters because it allows attackers to run malicious code under the cover of a trusted, digitally signed program, making the attack nearly invisible to many security tools that only scrutinize the "safe" executable.

## Testing

During testing, the file `MediaCenter350038-x64.exe` was downloaded and used. This file has the following SHA256: `5ba63f08692ae6a7d70d0b9c7414d85928ae86e59d5e4aef59e6b5a98e2f1e09`.
When this setup installer is run and the application is installed, files are created in the directory `C:\Program Files\J River\Media Center 35`. 
When the application is installed using this method, and the files `JRService.exe` and `JRTools.dll` exist in those locations, the application will load this dll no matter where else these files are placed on disk.
During testing, the SHA256 hash of `JRService.exe` was `73dc3291cbc89663ecec0c5169000cc0bf153dab7decefabd31fc12bae2fc548` [VT](https://www.virustotal.com/gui/file/73dc3291cbc89663ecec0c5169000cc0bf153dab7decefabd31fc12bae2fc548) and the SHA256 hash of `JRTools.dll` was `e422bf2cc1dec97c132edb7345f180dd0c6faccd34ad62a874fe6420a5da16a9` [VT](https://www.virustotal.com/gui/file/e422bf2cc1dec97c132edb7345f180dd0c6faccd34ad62a874fe6420a5da16a9).

Standard execution post-installation shows the DLL being loaded from the correct location:

![Standard execution](/static/jriver/JRTools1.png)

Running it again here with `JRService.exe` and `JRTools.dll` on the Desktop, note that the legitimate DLL is still loaded in from the installation directory in `Program Files`:

![Still trying to load in the original DLL](/static/jriver/JRTools2.png)

## Sideloading

However, when an attacker brings their own `JRService.exe` and `JRTools.dll`, and the application is _not_ installed (this application is unlikely to be installed in corporate environments), the application will be vulnerable to a sideload of `JRTools.dll` from the current working directory. Note below the empty directory, and the sucessful `Load Image` from `C:\Users\bfake\Desktop\JRTools.dll`. `JRService.exe` does not use strict/safe DLL Search Mode or DLL redirection to ensure it only loads signed binaries from protected paths.

![Loading in the DLL from current directory](/static/jriver/JRTools3.png)

When creating a POC DLL, I proxied the DLL's two exports using the `Spartacus` tool from Accenture, found [here on GitHub](https://github.com/sadreck/Spartacus) to pop a MessageBox, this can obviously be abused for more nefarious purposes.

![Creating a POC](/static/jriver/JRTools4.png)

Final POC demonstrating the DLL being executed and the MessageBox being popped:

![POC demonstration and execution](/static/jriver/JRTools5.png)

## Detection

```
title: DLL Sideloading of JRTools via JRService
id: 7fe85fb0-ea8a-4c5a-9783-f70633c89197
status: experimental
description: Detects the loading of JRTools.dll by JRService.exe from a non-standard directory, suggesting potential DLL sideloading or "Bring Your Own Vulnerable Binary" (BYOVB) activity.
references:
    - https://ventdrop.github.io/posts/jriver/
    - https://hijacklibs.net/
author: Rick Gatenby
date: 2026/02/03
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\JRService.exe'
        ImageLoaded|endswith: '\JRTools.dll'
    filter:
        ImageLoaded|contains: 
            - ':\Program Files\J River\'
            - ':\Program Files (x86)\J River\'
    condition: selection and not filter
falsepositives:
    - Administrative troubleshooting where the binary was copied to a temp folder.
level: high
```

## MITRE

Tactic: Persistence / Privilege Escalation / Defense Evasion
Technique: T1574.002 - Hijack Execution Flow: DLL Side-Loading



