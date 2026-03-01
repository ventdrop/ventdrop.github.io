---
title: "GachiLoader pt. 3 - Smart Contract C2"
date: 2026-03-01T10:25:16+11:00
tags: ['reverse_engineering', 'DFIR', 'threat_hunting']
draft: false
---

## Intro

Today we're looking at an entirely different Rhadamanthys sample to pt1 and pt2 but with similarities. The payload is still an infostealer, however some different techniques have been applied. This isn't going to be a complete teardown, just some notable differences primarily in the way the malware retrieves the C2. The methods for acquiring the final injected payload executable were mostly identical to the previous sample, leaning on CheckPoint's tracer.js[^1] and some custom scripts.

## Malware Chain

Our new sample loosely has the following chain: 

```text
===============================================================================

  GitHub repo (FPS Booster for all games)
  |
  +-> "Download official release" button
      |
      +-> .zip download (HTML smuggled via linked site)
          |
          +-> Unzip -> Latest_Software.v4.0.0.exe (69MB)
              |
              +-> Node SEA JavaScript payload
                  |
                  +-> Final executable injected via "Vectored Overloading"
                      |
                      +-> C2 retrieved from Polygon blockchain smart contract

===============================================================================
```

The sample was downloaded from the following Github repo:

![caption](/static/gachiloader3/github.png)

Looking at the contents of the repo (emojis, layout) and inspecting some of the URL location placeholders (yourusername) show that this was most likely LLM generated content:

![caption](/static/gachiloader3/vibecoded.png)

The actual release had no malware within it, however clicking the 'Download Official Release' button led us to the malware download URL of fullsofts[.]org:

![caption](/static/gachiloader3/downloadurl.png)

![caption](/static/gachiloader3/contents.png)


## What's Different?

A few things that changed from the previous sample:
- Github lure and HTML smuggling rather than MediaFire download
- Control flow flattening
- Node SEA embedded rather than BYO node and JS file
- C2 retrieval via Blockchain (Polygon, compatible with Ethereum)

Control flow flattening in Ida:

![caption](/static/gachiloader3/cff.png)

Extracting the Node SEA content (JavaScript payload):

![caption](/static/gachiloader3/nodeSEA.png)

## C2 Retrieval

The previous sample retrieved a hex value from two telegra[.]ph pages and decrypted them to resolve the C2, whereas this sample retrieves the C2 address from a smart contract. You could forgive me for thinking this C2 retrieval technique could be labelled "EtherHiding"; I think this is very similar, but instead of retrieving a stored malicious payload, it's retrieving the C2 address. 

The malware will send a read-only `eth_call` to one of six Polygon RPC endpoints via JSON-RPC:

```text
    poly.api.pocket.network
    polygon.drpc.org
    polygon-public.nodies.app
    1rpc.io/matic
    polygon-bor-rpc.publicnode.com
    polygon-rpc.com
```

That specific request looks like this:

```json
    POST / HTTP/1.1
    Content-Type: application/json

    {
      "jsonrpc": "2.0",
      "method":  "eth_call",
      "params":  [{"to": "0xb97b1A017feAf337bB70241F1571720f1eaEa5d1"}, "latest"],
      "id":      1
    }
```

The response is then extracted, hex decoded, and decrypted. We can achieve this using the following values:

```text
    Algorithm : AES-256-CBC
    Key       : 86dc073a1cbda36f85f45b1bd4ff247e2159790bc7a3568cc5dec23cdfbba1cd
    IV        : 0x00 * 16
    Ciphertext: 2fa31ce0f685cdddc2c80a238f75a0bac54867fa27cab73da3d4ed1c06da0993
                077840b3e8f075f1d5569480351535b3
```

![caption](/static/gachiloader3/contract.png)

Once decrypted, we get the following C2: 

```text
    deceptqower.onfinality[.]pro:443
```

Manually decrypting the encrypted strings within the binary gives us the C2 URI and also shows a bunch of well-known Rhadamanthys strings that show this to be an infostealer:

```text
POST /adb8a56294dadf33644cb54a090cb9f6/folgk.bvqd
```

![caption](/static/gachiloader3/strings.png)

The blockchain is purely a resilient dead drop for the C2 address. All actual data movement goes through traditional HTTPS to the resolved C2. Note that this domain currently has no active DNS at time of writing, however the TA can rotate the C2 infrastructure for this sample effectively instantly by updating the smart contract. 

## Why this technique?

This C2 retrieval technique is functionally very similar to Group-IB research on Deadlock ransomware[^2], however the stolen data is sent to the C2. 

Why is this method effective? I think it is put best here by Global Security Mag[^3]:

> By using the blockchain in this way, the attackers gain two key advantages: their infrastructure becomes virtually impossible to take down due to the blockchain’s immutable nature, and the decentralized architecture makes it extremely difficult to block these communications.

## Indicators

```text
Git_Latest_Software.v4.0.0.zip: e46f9f123d9dbecd82ac310d818fccdb0318e24810e9c76b4b4de8339880e0e3
Latest_Software.v4.0.0.exe: 7f1917b261182a2eefe53083a4cd39b696cdc319928e00afbe36b4320fb20189
Download URL: fullsofts[.]org
C2 Domain: deceptqower.onfinality[.]pro
C2 URL: hxxps[:]//deceptqower.onfinality[.]pro/adb8a56294dadf33644cb54a090cb9f6/folgk.bvqd
Final payload (extracted): 2ac0499e2691f9ddba7cee22cf6e528bcfad622489a137b4b29acb5fd9fdcf1f
```

## References 

[^1]: https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/

[^2]: https://www.group-ib.com/blog/deadlock-ransomware-polygon-smart-contracts/

[^3]: https://www.globalsecuritymag.fr/supply-chain-attack-using-ethereum-smart-contracts-to-distribute-multi-platform.html


RG