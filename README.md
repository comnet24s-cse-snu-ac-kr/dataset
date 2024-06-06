# DNS tunnel packet capture (pcap) dataset

- This repository contains:
  - PCAP files captured from various DNS tunneling tools and benign situation
  - Snort 3 community rules
  - PCAP-to-JSON (which will be input-compatible w/ [ztmb](https://github.com/comnet24s-cse-snu-ac-kr/go-ztmb-wo-zkp)) converter

## Dataset and pre-built binary

- Dataset and pre-built converter binary (`ztmb-conv-json-*`) are saved in [/build](./build) directory.

## PCAP-to-JSON converter development guide

- Install dependencies:

```bash
make deps
```

- Build:

```bash
make
```

- Convert and compress (to `.tar.gz`, [ztmb](https://github.com/comnet24s-cse-snu-ac-kr/go-ztmb-wo-zkp) required.)

```bash
make ztmb
```
