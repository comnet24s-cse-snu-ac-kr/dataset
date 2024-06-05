# DNS tunnel packet capture (pcap) dataset

- This repository contains:
  - PCAP files captured w/ various DNS tunneling tools and benign situation
  - Snort 3 community rules
  - PCAP-to-JSON converter

## Dataset and pre-built binary

- Dataset and pre-built converter binary (`ztmb-conv-json`) are saved in [/build](./build) directory.

## PCAP-to-JSON converter development guide

- Install dependencies:

```bash
make deps
```

- Build:

```bash
make
```

- Convert and compress (to `.tar.gz`)

```bash
make pack
```
