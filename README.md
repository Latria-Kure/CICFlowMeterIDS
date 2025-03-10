# CICFlowMeter-IDS2017-Compatible

[English](README.md) | [中文](README_zh.md)

## Overview
This project is a modified version of CICFlowMeter that maintains compatibility with the CICIDS2017 dataset while fixing critical bugs.

### Background
CICFlowMeter has been widely used in many cybersecurity datasets, including CICIDS2017. However, older versions had several significant issues:

- **Incorrect Flag Counting**: All flag counts were ≤1, with cases where flag=1 but flag count=0
- **TCP Payload Calculation Error**: Ethernet frame padding was incorrectly included in payload calculations
- **Bulk Transfer Detection Issue**: All packets with payload were treated as backward bulk, resulting in zero forward bulk features

### Project Goals
While these issues have been fixed in the latest CICFlowMeter, the new version introduced breaking changes in flow measurement by considering RST flags. This results in different flow counts (e.g., 770K vs 690K flows for the same CICIDS2017 pcap).

This project aims to:
- **Fix Critical Bugs While Maintaining Flow Compatibility**: Generate the same number of flows as CICIDS2017 but with correct features. User can match two datasets to use the existing label and correct features.
- **Provide Ready-to-Use Binaries**: Especially beneficial for Windows users
- **Simplify Build Process**: Optimized build scripts and detailed instructions

## Quick Start

### Prerequisites

#### Windows
- [JDK 1.8](https://www.oracle.com/java/technologies/downloads/#java8)
- [Npcap](https://npcap.com/) (Make sure to select "WinPcap API-compatible Mode" during installation)
  > Note: Npcap replaces the older WinPcap. If you have WinPcap installed, please uninstall it first.

#### Linux
```bash
sudo apt install libpcap-dev openjdk-8-jdk
```

### Usage
1. Download and extract the release package
2. Run the application:
```bash
cd CICFlowMeter-1.0-IDS/bin

# GUI Mode
./CICFlowMeter    # Linux
CICFlowMeter.bat  # Windows

# Command Line Mode
./cfm <input-pcap-file> <output-folder>     # Linux
cfm.bat <input-pcap-file> <output-folder>   # Windows

# Command Line Mode with packet tracking (outputs packet numbers to <flow-id>.json files for every flow)
./cfm <input-pcap-file> <output-folder> --savepacketinfo     # Linux
cfm.bat <input-pcap-file> <output-folder> --savepacketinfo   # Windows
```

## Building from Source

### Prerequisites

#### Windows
- [JDK 1.8](https://www.oracle.com/java/technologies/downloads/#java8)
- [Npcap](https://npcap.com/) (Make sure to select "WinPcap API-compatible Mode" during installation)
  > Note: Npcap replaces the older WinPcap. If you have WinPcap installed, please uninstall it first.
- [Maven](https://maven.apache.org/)

#### Linux
```bash
sudo apt install libpcap-dev openjdk-8-jdk maven
```

### Build Steps

1. **Install jnetpcap to Local Maven Repository**
```bash
# At project root directory:

# Linux (requires sudo):
mvn "install:install-file" "-Dfile=jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar" "-DgroupId=org.jnetpcap" "-DartifactId=jnetpcap" "-Dversion=1.4.1" "-Dpackaging=jar"

# Windows:
mvn "install:install-file" "-Dfile=jnetpcap/win/jnetpcap-1.4.r1425/jnetpcap.jar" "-DgroupId=org.jnetpcap" "-DartifactId=jnetpcap" "-Dversion=1.4.1" "-Dpackaging=jar"
```

2. **Build Distribution Package**
```bash
# Windows
gradlew distZip

# Linux
./gradlew distZip
```

3. **Run Directly (Optional)**
```bash
# First, set up native libraries:

# Windows: Either
# - Copy jnetpcap.dll and jnetpcap-pcap100.dll from jnetpcap/win/jnetpcap-1.4.r1425/ to C:\Windows\System32
# - Or add jnetpcap/win/jnetpcap-1.4.r1425 to PATH

# Linux:
sudo cp jnetpcap/linux/jnetpcap-1.4.r1425/libjnetpcap.so /usr/lib/
sudo cp jnetpcap/linux/jnetpcap-1.4.r1425/libjnetpcap-pcap100.so /usr/lib/

# Then run:
gradlew execute    # Windows
./gradlew execute # Linux
```

## Data Matching with Original CICIDS2017
Here's a Python script example that demonstrates how to match flows between the original CICIDS2017 dataset and the new dataset generated by this project. This allows you to transfer labels from the original dataset to the new one with corrected features.

```python
import pandas as pd
import numpy as np

# Note: Ensure feature names are consistent between datasets before running this script
def encode_flow_hash(row):
    return hash((row['Src IP'], row['Src Port'], row['Dst IP'], row['Dst Port'], row['Protocol'],row['Flow Duration'],row['Total Fwd Packet'],row['Total Bwd packets']))

# The original IDS2017 dataset
old_data = pd.read_csv("data/output_csv_files/old.csv",)
# The dataset generated by this project using the same pcap file
new_data = pd.read_csv("data/output_csv_files/new.csv",)

old_data['Flow Hash'] = old_data.apply(encode_flow_hash, axis=1)
new_data['Flow Hash'] = new_data.apply(encode_flow_hash, axis=1)

old_hash_label ={}

# Note: While flow hashes are not guaranteed to be unique,
# flows with the same hash typically share the same label.
# In rare cases where hash collisions result in different labels,
# additional matching criteria may be needed.
for idx, row in old_data.iterrows():
    old_hash_label[row['Flow Hash']] = row['Label']

new_data['Label'] = new_data['Flow Hash'].map(old_hash_label)
```

### JSON Packet Tracking Format

When using the `--save-packet-info` option, the tool will generate JSON files that map each flow to the packet numbers in the original PCAP file. The JSON format looks like:

```json
{
    "1": [1, 3, 7, 9],
    "2": [2, 4, 6, 8],
    "3": [5]
}
```

This indicates that there are three flows with the same flow ID:
- Flow 1 consists of packets 1, 3, 7, and 9
- Flow 2 consists of packets 2, 4, 6, and 8
- Flow 3 consists of packet 5

These packet numbers are 1-based (they start from 1) and correspond to the packet positions in the original PCAP file. This feature is useful for:
- Tracing which packets contributed to a specific flow
- Extracting packets from specific flows for deeper analysis
- Validating flow generation and feature extraction




