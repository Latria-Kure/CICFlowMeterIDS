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
- [WinPcap](https://www.winpcap.org/)

#### Linux
```bash
sudo apt install libpcap-dev openjdk-8-jdk
```

### Usage
1. Download and extract the release package
2. Run the application:
```bash
cd CICFlowMeter-IDS2017-Compatible-1.0/bin

# GUI Mode
./CICFlowMeter    # Linux
CICFlowMeter.bat  # Windows

# Command Line Mode
./cfm <input-pcap-file> <output-folder>     # Linux
cfm.bat <input-pcap-file> <output-folder>   # Windows
```

## Building from Source

### Prerequisites

#### Windows
- [JDK 1.8](https://www.oracle.com/java/technologies/downloads/#java8)
- [WinPcap](https://www.winpcap.org/)
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



