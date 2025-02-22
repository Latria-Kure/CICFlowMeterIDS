# CICFlowMeter-IDS2017-Compatible

[English](README.md) | [中文](README_zh.md)

## 概述
本项目是 CICFlowMeter 的修改版本，修复了关键bug的同时保持与CICIDS2017数据集的兼容性。

### 背景
CICFlowMeter 被广泛应用于包括 CICIDS2017 在内的多个网络安全数据集。然而，早期版本存在几个重要问题：

- **标志计数错误**：所有Flag count均 ≤1，甚至出现标志=1但count=0的情况
- **TCP载荷计算错误**：错误地将以太网帧padding计入tcp payload.
- **bulk检测问题**：所有带payload的packet都被记为backward bulk，导致所有forward bulk相关的特征均为0，backward bulk特征的值也都是错误的。

### 项目目标
虽然最新版本的 CICFlowMeter 已修复这些问题，但由于流量测量方法改变了，这导致相同的 pcap 文件会产生不同数量的FLow（如 CICIDS2017 的一个数据集的 690K FLows变为 770K Flows）。

本项目旨在：
- **修复关键Bug同时保持流兼容性**：生成与CICIDS2017相同数量的流，但具有正确的特征。可以将两个数据集相匹配，从而修复IDS2017的错误特征
- **提供二进制Release**：按照README安装少量依赖后即可使用，避免从源代码build的繁琐过程，尤其是Windows上的build难倒了无数用户。
- **简化构建过程**：优化构建脚本并提供详细说明

## 快速开始

### 环境要求

#### Windows
- [JDK 1.8](https://www.oracle.com/java/technologies/downloads/#java8)
- [Npcap](https://npcap.com/) (安装时请确保选中"WinPcap API-compatible Mode"选项)
  > 注意：应使用Npcap 来替代现在已经不再维护的 WinPcap 。如果您已安装 WinPcap，请先卸载它。

#### Linux
```bash
sudo apt install libpcap-dev openjdk-8-jdk
```

### 使用方法
1. 下载并解压Release的压缩包
2. 运行应用：
```bash
cd CICFlowMeter-1.0-IDS/bin

# 图形界面模式
./CICFlowMeter    # Linux
CICFlowMeter.bat  # Windows

# 命令行模式
./cfm <输入pcap文件> <输出文件夹>     # Linux
cfm.bat <输入pcap文件> <输出文件夹>   # Windows
```
> 注：无论是GUI还是命令行模式，输入输出文件路径都不可携带中文。

## 从源码构建

### 环境要求

#### Windows
- [JDK 1.8](https://www.oracle.com/java/technologies/downloads/#java8)
- [WinPcap](https://www.winpcap.org/)
- [Maven](https://maven.apache.org/)

#### Linux
```bash
sudo apt install libpcap-dev openjdk-8-jdk maven
```

### 构建步骤

1. **安装 jnetpcap 到本地 Maven 仓库**
```bash
# 在项目根目录下：

# Linux (需要 sudo):
mvn "install:install-file" "-Dfile=jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar" "-DgroupId=org.jnetpcap" "-DartifactId=jnetpcap" "-Dversion=1.4.1" "-Dpackaging=jar"

# Windows:
mvn "install:install-file" "-Dfile=jnetpcap/win/jnetpcap-1.4.r1425/jnetpcap.jar" "-DgroupId=org.jnetpcap" "-DartifactId=jnetpcap" "-Dversion=1.4.1" "-Dpackaging=jar"
```

2. **构建发布包**
```bash
# Windows
gradlew distZip

# Linux
./gradlew distZip
```

3. **直接运行（可选）**
```bash
# 首先，设置本地库：

# Windows: 选择以下任一方式
# - 复制 jnetpcap.dll 和 jnetpcap-pcap100.dll （从 jnetpcap/win/jnetpcap-1.4.r1425/）到 C:\Windows\System32
# - 或将 jnetpcap/win/jnetpcap-1.4.r1425 添加到 PATH

# Linux:
sudo cp jnetpcap/linux/jnetpcap-1.4.r1425/libjnetpcap.so /usr/lib/
sudo cp jnetpcap/linux/jnetpcap-1.4.r1425/libjnetpcap-pcap100.so /usr/lib/

# 然后运行：
gradlew execute    # Windows
./gradlew execute # Linux
```

### build时的网络问题
#### maven安装依赖速度过慢问题
在maven配置文件中配置镜像源或者使用代理.
```xml
<!-- C:\Users\用户名\.m2\ -->
<mirrors>
    <mirror>
        <id>alimaven</id>
        <name>aliyun maven</name>
        <url>http://maven.aliyun.com/nexus/content/groups/public/</url>
        <mirrorOf>central</mirrorOf>
    </mirror>
</mirrors>
<!-- use 10.0.2.2:7890 as http and https proxy  -->
<settings>
    <proxies>
        <proxy>
            <id>example-proxy</id>
            <active>true</active>
            <protocol>http</protocol>
            <host>10.0.2.2</host>
            <port>7890</port>
        </proxy>
    </proxies>
</settings>

```

#### Gradlew build时无法下载gradle
替换项目中gradle-wrapper的配置文件里的`distributionUrl`为镜像源
```java
// gradle/wrapper/gradle-wrapper.properties
distributionUrl=https://mirrors.huaweicloud.com/gradle/gradle-4.2-all.zip
```

## 数据匹配
### 与原始CICIDS2017数据集匹配
以下是一个Python脚本示例，演示如何将本项目生成的新数据集与原始CICIDS2017数据集中的流量进行匹配。这使得我们可以将原始数据集中的标签转移到具有正确特征的新数据集中。

```python
import pandas as pd
import numpy as np

# 注意：运行此脚本前请确保两个数据集的特征名称一致
def encode_flow_hash(row):
    return hash((row['Src IP'], row['Src Port'], row['Dst IP'], row['Dst Port'], row['Protocol'],row['Flow Duration'],row['Total Fwd Packet'],row['Total Bwd packets']))

# 原始IDS2017数据集
old_data = pd.read_csv("data/output_csv_files/old.csv",)
# 使用相同pcap文件由本项目生成的数据集
new_data = pd.read_csv("data/output_csv_files/new.csv",)

old_data['Flow Hash'] = old_data.apply(encode_flow_hash, axis=1)
new_data['Flow Hash'] = new_data.apply(encode_flow_hash, axis=1)

old_hash_label ={}

# 注意：虽然Flow hash不能保证唯一性，
# 但具有相同hash的flow通常具有相同的label。
# 在极少数哈希冲突导致label不同的情况下，
# 需要用户根据需求自行处理
for idx, row in old_data.iterrows():
    old_hash_label[row['Flow Hash']] = row['Label']

new_data['Label'] = new_data['Flow Hash'].map(old_hash_label)
```