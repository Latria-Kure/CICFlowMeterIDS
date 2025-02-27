package cic.cs.unb.ca.jnetpcap;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.jnetpcap.packet.format.FormatUtils;

public class BasicFlow {

    private final static String separator = ",";
    private SummaryStatistics fwdPktStats = null;
    private SummaryStatistics bwdPktStats = null;
    private List<BasicPacketInfo> forward = null;
    private List<BasicPacketInfo> backward = null;
    private List<Long> packetSerialNumbers = null;

    private long forwardBytes;
    private long backwardBytes;
    private long fHeaderBytes;
    private long bHeaderBytes;

    private boolean isBidirectional;

    private HashMap<String, MutableInt> flagCounts;

    private int fPSH_cnt;
    private int bPSH_cnt;
    private int fURG_cnt;
    private int bURG_cnt;

    private long Act_data_pkt_forward;
    private long min_seg_size_forward;
    private int Init_Win_bytes_forward = -1;
    private int Init_Win_bytes_backward = -1;

    private byte[] src;
    private byte[] dst;
    private int srcPort;
    private int dstPort;
    private int protocol;
    private long flowStartTime;
    private long startActiveTime;
    private long endActiveTime;
    private String flowId = null;

    private SummaryStatistics flowIAT = null;
    private SummaryStatistics forwardIAT = null;
    private SummaryStatistics backwardIAT = null;
    private SummaryStatistics flowLengthStats = null;
    private SummaryStatistics flowActive = null;
    private SummaryStatistics flowIdle = null;

    private long flowLastSeen;
    private long forwardLastSeen;
    private long backwardLastSeen;
    private long activityTimeout;

    public BasicFlow(boolean isBidirectional, BasicPacketInfo packet, byte[] flowSrc, byte[] flowDst, int flowSrcPort,
            int flowDstPort, long activityTimeout) {
        super();
        this.activityTimeout = activityTimeout;
        this.initParameters();
        this.isBidirectional = isBidirectional;
        this.firstPacket(packet);
        this.src = flowSrc;
        this.dst = flowDst;
        this.srcPort = flowSrcPort;
        this.dstPort = flowDstPort;
    }

    public BasicFlow(boolean isBidirectional, BasicPacketInfo packet, long activityTimeout) {
        super();
        this.activityTimeout = activityTimeout;
        this.initParameters();
        this.isBidirectional = isBidirectional;
        this.firstPacket(packet);
    }

    public BasicFlow(BasicPacketInfo packet, long activityTimeout) {
        super();
        this.activityTimeout = activityTimeout;
        this.initParameters();
        this.isBidirectional = true;
        firstPacket(packet);
    }

    public void initParameters() {
        this.forward = new ArrayList<BasicPacketInfo>();
        this.backward = new ArrayList<BasicPacketInfo>();
        this.packetSerialNumbers = new ArrayList<Long>();
        this.flowIAT = new SummaryStatistics();
        this.forwardIAT = new SummaryStatistics();
        this.backwardIAT = new SummaryStatistics();
        this.flowActive = new SummaryStatistics();
        this.flowIdle = new SummaryStatistics();
        this.flowLengthStats = new SummaryStatistics();
        this.fwdPktStats = new SummaryStatistics();
        this.bwdPktStats = new SummaryStatistics();
        this.flagCounts = new HashMap<String, MutableInt>();
        initFlags();
        this.forwardBytes = 0L;
        this.backwardBytes = 0L;
        this.startActiveTime = 0L;
        this.endActiveTime = 0L;
        this.src = null;
        this.dst = null;
        this.fPSH_cnt = 0;
        this.bPSH_cnt = 0;
        this.fURG_cnt = 0;
        this.bURG_cnt = 0;
        this.fHeaderBytes = 0L;
        this.bHeaderBytes = 0L;

    }

    public void firstPacket(BasicPacketInfo packet) {
        updateFlowBulk(packet);
        detectUpdateSubflows(packet);
        checkFlags(packet);
        this.flowStartTime = packet.getTimeStamp();
        this.flowLastSeen = packet.getTimeStamp();
        this.startActiveTime = packet.getTimeStamp();
        this.endActiveTime = packet.getTimeStamp();
        this.flowLengthStats.addValue((double) packet.getPayloadBytes());
        this.packetSerialNumbers.add(packet.getId());

        if (this.src == null) {
            this.src = packet.getSrc();
            this.srcPort = packet.getSrcPort();
        }
        if (this.dst == null) {
            this.dst = packet.getDst();
            this.dstPort = packet.getDstPort();
        }
        if (Arrays.equals(this.src, packet.getSrc())) {
            this.min_seg_size_forward = packet.getHeaderBytes();
            Init_Win_bytes_forward = packet.getTCPWindow();
            this.fwdPktStats.addValue((double) packet.getPayloadBytes());
            this.fHeaderBytes = packet.getHeaderBytes();
            this.forwardLastSeen = packet.getTimeStamp();
            this.forwardBytes += packet.getPayloadBytes();
            this.forward.add(packet);
            if (packet.hasFlagPSH()) {
                this.fPSH_cnt++;
            }
            if (packet.hasFlagURG()) {
                this.fURG_cnt++;
            }
        } else {
            Init_Win_bytes_backward = packet.getTCPWindow();
            this.bwdPktStats.addValue((double) packet.getPayloadBytes());
            this.bHeaderBytes = packet.getHeaderBytes();
            this.backwardLastSeen = packet.getTimeStamp();
            this.backwardBytes += packet.getPayloadBytes();
            this.backward.add(packet);
            if (packet.hasFlagPSH()) {
                this.bPSH_cnt++;
            }
            if (packet.hasFlagURG()) {
                this.bURG_cnt++;
            }
        }
        this.protocol = packet.getProtocol();
        this.flowId = packet.getFlowId();
    }

    public void addPacket(BasicPacketInfo packet) {
        updateFlowBulk(packet);
        detectUpdateSubflows(packet);
        checkFlags(packet);
        long currentTimestamp = packet.getTimeStamp();
        this.packetSerialNumbers.add(packet.getId());

        if (isBidirectional) {
            this.flowLengthStats.addValue((double) packet.getPayloadBytes());

            if (Arrays.equals(this.src, packet.getSrc())) {
                if (packet.getPayloadBytes() >= 1) {
                    this.Act_data_pkt_forward++;
                }
                this.fwdPktStats.addValue((double) packet.getPayloadBytes());
                this.fHeaderBytes += packet.getHeaderBytes();
                this.forward.add(packet);
                this.forwardBytes += packet.getPayloadBytes();
                if (this.forward.size() > 1)
                    this.forwardIAT.addValue(currentTimestamp - this.forwardLastSeen);
                this.forwardLastSeen = currentTimestamp;
                this.min_seg_size_forward = Math.min(packet.getHeaderBytes(), this.min_seg_size_forward);

            } else {
                this.bwdPktStats.addValue((double) packet.getPayloadBytes());
                if (Init_Win_bytes_backward == -1) {
                    Init_Win_bytes_backward = packet.getTCPWindow();
                }
                this.bHeaderBytes += packet.getHeaderBytes();
                this.backward.add(packet);
                this.backwardBytes += packet.getPayloadBytes();
                if (this.backward.size() > 1)
                    this.backwardIAT.addValue(currentTimestamp - this.backwardLastSeen);
                this.backwardLastSeen = currentTimestamp;
            }
        } else {
            if (packet.getPayloadBytes() >= 1) {
                this.Act_data_pkt_forward++;
            }
            this.fwdPktStats.addValue((double) packet.getPayloadBytes());
            this.flowLengthStats.addValue((double) packet.getPayloadBytes());
            this.fHeaderBytes += packet.getHeaderBytes();
            this.forward.add(packet);
            this.forwardBytes += packet.getPayloadBytes();
            this.forwardIAT.addValue(currentTimestamp - this.forwardLastSeen);
            this.forwardLastSeen = currentTimestamp;
            this.min_seg_size_forward = Math.min(packet.getHeaderBytes(), this.min_seg_size_forward);
        }

        this.flowIAT.addValue(packet.getTimeStamp() - this.flowLastSeen);
        this.flowLastSeen = packet.getTimeStamp();

    }

    public double getfPktsPerSecond() {
        long duration = this.flowLastSeen - this.flowStartTime;
        if (duration > 0) {
            return (double) this.forward.size() / ((double) duration / 1000000L);
        } else
            return 0;
    }

    public double getbPktsPerSecond() {
        long duration = this.flowLastSeen - this.flowStartTime;
        if (duration > 0) {
            return (double) this.backward.size() / ((double) duration / 1000000L);
        } else
            return 0;
    }

    public double getDownUpRatio() {
        if (this.forward.size() > 0) {
            return (double) this.backward.size() / (double) this.forward.size();
        }
        return 0;
    }

    public double getAvgPacketSize() {
        if (this.packetCount() > 0) {
            return (double) this.flowLengthStats.getSum() / (double) this.packetCount();
        }
        return 0;
    }

    public double fAvgSegmentSize() {
        if (this.forward.size() != 0)
            return (double) this.fwdPktStats.getSum() / (double) this.forward.size();
        return 0;
    }

    public double bAvgSegmentSize() {
        if (this.backward.size() != 0)
            return (double) this.bwdPktStats.getSum() / (double) this.backward.size();
        return 0;
    }

    public void initFlags() {
        flagCounts.put("FIN", new MutableInt());
        flagCounts.put("SYN", new MutableInt());
        flagCounts.put("RST", new MutableInt());
        flagCounts.put("PSH", new MutableInt());
        flagCounts.put("ACK", new MutableInt());
        flagCounts.put("URG", new MutableInt());
        flagCounts.put("CWR", new MutableInt());
        flagCounts.put("ECE", new MutableInt());
    }

    public void checkFlags(BasicPacketInfo packet) {
        if (packet.hasFlagFIN()) {
            flagCounts.get("FIN").increment();
        }
        if (packet.hasFlagSYN()) {
            flagCounts.get("SYN").increment();
        }
        if (packet.hasFlagRST()) {
            flagCounts.get("RST").increment();
        }
        if (packet.hasFlagPSH()) {
            flagCounts.get("PSH").increment();
        }
        if (packet.hasFlagACK()) {
            flagCounts.get("ACK").increment();
        }
        if (packet.hasFlagURG()) {
            flagCounts.get("URG").increment();
        }
        if (packet.hasFlagCWR()) {
            flagCounts.get("CWR").increment();
        }
        if (packet.hasFlagECE()) {
            flagCounts.get("ECE").increment();
        }
    }

    public long getSflow_fbytes() {
        if (sfCount <= 0)
            return 0;
        return this.forwardBytes / sfCount;
    }

    public long getSflow_fpackets() {
        if (sfCount <= 0)
            return 0;
        return this.forward.size() / sfCount;
    }

    public long getSflow_bbytes() {
        if (sfCount <= 0)
            return 0;
        return this.backwardBytes / sfCount;
    }

    public long getSflow_bpackets() {
        if (sfCount <= 0)
            return 0;
        return this.backward.size() / sfCount;
    }

    private long sfLastPacketTS = -1;
    private int sfCount = 0;
    private long sfAcHelper = -1;

    void detectUpdateSubflows(BasicPacketInfo packet) {
        if (sfLastPacketTS == -1) {
            sfLastPacketTS = packet.getTimeStamp();
            sfAcHelper = packet.getTimeStamp();
        }
        if (((packet.getTimeStamp() - sfLastPacketTS) / (double) 1000000) > 1.0) {
            sfCount++;
            long lastSFduration = packet.getTimeStamp() - sfAcHelper;
            updateActiveIdleTime(packet.getTimeStamp(), this.activityTimeout);
            sfAcHelper = packet.getTimeStamp();
        }

        sfLastPacketTS = packet.getTimeStamp();
    }

    //////////////////////////////
    private long fbulkDuration = 0;
    private long fbulkPacketCount = 0;
    private long fbulkSizeTotal = 0;
    private long fbulkStateCount = 0;
    private long fbulkPacketCountHelper = 0;
    private long fbulkStartHelper = 0;
    private long fbulkSizeHelper = 0;
    private long flastBulkTS = 0;
    private long bbulkDuration = 0;
    private long bbulkPacketCount = 0;
    private long bbulkSizeTotal = 0;
    private long bbulkStateCount = 0;
    private long bbulkPacketCountHelper = 0;
    private long bbulkStartHelper = 0;
    private long bbulkSizeHelper = 0;
    private long blastBulkTS = 0;

    public void updateFlowBulk(BasicPacketInfo packet) {

        if (Arrays.equals(this.src, packet.getSrc())) {
            updateForwardBulk(packet, blastBulkTS);
        } else {
            updateBackwardBulk(packet, flastBulkTS);
        }

    }

    public void updateForwardBulk(BasicPacketInfo packet, long tsOflastBulkInOther) {

        long size = packet.getPayloadBytes();
        if (tsOflastBulkInOther > fbulkStartHelper)
            fbulkStartHelper = 0;
        if (size <= 0)
            return;

        packet.getPayloadPacket();

        if (fbulkStartHelper == 0) {
            fbulkStartHelper = packet.getTimeStamp();
            fbulkPacketCountHelper = 1;
            fbulkSizeHelper = size;
            flastBulkTS = packet.getTimeStamp();
        } else {
            if (((packet.getTimeStamp() - flastBulkTS) / (double) 1000000) > 1.0) {
                fbulkStartHelper = packet.getTimeStamp();
                flastBulkTS = packet.getTimeStamp();
                fbulkPacketCountHelper = 1;
                fbulkSizeHelper = size;
            } else {
                fbulkPacketCountHelper += 1;
                fbulkSizeHelper += size;
                if (fbulkPacketCountHelper == 4) {
                    fbulkStateCount += 1;
                    fbulkPacketCount += fbulkPacketCountHelper;
                    fbulkSizeTotal += fbulkSizeHelper;
                    fbulkDuration += packet.getTimeStamp() - fbulkStartHelper;
                } else if (fbulkPacketCountHelper > 4) {
                    fbulkPacketCount += 1;
                    fbulkSizeTotal += size;
                    fbulkDuration += packet.getTimeStamp() - flastBulkTS;
                }
                flastBulkTS = packet.getTimeStamp();
            }
        }
    }

    public void updateBackwardBulk(BasicPacketInfo packet, long tsOflastBulkInOther) {
        long size = packet.getPayloadBytes();
        if (tsOflastBulkInOther > bbulkStartHelper)
            bbulkStartHelper = 0;
        if (size <= 0)
            return;

        packet.getPayloadPacket();

        if (bbulkStartHelper == 0) {
            bbulkStartHelper = packet.getTimeStamp();
            bbulkPacketCountHelper = 1;
            bbulkSizeHelper = size;
            blastBulkTS = packet.getTimeStamp();
        } else {
            if (((packet.getTimeStamp() - blastBulkTS) / (double) 1000000) > 1.0) {
                bbulkStartHelper = packet.getTimeStamp();
                blastBulkTS = packet.getTimeStamp();
                bbulkPacketCountHelper = 1;
                bbulkSizeHelper = size;
            } else {
                bbulkPacketCountHelper += 1;
                bbulkSizeHelper += size;
                if (bbulkPacketCountHelper == 4) {
                    bbulkStateCount += 1;
                    bbulkPacketCount += bbulkPacketCountHelper;
                    bbulkSizeTotal += bbulkSizeHelper;
                    bbulkDuration += packet.getTimeStamp() - bbulkStartHelper;
                } else if (bbulkPacketCountHelper > 4) {
                    bbulkPacketCount += 1;
                    bbulkSizeTotal += size;
                    bbulkDuration += packet.getTimeStamp() - blastBulkTS;
                }
                blastBulkTS = packet.getTimeStamp();
            }
        }

    }

    public long fbulkStateCount() {
        return fbulkStateCount;
    }

    public long fbulkSizeTotal() {
        return fbulkSizeTotal;
    }

    public long fbulkPacketCount() {
        return fbulkPacketCount;
    }

    public long fbulkDuration() {
        return fbulkDuration;
    }

    public double fbulkDurationInSecond() {
        return fbulkDuration / (double) 1000000;
    }

    public long fAvgBytesPerBulk() {
        if (this.fbulkStateCount() != 0)
            return (this.fbulkSizeTotal() / this.fbulkStateCount());
        return 0;
    }

    public long fAvgPacketsPerBulk() {
        if (this.fbulkStateCount() != 0)
            return (this.fbulkPacketCount() / this.fbulkStateCount());
        return 0;
    }

    public long fAvgBulkRate() {
        if (this.fbulkDuration() != 0)
            return (long) (this.fbulkSizeTotal() / this.fbulkDurationInSecond());
        return 0;
    }

    public long bbulkPacketCount() {
        return bbulkPacketCount;
    }

    public long bbulkStateCount() {
        return bbulkStateCount;
    }

    public long bbulkSizeTotal() {
        return bbulkSizeTotal;
    }

    public long bbulkDuration() {
        return bbulkDuration;
    }

    public double bbulkDurationInSecond() {
        return bbulkDuration / (double) 1000000;
    }

    public long bAvgBytesPerBulk() {
        if (this.bbulkStateCount() != 0)
            return (this.bbulkSizeTotal() / this.bbulkStateCount());
        return 0;
    }

    public long bAvgPacketsPerBulk() {
        if (this.bbulkStateCount() != 0)
            return (this.bbulkPacketCount() / this.bbulkStateCount());
        return 0;
    }

    public long bAvgBulkRate() {
        if (this.bbulkDuration() != 0)
            return (long) (this.bbulkSizeTotal() / this.bbulkDurationInSecond());
        return 0;
    }

    ////////////////////////////

    public void updateActiveIdleTime(long currentTime, long threshold) {
        if ((currentTime - this.endActiveTime) > threshold) {
            if ((this.endActiveTime - this.startActiveTime) > 0) {
                this.flowActive.addValue(this.endActiveTime - this.startActiveTime);
            }
            this.flowIdle.addValue(currentTime - this.endActiveTime);
            this.startActiveTime = currentTime;
            this.endActiveTime = currentTime;
        } else {
            this.endActiveTime = currentTime;
        }
    }

    public void endActiveIdleTime(long currentTime, long threshold, long flowTimeOut, boolean isFlagEnd) {

        if ((this.endActiveTime - this.startActiveTime) > 0) {
            this.flowActive.addValue(this.endActiveTime - this.startActiveTime);
        }

        if (!isFlagEnd && ((flowTimeOut - (this.endActiveTime - this.flowStartTime)) > 0)) {
            this.flowIdle.addValue(flowTimeOut - (this.endActiveTime - this.flowStartTime));
        }
    }

    public String dumpFlowBasedFeatures() {
        String dump = "";
        dump += this.flowId + ",";
        dump += FormatUtils.ip(src) + ",";
        dump += getSrcPort() + ",";
        dump += FormatUtils.ip(dst) + ",";
        dump += getDstPort() + ",";
        dump += getProtocol() + ",";
        dump += DateFormatter.parseDateFromLong(this.flowStartTime / 1000L, "dd/MM/yyyy hh:mm:ss") + ",";
        long flowDuration = this.flowLastSeen - this.flowStartTime;
        dump += flowDuration + ",";
        dump += this.fwdPktStats.getN() + ",";
        dump += this.bwdPktStats.getN() + ",";
        dump += this.fwdPktStats.getSum() + ",";
        dump += this.bwdPktStats.getSum() + ",";
        if (fwdPktStats.getN() > 0L) {
            dump += this.fwdPktStats.getMax() + ",";
            dump += this.fwdPktStats.getMin() + ",";
            dump += this.fwdPktStats.getMean() + ",";
            dump += this.fwdPktStats.getStandardDeviation() + ",";
        } else {
            dump += "0,0,0,0,";
        }
        if (bwdPktStats.getN() > 0L) {
            dump += this.bwdPktStats.getMax() + ",";
            dump += this.bwdPktStats.getMin() + ",";
            dump += this.bwdPktStats.getMean() + ",";
            dump += this.bwdPktStats.getStandardDeviation() + ",";
        } else {
            dump += "0,0,0,0,";
        }
        dump += ((double) (this.forwardBytes + this.backwardBytes)) / ((double) flowDuration / 1000000L) + ",";
        dump += ((double) packetCount()) / ((double) flowDuration / 1000000L) + ",";
        dump += this.flowIAT.getMean() + ",";
        dump += this.flowIAT.getStandardDeviation() + ",";
        dump += this.flowIAT.getMax() + ",";
        dump += this.flowIAT.getMin() + ",";
        if (this.forward.size() > 1) {
            dump += this.forwardIAT.getSum() + ",";
            dump += this.forwardIAT.getMean() + ",";
            dump += this.forwardIAT.getStandardDeviation() + ",";
            dump += this.forwardIAT.getMax() + ",";
            dump += this.forwardIAT.getMin() + ",";
        } else {
            dump += "0,0,0,0,0,";
        }
        if (this.backward.size() > 1) {
            dump += this.backwardIAT.getSum() + ",";
            dump += this.backwardIAT.getMean() + ",";
            dump += this.backwardIAT.getStandardDeviation() + ",";
            dump += this.backwardIAT.getMax() + ",";
            dump += this.backwardIAT.getMin() + ",";
        } else {
            dump += "0,0,0,0,0,";
        }

        dump += this.fPSH_cnt + ",";
        dump += this.bPSH_cnt + ",";
        dump += this.fURG_cnt + ",";
        dump += this.bURG_cnt + ",";

        dump += this.fHeaderBytes + ",";
        dump += this.bHeaderBytes + ",";
        dump += getfPktsPerSecond() + ",";
        dump += getbPktsPerSecond() + ",";

        if (this.forward.size() > 0 || this.backward.size() > 0) {
            dump += this.flowLengthStats.getMin() + ",";
            dump += this.flowLengthStats.getMax() + ",";
            dump += this.flowLengthStats.getMean() + ",";
            dump += this.flowLengthStats.getStandardDeviation() + ",";
            dump += flowLengthStats.getVariance() + ",";
        } else {
            dump += "0,0,0,0,";
        }

        for (String key : flagCounts.keySet()) {
            dump += flagCounts.get(key).value + ",";
        }

        dump += getDownUpRatio() + ",";
        dump += getAvgPacketSize() + ",";
        dump += fAvgSegmentSize() + ",";
        dump += bAvgSegmentSize() + ",";
        dump += this.fHeaderBytes + ",";

        dump += fAvgBytesPerBulk() + ",";
        dump += fAvgPacketsPerBulk() + ",";
        dump += fAvgBulkRate() + ",";
        dump += bAvgBytesPerBulk() + ",";
        dump += bAvgPacketsPerBulk() + ",";
        dump += bAvgBulkRate() + ",";

        dump += getSflow_fpackets() + ",";
        dump += getSflow_fbytes() + ",";
        dump += getSflow_bpackets() + ",";
        dump += getSflow_bbytes() + ",";

        dump += this.Init_Win_bytes_forward + ",";
        dump += this.Init_Win_bytes_backward + ",";
        dump += this.Act_data_pkt_forward + ",";
        dump += this.min_seg_size_forward + ",";

        if (this.flowActive.getN() > 0) {
            dump += this.flowActive.getMean() + ",";
            dump += this.flowActive.getStandardDeviation() + ",";
            dump += this.flowActive.getMax() + ",";
            dump += this.flowActive.getMin() + ",";
        } else {
            dump += "0,0,0,0,";
        }

        if (this.flowIdle.getN() > 0) {
            dump += this.flowIdle.getMean() + ",";
            dump += this.flowIdle.getStandardDeviation() + ",";
            dump += this.flowIdle.getMax() + ",";
            dump += this.flowIdle.getMin();
        } else {
            dump += "0,0,0,0";
        }
        dump += "," + getLabel();

        return dump;
    }

    public int packetCount() {
        if (isBidirectional) {
            return (this.forward.size() + this.backward.size());
        } else {
            return this.forward.size();
        }
    }

    public List<BasicPacketInfo> getForward() {
        return new ArrayList<>(forward);
    }

    public void setForward(List<BasicPacketInfo> forward) {
        this.forward = forward;
    }

    public List<BasicPacketInfo> getBackward() {
        return new ArrayList<>(backward);
    }

    public void setBackward(List<BasicPacketInfo> backward) {
        this.backward = backward;
    }

    public boolean isBidirectional() {
        return isBidirectional;
    }

    public void setBidirectional(boolean isBidirectional) {
        this.isBidirectional = isBidirectional;
    }

    public byte[] getSrc() {
        return Arrays.copyOf(src, src.length);
    }

    public void setSrc(byte[] src) {
        this.src = src;
    }

    public byte[] getDst() {
        return Arrays.copyOf(dst, dst.length);
    }

    public void setDst(byte[] dst) {
        this.dst = dst;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public int getProtocol() {
        return protocol;
    }

    public String getProtocolStr() {
        switch (this.protocol) {
            case (6):
                return "TCP";
            case (17):
                return "UDP";
        }
        return "UNKNOWN";
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    public long getFlowStartTime() {
        return flowStartTime;
    }

    public void setFlowStartTime(long flowStartTime) {
        this.flowStartTime = flowStartTime;
    }

    public String getFlowId() {
        return flowId;
    }

    public void setFlowId(String flowId) {
        this.flowId = flowId;
    }

    public long getLastSeen() {
        return flowLastSeen;
    }

    public void setLastSeen(long lastSeen) {
        this.flowLastSeen = lastSeen;
    }

    public long getStartActiveTime() {
        return startActiveTime;
    }

    public void setStartActiveTime(long startActiveTime) {
        this.startActiveTime = startActiveTime;
    }

    public long getEndActiveTime() {
        return endActiveTime;
    }

    public void setEndActiveTime(long endActiveTime) {
        this.endActiveTime = endActiveTime;
    }

    public String getSrcIP() {
        return FormatUtils.ip(src);
    }

    public String getDstIP() {
        return FormatUtils.ip(dst);
    }

    public String getTimeStamp() {
        return DateFormatter.parseDateFromLong(flowStartTime / 1000L, "dd/MM/yyyy hh:mm:ss");
    }

    public long getFlowDuration() {
        return flowLastSeen - flowStartTime;
    }

    public long getTotalFwdPackets() {
        return fwdPktStats.getN();
    }

    public long getTotalBackwardPackets() {
        return bwdPktStats.getN();
    }

    public double getTotalLengthofFwdPackets() {
        return fwdPktStats.getSum();
    }

    public double getTotalLengthofBwdPackets() {
        return bwdPktStats.getSum();
    }

    public double getFwdPacketLengthMax() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getMax() : 0;
    }

    public double getFwdPacketLengthMin() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getMin() : 0;
    }

    public double getFwdPacketLengthMean() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getMean() : 0;
    }

    public double getFwdPacketLengthStd() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getStandardDeviation() : 0;
    }

    public double getBwdPacketLengthMax() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getMax() : 0;
    }

    public double getBwdPacketLengthMin() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getMin() : 0;
    }

    public double getBwdPacketLengthMean() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getMean() : 0;
    }

    public double getBwdPacketLengthStd() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getStandardDeviation() : 0;
    }

    public double getFlowBytesPerSec() {
        return ((double) (forwardBytes + backwardBytes)) / ((double) getFlowDuration() / 1000000L);
    }

    public double getFlowPacketsPerSec() {
        return ((double) packetCount()) / ((double) getFlowDuration() / 1000000L);
    }

    public SummaryStatistics getFlowIAT() {
        return flowIAT;
    }

    public double getFwdIATTotal() {
        return (forward.size() > 1) ? forwardIAT.getSum() : 0;
    }

    public double getFwdIATMean() {
        return (forward.size() > 1) ? forwardIAT.getMean() : 0;
    }

    public double getFwdIATStd() {
        return (forward.size() > 1) ? forwardIAT.getStandardDeviation() : 0;
    }

    public double getFwdIATMax() {
        return (forward.size() > 1) ? forwardIAT.getMax() : 0;
    }

    public double getFwdIATMin() {
        return (forward.size() > 1) ? forwardIAT.getMin() : 0;
    }

    public double getBwdIATTotal() {
        return (backward.size() > 1) ? backwardIAT.getSum() : 0;
    }

    public double getBwdIATMean() {
        return (backward.size() > 1) ? backwardIAT.getMean() : 0;
    }

    public double getBwdIATStd() {
        return (backward.size() > 1) ? backwardIAT.getStandardDeviation() : 0;
    }

    public double getBwdIATMax() {
        return (backward.size() > 1) ? backwardIAT.getMax() : 0;
    }

    public double getBwdIATMin() {
        return (backward.size() > 1) ? backwardIAT.getMin() : 0;
    }

    public int getFwdPSHFlags() {
        return fPSH_cnt;
    }

    public int getBwdPSHFlags() {
        return bPSH_cnt;
    }

    public int getFwdURGFlags() {
        return fURG_cnt;
    }

    public int getBwdURGFlags() {
        return bURG_cnt;
    }

    public long getFwdHeaderLength() {
        return fHeaderBytes;
    }

    public long getBwdHeaderLength() {
        return bHeaderBytes;
    }

    public double getMinPacketLength() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getMin() : 0;
    }

    public double getMaxPacketLength() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getMax() : 0;
    }

    public double getPacketLengthMean() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getMean() : 0;
    }

    public double getPacketLengthStd() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getStandardDeviation() : 0;
    }

    public double getPacketLengthVariance() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getVariance() : 0;
    }

    public int getFlagCount(String key) {
        return flagCounts.get(key).value;
    }

    public int getInit_Win_bytes_forward() {
        return Init_Win_bytes_forward;
    }

    public int getInit_Win_bytes_backward() {
        return Init_Win_bytes_backward;
    }

    public long getAct_data_pkt_forward() {
        return Act_data_pkt_forward;
    }

    public long getmin_seg_size_forward() {
        return min_seg_size_forward;
    }

    public double getActiveMean() {
        return (flowActive.getN() > 0) ? flowActive.getMean() : 0;
    }

    public double getActiveStd() {
        return (flowActive.getN() > 0) ? flowActive.getStandardDeviation() : 0;
    }

    public double getActiveMax() {
        return (flowActive.getN() > 0) ? flowActive.getMax() : 0;
    }

    public double getActiveMin() {
        return (flowActive.getN() > 0) ? flowActive.getMin() : 0;
    }

    public double getIdleMean() {
        return (flowIdle.getN() > 0) ? flowIdle.getMean() : 0;
    }

    public double getIdleStd() {
        return (flowIdle.getN() > 0) ? flowIdle.getStandardDeviation() : 0;
    }

    public double getIdleMax() {
        return (flowIdle.getN() > 0) ? flowIdle.getMax() : 0;
    }

    public double getIdleMin() {
        return (flowIdle.getN() > 0) ? flowIdle.getMin() : 0;
    }

    public String getLabel() {
        return "NeedManualLabel";
    }

    public String dumpFlowBasedFeaturesEx() {
        StringBuilder dump = new StringBuilder();

        dump.append(flowId).append(separator);
        dump.append(FormatUtils.ip(src)).append(separator);
        dump.append(getSrcPort()).append(separator);
        dump.append(FormatUtils.ip(dst)).append(separator);
        dump.append(getDstPort()).append(separator);
        dump.append(getProtocol()).append(separator);

        String starttime = DateFormatter.convertMilliseconds2String(flowStartTime / 1000L, "dd/MM/yyyy hh:mm:ss a");
        dump.append(starttime).append(separator);

        long flowDuration = flowLastSeen - flowStartTime;
        dump.append(flowDuration).append(separator);

        dump.append(fwdPktStats.getN()).append(separator);
        dump.append(bwdPktStats.getN()).append(separator);
        dump.append(fwdPktStats.getSum()).append(separator);
        dump.append(bwdPktStats.getSum()).append(separator);

        if (fwdPktStats.getN() > 0L) {
            dump.append(fwdPktStats.getMax()).append(separator);
            dump.append(fwdPktStats.getMin()).append(separator);
            dump.append(fwdPktStats.getMean()).append(separator);
            dump.append(fwdPktStats.getStandardDeviation()).append(separator);
        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }

        if (bwdPktStats.getN() > 0L) {
            dump.append(bwdPktStats.getMax()).append(separator);
            dump.append(bwdPktStats.getMin()).append(separator);
            dump.append(bwdPktStats.getMean()).append(separator);
            dump.append(bwdPktStats.getStandardDeviation()).append(separator);
        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }
        dump.append(((double) (forwardBytes + backwardBytes)) / ((double) flowDuration / 1000000L)).append(separator);
        dump.append(((double) packetCount()) / ((double) flowDuration / 1000000L)).append(separator);
        dump.append(flowIAT.getMean()).append(separator);
        dump.append(flowIAT.getStandardDeviation()).append(separator);
        dump.append(flowIAT.getMax()).append(separator);
        dump.append(flowIAT.getMin()).append(separator);

        if (this.forward.size() > 1) {
            dump.append(forwardIAT.getSum()).append(separator);
            dump.append(forwardIAT.getMean()).append(separator);
            dump.append(forwardIAT.getStandardDeviation()).append(separator);
            dump.append(forwardIAT.getMax()).append(separator);
            dump.append(forwardIAT.getMin()).append(separator);

        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }
        if (this.backward.size() > 1) {
            dump.append(backwardIAT.getSum()).append(separator);
            dump.append(backwardIAT.getMean()).append(separator);
            dump.append(backwardIAT.getStandardDeviation()).append(separator);
            dump.append(backwardIAT.getMax()).append(separator);
            dump.append(backwardIAT.getMin()).append(separator);
        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }

        dump.append(fPSH_cnt).append(separator);
        dump.append(bPSH_cnt).append(separator);
        dump.append(fURG_cnt).append(separator);
        dump.append(bURG_cnt).append(separator);

        dump.append(fHeaderBytes).append(separator);
        dump.append(bHeaderBytes).append(separator);
        dump.append(getfPktsPerSecond()).append(separator);
        dump.append(getbPktsPerSecond()).append(separator);

        if (this.forward.size() > 0 || this.backward.size() > 0) {
            dump.append(flowLengthStats.getMin()).append(separator);
            dump.append(flowLengthStats.getMax()).append(separator);
            dump.append(flowLengthStats.getMean()).append(separator);
            dump.append(flowLengthStats.getStandardDeviation()).append(separator);
            dump.append(flowLengthStats.getVariance()).append(separator);
        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }

        dump.append(flagCounts.get("FIN").value).append(separator);
        dump.append(flagCounts.get("SYN").value).append(separator);
        dump.append(flagCounts.get("RST").value).append(separator);
        dump.append(flagCounts.get("PSH").value).append(separator);
        dump.append(flagCounts.get("ACK").value).append(separator);
        dump.append(flagCounts.get("URG").value).append(separator);
        dump.append(flagCounts.get("CWR").value).append(separator);
        dump.append(flagCounts.get("ECE").value).append(separator);

        dump.append(getDownUpRatio()).append(separator);
        dump.append(getAvgPacketSize()).append(separator);
        dump.append(fAvgSegmentSize()).append(separator);
        dump.append(bAvgSegmentSize()).append(separator);

        dump.append(fAvgBytesPerBulk()).append(separator);
        dump.append(fAvgPacketsPerBulk()).append(separator);
        dump.append(fAvgBulkRate()).append(separator);
        dump.append(bAvgBytesPerBulk()).append(separator);
        dump.append(bAvgPacketsPerBulk()).append(separator);
        dump.append(bAvgBulkRate()).append(separator);

        dump.append(getSflow_fpackets()).append(separator);
        dump.append(getSflow_fbytes()).append(separator);
        dump.append(getSflow_bpackets()).append(separator);
        dump.append(getSflow_bbytes()).append(separator);

        dump.append(Init_Win_bytes_forward).append(separator);
        dump.append(Init_Win_bytes_backward).append(separator);
        dump.append(Act_data_pkt_forward).append(separator);
        dump.append(min_seg_size_forward).append(separator);

        if (this.flowActive.getN() > 0) {
            dump.append(flowActive.getMean()).append(separator);
            dump.append(flowActive.getStandardDeviation()).append(separator);
            dump.append(flowActive.getMax()).append(separator);
            dump.append(flowActive.getMin()).append(separator);
        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }

        if (this.flowIdle.getN() > 0) {
            dump.append(flowIdle.getMean()).append(separator);
            dump.append(flowIdle.getStandardDeviation()).append(separator);
            dump.append(flowIdle.getMax()).append(separator);
            dump.append(flowIdle.getMin()).append(separator);
        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }

        dump.append(getLabel());

        return dump.toString();
    }

    public List<Long> getPacketSerialNumbers() {
        return packetSerialNumbers;
    }
}

class MutableInt {
    int value = 0;

    public void increment() {
        ++value;
    }

    public int get() {
        return value;
    }

}
