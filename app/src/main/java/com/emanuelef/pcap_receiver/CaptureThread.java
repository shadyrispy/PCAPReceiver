package com.emanuelef.pcap_receiver;

import android.util.Log;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.UdpPacket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class CaptureThread extends Thread {
    static final String TAG = "CaptureThread";
    static final int PCAP_HDR_SIZE = 24;
    static final int PCAPREC_HDR_SIZE = 16;
    static final int FILTER_PORT_1 = 22101;
    static final int FILTER_PORT_2 = 22102;
    static final ByteBuffer PCAP_HDR_START_BYTES = ByteBuffer.wrap(hex2bytes("d4c3b2a1020004000000000000000000"));
    final MainActivity mActivity;
    private DatagramSocket mSocket;
    private List<CapturedPacket> capturedPackets;

    public static class CapturedPacket {
        public long timestamp;
        public byte[] data;
        public int length;

        public CapturedPacket(long timestamp, byte[] data, int length) {
            this.timestamp = timestamp;
            this.data = data;
            this.length = length;
        }
    }

    public CaptureThread(MainActivity activity) {
        mActivity = activity;
        capturedPackets = new ArrayList<>();
    }

    public static byte[] hex2bytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public List<CapturedPacket> getCapturedPackets() {
        return capturedPackets;
    }

    @Override
    public void run() {
        try {
            mSocket = new DatagramSocket(5123);
            byte[] buf = new byte[65535];
            DatagramPacket datagram = new DatagramPacket(buf, buf.length);
            Log.d(TAG, "running");

            while(true) {
                mSocket.receive(datagram);
                int len = datagram.getLength();
                ByteBuffer data = ByteBuffer.wrap(buf, 0, len);

                if((len == PCAP_HDR_SIZE) && (ByteBuffer.wrap(buf, 0, PCAP_HDR_START_BYTES.capacity()).equals(PCAP_HDR_START_BYTES))) {
                    Log.d(TAG, "Detected PCAP header, skipping");
                    continue;
                }

                if(len < PCAPREC_HDR_SIZE) {
                    Log.w(TAG, "Invalid PCAP record: " + len);
                    continue;
                }

                try {
                    EthernetPacket pkt = EthernetPacket.newPacket(buf, PCAPREC_HDR_SIZE, len - PCAPREC_HDR_SIZE);

                    if (shouldCapturePacket(pkt)) {
                        byte[] packetData = new byte[len];
                        System.arraycopy(buf, 0, packetData, 0, len);
                        long timestamp = System.currentTimeMillis() * 1000;
                        capturedPackets.add(new CapturedPacket(timestamp, packetData, len));
                        Log.d(TAG, "Captured packet: " + len + " bytes (Total: " + capturedPackets.size() + ")");
                    }

                    mActivity.runOnUiThread(() -> mActivity.onPacketReceived(pkt));
                } catch (IllegalRawDataException e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            if(!(e instanceof SocketException))
                e.printStackTrace();
        }
    }

    private boolean shouldCapturePacket(EthernetPacket pkt) {
        if (pkt.getPayload() instanceof IpV4Packet) {
            IpV4Packet ipV4Packet = (IpV4Packet) pkt.getPayload();
            if (ipV4Packet.getPayload() instanceof UdpPacket) {
                UdpPacket udpPacket = (UdpPacket) ipV4Packet.getPayload();
                int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
                return (srcPort == FILTER_PORT_1 || srcPort == FILTER_PORT_2 ||
                        dstPort == FILTER_PORT_1 || dstPort == FILTER_PORT_2);
            }
        }
        return false;
    }

    public void stopCapture() {
        if(mSocket != null)
            mSocket.close();
        try {
            join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
