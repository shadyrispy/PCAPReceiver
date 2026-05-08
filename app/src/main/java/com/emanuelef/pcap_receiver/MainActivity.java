package com.emanuelef.pcap_receiver;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Observable;
import java.util.Observer;

public class MainActivity extends AppCompatActivity implements Observer {
    static final String PCAPDROID_PACKAGE = "com.emanuelef.remote_capture";
    static final String CAPTURE_CTRL_ACTIVITY = "com.emanuelef.remote_capture.activities.CaptureCtrl";
    static final String CAPTURE_STATUS_ACTION = "com.emanuelef.remote_capture.CaptureStatus";
    static final String TAG = "PCAP Receiver";
    private static final int PCAPDROID_TRAILER_SIZE = 32;
    private static final int PCAPDROID_MAGIC = 0x01072021;
    private static final int FCS_SIZE = 4;
    private static final int PCAPREC_HDR_SIZE = 16;

    Button mStart;
    CaptureThread mCapThread;
    TextView mLog;
    boolean mCaptureRunning = false;

    private final ActivityResultLauncher<Intent> captureStartLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), this::handleCaptureStartResult);
    private final ActivityResultLauncher<Intent> captureStopLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), this::handleCaptureStopResult);
    private final ActivityResultLauncher<Intent> captureStatusLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), this::handleCaptureStatusResult);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mLog = findViewById(R.id.pkts_log);
        mStart = findViewById(R.id.start_btn);
        mStart.setOnClickListener(v -> {
            if(!mCaptureRunning)
                startCapture();
            else
                stopCapture();
        });

        if((savedInstanceState != null) && savedInstanceState.containsKey("capture_running"))
            setCaptureRunning(savedInstanceState.getBoolean("capture_running"));
        else
            queryCaptureStatus();

        MyBroadcastReceiver.CaptureObservable.getInstance().addObserver(this);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        MyBroadcastReceiver.CaptureObservable.getInstance().deleteObserver(this);
        stopCaptureThread();
    }

    @Override
    public void update(Observable o, Object arg) {
        boolean capture_running = (boolean)arg;
        Log.d(TAG, "capture_running: " + capture_running);
        setCaptureRunning(capture_running);
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle bundle) {
        bundle.putBoolean("capture_running", mCaptureRunning);
        super.onSaveInstanceState(bundle);
    }

    void onPacketReceived(EthernetPacket pkt) {
        int ethPayloadLength = pkt.length();
        if (ethPayloadLength < PCAPDROID_TRAILER_SIZE) {
            Log.w(TAG, "Packet too short to contain trailer");
            return;
        }

        byte[] trailer = Arrays.copyOfRange(pkt.getRawData(), ethPayloadLength - PCAPDROID_TRAILER_SIZE, ethPayloadLength - FCS_SIZE);

        ByteBuffer trailerBuffer = ByteBuffer.wrap(trailer);

        int magic = trailerBuffer.getInt(0);
        int uid = trailerBuffer.getInt(4);
        byte[] appNameBytes = new byte[20];
        trailerBuffer.position(8);
        trailerBuffer.get(appNameBytes, 0, 20);
        String appName = new String(appNameBytes, StandardCharsets.UTF_8).trim();

        if (magic != PCAPDROID_MAGIC) {
            Log.w(TAG, "Invalid magic number: " + Integer.toHexString(magic));
            return;
        }

        if (pkt.getPayload() instanceof IpV4Packet) {
            IpV4Packet ipV4Packet = (IpV4Packet) pkt.getPayload();
            IpV4Packet.IpV4Header hdr = ipV4Packet.getHeader();
            mLog.append(String.format("[%s] %s -> %s [%d B] (App: %s, UID: %d)\n",
                    hdr.getProtocol(),
                    hdr.getSrcAddr().getHostAddress(), hdr.getDstAddr().getHostAddress(),
                    ipV4Packet.length(), appName, uid));
        } else {
            Log.w(TAG, "Received non-IPv4 packet");
        }
    }

    void queryCaptureStatus() {
        Log.d(TAG, "Querying PCAPdroid");

        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setClassName(PCAPDROID_PACKAGE, CAPTURE_CTRL_ACTIVITY);
        intent.putExtra("action", "get_status");

        try {
            captureStatusLauncher.launch(intent);
        } catch (ActivityNotFoundException e) {
            Toast.makeText(this, "PCAPdroid package not found: " + PCAPDROID_PACKAGE, Toast.LENGTH_LONG).show();
        }
    }

    void startCapture() {
        Log.d(TAG, "Starting PCAPdroid");

        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setClassName(PCAPDROID_PACKAGE, CAPTURE_CTRL_ACTIVITY);

        intent.putExtra("action", "start");
        intent.putExtra("broadcast_receiver", "com.emanuelef.pcap_receiver.MyBroadcastReceiver");
        intent.putExtra("pcap_dump_mode", "udp_exporter");
        intent.putExtra("collector_ip_address", "127.0.0.1");
        intent.putExtra("collector_port", "5123");
        intent.putExtra("pcapdroid_trailer", "true");

        captureStartLauncher.launch(intent);
    }

    void stopCapture() {
        Log.d(TAG, "Stopping PCAPdroid");

        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setClassName(PCAPDROID_PACKAGE, CAPTURE_CTRL_ACTIVITY);
        intent.putExtra("action", "stop");

        captureStopLauncher.launch(intent);
    }

    void setCaptureRunning(boolean running) {
        mCaptureRunning = running;
        mStart.setText(running ? "Stop Capture" : "Start Capture");

        if(mCaptureRunning && (mCapThread == null)) {
            mCapThread = new CaptureThread(this);
            mCapThread.start();
        } else if(!mCaptureRunning)
            stopCaptureThread();
    }

    void stopCaptureThread() {
        if(mCapThread == null)
            return;

        mCapThread.stopCapture();
        mCapThread.interrupt();
        mCapThread = null;
    }

    void handleCaptureStartResult(final ActivityResult result) {
        Log.d(TAG, "PCAPdroid start result: " + result);

        if(result.getResultCode() == RESULT_OK) {
            Toast.makeText(this, "Capture started!", Toast.LENGTH_SHORT).show();
            setCaptureRunning(true);
            mLog.setText("");
        } else
            Toast.makeText(this, "Capture failed to start", Toast.LENGTH_SHORT).show();
    }

    void handleCaptureStopResult(final ActivityResult result) {
        Log.d(TAG, "PCAPdroid stop result: " + result);

        if(result.getResultCode() == RESULT_OK) {
            Toast.makeText(this, "Capture stopped!", Toast.LENGTH_SHORT).show();
            setCaptureRunning(false);
            saveCapturedPackets();
        } else
            Toast.makeText(this, "Could not stop capture", Toast.LENGTH_SHORT).show();

        Intent intent = result.getData();
        if((intent != null) && (intent.hasExtra("bytes_sent")))
            logStats(intent);
    }

    private void saveCapturedPackets() {
        if (mCapThread == null) {
            Log.w(TAG, "No capture thread found");
            return;
        }

        List<CaptureThread.CapturedPacket> packets = mCapThread.getCapturedPackets();
        if (packets == null || packets.isEmpty()) {
            Log.w(TAG, "No packets captured");
            Toast.makeText(this, "No packets captured on ports 22101/22102", Toast.LENGTH_SHORT).show();
            return;
        }

        new Thread(() -> {
            try {
                String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(new Date());
                String filename = "capture_" + timestamp + ".pcap";

                File downloadDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                if (!downloadDir.exists()) {
                    downloadDir.mkdirs();
                }

                File outputFile = new File(downloadDir, filename);

                FileOutputStream fos = new FileOutputStream(outputFile);

                writePcapHeader(fos, packets.size());

                for (CaptureThread.CapturedPacket packet : packets) {
                    writePcapRecord(fos, packet);
                }

                fos.close();

                final String savedPath = outputFile.getAbsolutePath();
                final int packetCount = packets.size();

                runOnUiThread(() -> {
                    Toast.makeText(this,
                        "Saved " + packetCount + " packets to Downloads/" + filename,
                        Toast.LENGTH_LONG).show();
                    Log.i(TAG, "Packets saved to: " + savedPath);
                });

            } catch (IOException e) {
                Log.e(TAG, "Failed to save packets", e);
                runOnUiThread(() -> {
                    Toast.makeText(this,
                        "Failed to save packets: " + e.getMessage(),
                        Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    private void writePcapHeader(FileOutputStream fos, int packetCount) throws IOException {
        ByteBuffer header = ByteBuffer.allocate(24);

        header.putInt(0x1A2B3C4D);
        header.putShort((short) 0x0002);
        header.putShort((short) 0x0004);
        header.putInt(0);
        header.putInt(0);
        header.putInt(65535);
        header.putInt(1);

        fos.write(header.array());
    }

    private void writePcapRecord(FileOutputStream fos, CaptureThread.CapturedPacket packet) throws IOException {
        if (packet.length < PCAPREC_HDR_SIZE) {
            Log.w(TAG, "Invalid packet length: " + packet.length);
            return;
        }

        byte[] pcapData = Arrays.copyOfRange(packet.data, PCAPREC_HDR_SIZE, packet.length);
        int captureLen = pcapData.length;
        int origLen = packet.length - PCAPREC_HDR_SIZE;

        ByteBuffer recordHeader = ByteBuffer.allocate(16);
        recordHeader.putInt((int) (packet.timestamp >> 32));
        recordHeader.putInt((int) (packet.timestamp & 0xFFFFFFFF));
        recordHeader.putInt(captureLen);
        recordHeader.putInt(origLen);

        fos.write(recordHeader.array());
        fos.write(pcapData);
    }

    void handleCaptureStatusResult(final ActivityResult result) {
        Log.d(TAG, "PCAPdroid status result: " + result);

        if((result.getResultCode() == RESULT_OK) && (result.getData() != null)) {
            Intent intent = result.getData();
            boolean running = intent.getBooleanExtra("running", false);
            int verCode = intent.getIntExtra("version_code", 0);
            String verName = intent.getStringExtra("version_name");

            if(verName == null)
                verName = "<1.4.6";

            Log.d(TAG, "PCAPdroid " + verName + "(" + verCode + "): running=" + running);
            setCaptureRunning(running);
        }
    }

    void logStats(Intent intent) {
        String stats = "*** Stats ***" +
                "\nBytes sent: " +
                intent.getLongExtra("bytes_sent", 0) +
                "\nBytes received: " +
                intent.getLongExtra("bytes_rcvd", 0) +
                "\nPackets sent: " +
                intent.getIntExtra("pkts_sent", 0) +
                "\nPackets received: " +
                intent.getIntExtra("pkts_rcvd", 0) +
                "\nPackets dropped: " +
                intent.getIntExtra("pkts_dropped", 0) +
                "\nPCAP dump size: " +
                intent.getLongExtra("bytes_dumped", 0);

        Log.i("stats", stats);
    }
}
