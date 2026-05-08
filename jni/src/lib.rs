use jni::JNIEnv;
use jni::objects::{JClass, JByteArray};
use jni::sys::jstring;
use auto_artifactarium::{GameSniffer, GamePacket};
use std::sync::Mutex;
use once_cell::sync::Lazy;

static GAME_SNIFFER: Lazy<Mutex<GameSniffer>> = Lazy::new(|| {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    Mutex::new(GameSniffer::new())
});

fn connection_desc(conn: &auto_artifactarium::ConnectionPacket) -> String {
    use auto_artifactarium::ConnectionPacket;
    match conn {
        ConnectionPacket::HandshakeRequested => "HandshakeRequested".to_string(),
        ConnectionPacket::Disconnected => "Disconnected".to_string(),
        ConnectionPacket::HandshakeEstablished => "HandshakeEstablished".to_string(),
        ConnectionPacket::SegmentData(dir, data) => {
            format!("SegmentData({:?}, {} bytes)", dir, data.len())
        }
    }
}

#[no_mangle]
pub extern "C" fn Java_com_emanuelef_1pcap_1receiver_MainActivity_nativeProcessPacket(
    env: JNIEnv,
    _class: JClass,
    packet_data: JByteArray,
) -> jstring {
    let _span = tracing::info_span!("nativeProcessPacket").entered();

    let packet_vec = match env.convert_byte_array(packet_data) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(?e, "Failed to convert byte array");
            let jstr = env.new_string("Error: Failed to convert byte array").expect("Failed to create JString");
            return jstr.into_raw();
        }
    };

    tracing::info!(len = packet_vec.len(), "Processing packet via JNI");

    let mut sniffer = match GAME_SNIFFER.lock() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(?e, "Failed to lock sniffer");
            let jstr = env.new_string("Error: Failed to lock sniffer").expect("Failed to create JString");
            return jstr.into_raw();
        }
    };

    let result = sniffer.receive_packet(packet_vec);

    let result_str = match result {
        Some(GamePacket::Connection(conn)) => {
            let desc = connection_desc(&conn);
            tracing::info!("Connection packet: {}", desc);
            format!("Connection: {}", desc)
        }
        Some(GamePacket::Commands(commands)) => {
            let mut result_parts = Vec::new();
            for cmd in &commands {
                tracing::info!("Game command: id={}, data_len={}", cmd.command_id, cmd.data_len);
                result_parts.push(format!("Command(id={}, data_len={})", cmd.command_id, cmd.data_len));
            }
            if result_parts.is_empty() {
                "Commands: (empty)".to_string()
            } else {
                format!("Commands: [{}]", result_parts.join(", "))
            }
        }
        None => {
            tracing::info!("No packet parsed");
            "No packet parsed".to_string()
        }
    };

    tracing::info!(result = %result_str, "JNI result");

    let jstr = env.new_string(&result_str).expect("Failed to create JString");
    jstr.into_raw()
}
