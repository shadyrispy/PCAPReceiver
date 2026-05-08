use jni::JNIEnv;
use jni::objects::{JClass, JString};
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

#[no_mangle]
pub extern "C" fn Java_com_emanuelef_1pcap_1receiver_MainActivity_nativeProcessPacket(
    env: JNIEnv,
    _class: JClass,
    packet_data: jni::objects::JbyteArray,
) -> jstring {
    let _span = tracing::info_span!("nativeProcessPacket").entered();

    let packet_vec = match env.convert_byte_array(packet_data) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(?e, "Failed to convert byte array");
            return env.new_string("Error: Failed to convert byte array").unwrap_or_else(|_| std::ptr::null_mut());
        }
    };

    tracing::info!(len = packet_vec.len(), "Processing packet via JNI");

    let mut sniffer = match GAME_SNIFFER.lock() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(?e, "Failed to lock sniffer");
            return env.new_string("Error: Failed to lock sniffer").unwrap_or_else(|_| std::ptr::null_mut());
        }
    };

    let result = sniffer.receive_packet(packet_vec);

    let result_str = match result {
        Some(GamePacket::Connection(conn)) => {
            tracing::info!(?conn, "Connection packet");
            format!("Connection: {:?}", conn)
        }
        Some(GamePacket::Commands(commands)) => {
            let mut result_parts = Vec::new();
            for cmd in &commands {
                tracing::info!(?cmd, "Game command");
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

    env.new_string(&result_str)
        .map(|s| s.into_raw())
        .unwrap_or_else(|_| std::ptr::null_mut())
}
