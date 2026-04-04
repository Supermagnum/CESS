//! Serpent-256-CTR helper for CESS test vector generation (GPL-3.0 per repository).
use cipher::{BlockCipherEncrypt, KeyInit};
use serpent::Serpent;
use std::env;
use std::io::Read;

fn serpent_ctr_encrypt(key: &[u8], iv16: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    let cipher = Serpent::new_from_slice(key).expect("key length 16..=32");
    let mut out = vec![0u8; pt.len()];
    let mut ctr = *iv16;
    let mut offset = 0usize;
    while offset < pt.len() {
        let mut block = cipher::Block::<Serpent>::from(ctr);
        cipher.encrypt_block(&mut block);
        let take = (pt.len() - offset).min(16);
        for i in 0..take {
            out[offset + i] = pt[offset + i] ^ block[i];
        }
        offset += take;
        for i in (0..16).rev() {
            ctr[i] = ctr[i].wrapping_add(1);
            if ctr[i] != 0 {
                break;
            }
        }
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: serpent_helper <hex_key_32> <hex_iv_16> <hex_pt | -> for stdin>");
        std::process::exit(1);
    }
    let key = hex::decode(&args[1]).unwrap();
    let iv = hex::decode(&args[2]).unwrap();
    let pt = if args[3] == "-" {
        let mut v = Vec::new();
        std::io::stdin().read_to_end(&mut v).unwrap();
        v
    } else {
        hex::decode(&args[3]).unwrap()
    };
    let mut iv16 = [0u8; 16];
    iv16.copy_from_slice(&iv);
    let ct = serpent_ctr_encrypt(&key, &iv16, &pt);
    print!("{}", hex::encode(ct));
}
