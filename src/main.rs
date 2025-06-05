use bitcoin::address::Address;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Network, PublicKey};
use rayon::prelude::*;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::sync::Mutex;
use std::time::SystemTime;

// Base58 decode function to produce 32-byte array, then convert to 64-character hex
fn base58_decode(s: &str) -> Result<String, &'static str> {
    const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut result = vec![0u8; 32]; // Initialize 32-byte array
    for &c in s.as_bytes() {
        let value = BASE58_ALPHABET
            .iter()
            .position(|&x| x == c)
            .ok_or("Invalid Base58 character")?;
        let mut carry = value as u64;
        for byte in result.iter_mut().rev() {
            carry += (*byte as u64) * 58;
            *byte = (carry % 256) as u8;
            carry /= 256;
        }
        if carry > 0 {
            return Err("Base58 decode overflow");
        }
    }
    // Convert to 64-character hexadecimal string
    let hex_str: String = result.iter().map(|b| format!("{:02x}", b)).collect();
    Ok(hex_str)
}

// Function to generate compressed P2PKH address from private key (hex string)
fn private_key_to_p2pkh(hex_private_key: &str) -> Result<String, &'static str> {
    // Convert 64-character hex string to 32-byte array
    let private_key_bytes = hex::decode(hex_private_key).map_err(|_| "Invalid hex private key")?;
    if private_key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes");
    }
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key_bytes).map_err(|_| "Invalid private key")?;
    let secp_public_key = secret_key.public_key(&secp);
    // Convert secp256k1::PublicKey to bitcoin::PublicKey
    let public_key = PublicKey {
        compressed: true,
        inner: secp_public_key,
    };
    let address = Address::p2pkh(&public_key, Network::Bitcoin);
    Ok(address.to_string())
}

// Xorshift128 RNG struct
struct XorShift128 {
    state: [u32; 4],
}

impl XorShift128 {
    fn new(seed: [u32; 4]) -> Self {
        XorShift128 { state: seed }
    }

    fn next(&mut self) -> u32 {
        let mut t = self.state[0];
        let s = self.state[3];
        self.state[0] = self.state[1];
        self.state[1] = self.state[2];
        self.state[2] = self.state[3];
        t ^= t << 11;
        t ^= t >> 8;
        self.state[3] = t ^ s ^ (s >> 19);
        self.state[3]
    }

    fn next_char(&mut self, scale: &[u8]) -> u8 {
        let index = (self.next() as usize) % scale.len();
        scale[index]
    }
}

fn main() -> io::Result<()> {
    // Fixed Base58 scale
    let scale = b"13456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // File for output, protected by Mutex for thread-safe writing
    let file = Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("output.txt")?,
    );

    // Fixed prefix
    let prefix = "111111111111111111111112";

    // Allowed characters for the first character after prefix
    let first_char_scale = b"23456789ABC";

    // Generate seeds based on system time
    let seed_base = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Parallel processing
    (0..rayon::current_num_threads()).into_par_iter().for_each(|i| {
        let mut rng = XorShift128::new([
            (seed_base.wrapping_add(i as u64)) as u32,
            (seed_base.wrapping_add((i + 1) as u64)) as u32,
            (seed_base.wrapping_add((i + 2) as u64)) as u32,
            (seed_base.wrapping_add((i + 3) as u64)) as u32,
        ]);

        loop {
            // Generate 12-character string
            let mut generated = vec![0u8; 12];
            // First character (position 25) must be from first_char_scale
            generated[0] = rng.next_char(first_char_scale.as_slice());
            // Remaining 11 characters from fixed scale
            for j in 1..12 {
                generated[j] = rng.next_char(scale.as_slice());
            }
            let generated_str = String::from_utf8(generated).unwrap();
            let full_number = format!("{}{}", prefix, generated_str);

            // Perform Base58 decode
            match base58_decode(&full_number) {
                Ok(hex_private_key) => {
                    // Generate P2PKH address
                    match private_key_to_p2pkh(&hex_private_key) {
                        Ok(address) => {
                            // Print to console for feedback
                            println!("Number: {}\nAddress: {}", full_number, address);

                            // Save to file if address starts with "1PWo"
                            if address.starts_with("1PWo") {
                                let output = format!("Number: {}\nAddress: {}\n", full_number, address);
                                let mut file = file.lock().unwrap();
                                file.write_all(output.as_bytes()).unwrap();
                                file.flush().unwrap();
                            }
                        }
                        Err(_) => continue,
                    }
                }
                Err(_) => continue,
            }
        }
    });

    Ok(())
}
