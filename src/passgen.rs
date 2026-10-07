use anyhow::{anyhow, Result};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

fn random_index(n: usize) -> Result<usize> {
    let limit = 256 - (256 % n);
    loop {
        let mut b = [0u8; 1];
        getrandom::getrandom(&mut b).map_err(|e| anyhow!("RNG failure: {e}"))?;
        if (b[0] as usize) < limit {
            return Ok((b[0] as usize) % n);
        }
    }
}

pub fn generate(len: usize) -> Result<String> {
    let len = len.clamp(8, 128);
    let alphabet: Vec<u8> = [LOWER, UPPER, DIGITS, SYMBOLS].concat();
    loop {
        let mut pw = String::with_capacity(len);
        for _ in 0..len {
            pw.push(alphabet[random_index(alphabet.len())?] as char);
    }
    let has = |set: &[u8]| pw.bytes().any(|c| set.contains(&c));
    if has(LOWER) && has(UPPER) && has(DIGITS) && has(SYMBOLS) {
        return Ok(pw);
    }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    Weak,
    Fair,
    Good,
    Strong,
}

impl Strength {
    pub fn label(self) -> &'static str {
        match self {
            Strength::Weak => "Weak",
            Strength::Fair => "Fair",
            Strength::Good => "Good",
            Strength::Strong => "Strong",
        }
    }
}

pub fn estimate_bits(pw: &str) -> f64 {
    let mut pool = 0u32;
    if pw.bytes().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
