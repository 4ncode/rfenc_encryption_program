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

