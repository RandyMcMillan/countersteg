//! MSB-first bit stream reader/writer (morse_binary_tree.rs gist pattern).

/// Accumulates bits MSB-first into bytes; partial tail byte is zero-padded.
pub struct BitWriter {
    bytes: Vec<u8>,
    cur: u8,
    used: u8,
}

impl BitWriter {
    pub fn new() -> Self {
        Self { bytes: Vec::new(), cur: 0, used: 0 }
    }

    pub fn push(&mut self, bit: u8) {
        self.cur = (self.cur << 1) | (bit & 1);
        self.used += 1;
        if self.used == 8 {
            self.bytes.push(self.cur);
            self.cur = 0;
            self.used = 0;
        }
    }

    pub fn push_bits(&mut self, value: u32, n: u32) {
        for k in 0..n {
            self.push(((value >> (n - 1 - k)) & 1) as u8);
        }
    }

    pub fn bit_len(&self) -> usize {
        self.bytes.len() * 8 + self.used as usize
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        if self.used > 0 {
            self.bytes.push(self.cur << (8 - self.used));
        }
        self.bytes
    }
}

/// Reads bits MSB-first. `take(n)` returns None when fewer than n bits remain.
pub struct BitReader<'a> {
    bytes: &'a [u8],
    bitpos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bitpos: 0 }
    }

    pub fn take(&mut self, n: usize) -> Option<u32> {
        if self.remaining() < n || n > 32 {
            return None;
        }
        let mut v = 0u32;
        for _ in 0..n {
            let byte = self.bytes[self.bitpos / 8];
            let bit = (byte >> (7 - (self.bitpos % 8))) & 1;
            v = (v << 1) | bit as u32;
            self.bitpos += 1;
        }
        Some(v)
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() * 8 - self.bitpos
    }

    pub fn consumed(&self) -> usize {
        self.bitpos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_reader_roundtrip() {
        let mut w = BitWriter::new();
        w.push_bits(0b101, 3);
        w.push_bits(0b11111111, 8);
        w.push_bits(0, 1);
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.take(3), Some(0b101));
        assert_eq!(r.take(8), Some(0b11111111));
        // 11 bits consumed of 16: the 12th (pushed) bit plus 4 pad bits remain.
        for _ in 0..5 {
            assert_eq!(r.take(1), Some(0));
        }
        assert_eq!(r.take(1), None);
    }

    #[test]
    fn padding_zeros() {
        let mut w = BitWriter::new();
        w.push(1);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0b1000_0000]);
    }
}
