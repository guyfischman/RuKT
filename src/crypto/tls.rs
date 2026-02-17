use anyhow::{Result, anyhow};

pub trait TlsEncode {
    fn tls_encode(&self, buf: &mut Vec<u8>);
}

// primitives
impl TlsEncode for u8 {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
    }
}

impl TlsEncode for u16 {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl TlsEncode for u32 {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl TlsEncode for u64 {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

// Helper for opaque<0..2^8-1> (1-byte length prefix)
pub struct Opaqueu8<'a>(pub &'a [u8]);
impl<'a> TlsEncode for Opaqueu8<'a> {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        // Panic or error handling should ideally happen before, but for trait simplicity:
        // We cap at u8::MAX. In a real scenario, check lengths upstream.
        let len = self.0.len().min(255) as u8;
        buf.push(len);
        buf.extend_from_slice(&self.0[..len as usize]);
    }
}

// Helper for opaque<0..2^16-1> (2-byte length prefix)
pub struct Opaqueu16<'a>(pub &'a [u8]);
impl<'a> TlsEncode for Opaqueu16<'a> {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        let len = self.0.len().min(65535) as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.0[..len as usize]);
    }
}

// Helper for opaque<0..2^32-1> (4-byte length prefix)
pub struct Opaqueu32<'a>(pub &'a [u8]);
impl<'a> TlsEncode for Opaqueu32<'a> {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        let len = self.0.len() as u32; // Assuming usize fits in u32 for this context
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(self.0);
    }
}

// Helper for fixed length arrays opaque[N] (No length prefix)
pub struct FixedOpaque<'a>(pub &'a [u8]);
impl<'a> TlsEncode for FixedOpaque<'a> {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.0);
    }
}