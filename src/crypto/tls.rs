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
pub struct Opaqueu8<'a>(&'a [u8]);
impl<'a> Opaqueu8<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > u8::MAX as usize {
            return Err(anyhow!("opaque<0..2^8-1> overflow: {} bytes", bytes.len()));
        }
        Ok(Self(bytes))
    }
}
impl<'a> TlsEncode for Opaqueu8<'a> {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.0.len() as u8);
        buf.extend_from_slice(self.0);
    }
}

// Helper for opaque<0..2^16-1> (2-byte length prefix)
pub struct Opaqueu16<'a>(&'a [u8]);
impl<'a> Opaqueu16<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > u16::MAX as usize {
            return Err(anyhow!("opaque<0..2^16-1> overflow: {} bytes", bytes.len()));
        }
        Ok(Self(bytes))
    }
}
impl<'a> TlsEncode for Opaqueu16<'a> {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.0.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.0);
    }
}

// Helper for opaque<0..2^32-1> (4-byte length prefix)
pub struct Opaqueu32<'a>(&'a [u8]);
impl<'a> Opaqueu32<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > u32::MAX as usize {
            return Err(anyhow!("opaque<0..2^32-1> overflow: {} bytes", bytes.len()));
        }
        Ok(Self(bytes))
    }
}
impl<'a> TlsEncode for Opaqueu32<'a> {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.0.len() as u32).to_be_bytes());
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

// §2.1
pub struct Optional<'a, T: TlsEncode>(pub Option<&'a T>);
impl<'a, T: TlsEncode> TlsEncode for Optional<'a, T> {
    fn tls_encode(&self, buf: &mut Vec<u8>) {
        match self.0 {
            None => buf.push(0),
            Some(v) => {
                buf.push(1);
                v.tls_encode(buf);
            }
        }
    }
}

pub trait TlsDecode: Sized {
    fn tls_decode(buf: &mut &[u8]) -> Result<Self>;
}

fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if buf.len() < n {
        return Err(anyhow!("TLS decode: unexpected end of input"));
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Ok(head)
}

macro_rules! impl_tls_decode_uint {
    ($t:ty, $n:expr) => {
        impl TlsDecode for $t {
            fn tls_decode(buf: &mut &[u8]) -> Result<Self> {
                let bytes = take(buf, $n)?;
                Ok(<$t>::from_be_bytes(bytes.try_into().unwrap()))
            }
        }
    };
}

impl_tls_decode_uint!(u8, 1);
impl_tls_decode_uint!(u16, 2);
impl_tls_decode_uint!(u32, 4);
impl_tls_decode_uint!(u64, 8);

// §2.1: a presence octet other than 0 or 1 MUST be rejected as malformed
impl<T: TlsDecode> TlsDecode for Option<T> {
    fn tls_decode(buf: &mut &[u8]) -> Result<Self> {
        match u8::tls_decode(buf)? {
            0 => Ok(None),
            1 => Ok(Some(T::tls_decode(buf)?)),
            other => Err(anyhow!(
                "TLS decode: malformed optional presence octet {}",
                other
            )),
        }
    }
}

pub fn decode_opaque_u8<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = u8::tls_decode(buf)? as usize;
    take(buf, len)
}

pub fn decode_opaque_u16<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = u16::tls_decode(buf)? as usize;
    take(buf, len)
}

pub fn decode_opaque_u32<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = u32::tls_decode(buf)? as usize;
    take(buf, len)
}

pub fn decode_fixed_opaque<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    take(buf, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_roundtrip() {
        let mut buf = Vec::new();
        Optional::<u32>(None).tls_encode(&mut buf);
        Optional(Some(&7u32)).tls_encode(&mut buf);
        assert_eq!(buf, [0, 1, 0, 0, 0, 7]);

        let mut slice = &buf[..];
        assert_eq!(Option::<u32>::tls_decode(&mut slice).unwrap(), None);
        assert_eq!(Option::<u32>::tls_decode(&mut slice).unwrap(), Some(7));
        assert!(slice.is_empty());
    }

    #[test]
    fn optional_rejects_malformed_presence_octet() {
        for octet in [2u8, 0xff] {
            let buf = [octet, 0, 0, 0, 7];
            let mut slice = &buf[..];
            assert!(Option::<u32>::tls_decode(&mut slice).is_err());
        }
    }

    #[test]
    fn optional_rejects_truncated_value() {
        let buf = [1u8, 0, 0];
        let mut slice = &buf[..];
        assert!(Option::<u32>::tls_decode(&mut slice).is_err());
    }

    #[test]
    fn opaque_rejects_oversize_input() {
        assert!(Opaqueu8::new(&[0u8; 256]).is_err());
        assert!(Opaqueu8::new(&[0u8; 255]).is_ok());
        assert!(Opaqueu16::new(&[0u8; 65536]).is_err());
        assert!(Opaqueu16::new(&[0u8; 65535]).is_ok());
    }

    #[test]
    fn opaque_decode_roundtrip() {
        let mut buf = Vec::new();
        Opaqueu8::new(b"abc").unwrap().tls_encode(&mut buf);
        Opaqueu16::new(b"de").unwrap().tls_encode(&mut buf);
        Opaqueu32::new(b"f").unwrap().tls_encode(&mut buf);

        let mut slice = &buf[..];
        assert_eq!(decode_opaque_u8(&mut slice).unwrap(), b"abc");
        assert_eq!(decode_opaque_u16(&mut slice).unwrap(), b"de");
        assert_eq!(decode_opaque_u32(&mut slice).unwrap(), b"f");
        assert!(slice.is_empty());

        let mut short = &buf[..2];
        assert!(decode_opaque_u8(&mut short).is_err());
    }
}
