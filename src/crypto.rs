use digest::generic_array::typenum::U64;
use digest::generic_array::GenericArray;
use digest::{FixedOutput, HashMarker, OutputSizeUser, Reset, Update};

/// This is a Blake3 Hasher implementing the traits required for use in
/// the ed25519 construction in place of SHA-512
#[derive(Clone)]
pub struct Blake3 {
    pub(crate) h: blake3::Hasher,
}

impl Update for Blake3 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.h.update(data.as_ref());
    }
}

impl Reset for Blake3 {
    #[inline]
    fn reset(&mut self) {
        self.h.reset();
    }
}

impl Default for Blake3 {
    #[inline]
    fn default() -> Self {
        Blake3 {
            h: blake3::Hasher::new(),
        }
    }
}

impl FixedOutput for Blake3 {
    #[inline]
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.h.finalize_xof().fill(out);
    }
}

impl OutputSizeUser for Blake3 {
    type OutputSize = U64;
}

impl HashMarker for Blake3 {}
