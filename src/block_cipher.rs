use crate::CryptographicPrimitive;

pub trait BlockTransformation: CryptographicPrimitive {
    fn block_size(&self) -> usize;
    fn transform(&self, block: &[u8]) -> Vec<u8>;
}

pub trait BlockCipherEncrypt: BlockTransformation {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        self.transform(plaintext)
    }
}

pub trait BlockCipherDecrypt: BlockTransformation {
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        self.transform(ciphertext)
    }
}

pub trait TweakableBlockTransformation: BlockTransformation {
    fn tweak_size(&self) -> usize;
}

