use sha2::{Digest, Sha256};

pub (crate)const DST: &[u8] = b"bsb22-commitment"; // Example DST; change as needed
const SHA256_BLOCK_SIZE: usize = 64; // Block size for SHA-256
const SHA256_OUTPUT_SIZE: usize = 32; // Output size for SHA-256

// Helper function to perform the hash
fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ExpandMsgXmd function as per H2C spec
pub fn expand_msg_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {

    let ell = (len_in_bytes + SHA256_OUTPUT_SIZE - 1) / SHA256_OUTPUT_SIZE;
    if ell > 255 {
        panic!("ell must be <= 255");
    }

    let dst_len = dst.len() as u8;
    // let msg_len = msg.len();
    
    let z_pad = vec![0u8; SHA256_BLOCK_SIZE];
    let l_i_b_str = (len_in_bytes as u16).to_be_bytes();
    // let len0 = 2 + msg_len + dst_len + 1 + SHA256_OUTPUT_SIZE;

    let b0_preimage = vec![
        &z_pad[..],
        msg,
        &l_i_b_str,
        &[0u8],
        dst,
        &[dst_len],
    ]
    .concat();

    let b0 = hash_sha256(&b0_preimage);

    // let b0_len = b0.len();
    let b1_preimage = vec![
        &b0[..],
        &[1u8],
        dst,
        &[dst_len],
    ]
    .concat();

    let mut result = vec![];
    let mut b1: Vec<u8> = hash_sha256(&b1_preimage);
    result.extend_from_slice(&b1);

    for i in 2..=ell {
        let mut xored = vec![];
        for (x, y) in b1.iter().zip(b0.iter()) {
            xored.push(x ^ y);
        }
        let bi_preimage = vec![
            &xored[..],
            &[i as u8],
            dst,
            &[dst_len],
        ]
        .concat();
        b1 = hash_sha256(&bi_preimage);

        result.extend_from_slice(&b1);
    }

    result.truncate(len_in_bytes);
    result
}