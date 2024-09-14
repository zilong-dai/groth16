use ark_ff::PrimeField;
use ark_r1cs_std::{
    boolean::Boolean, convert::ToBitsGadget, prelude::ToBytesGadget, uint64::UInt64, uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;
use ark_std::ops::{BitAnd, BitXor, BitXorAssign, Not};

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const ROTR: [usize; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Keccak256 gadget
#[derive(Debug, Clone)]
pub struct Keccak256Gadget<ConstraintF: PrimeField> {
    state: Vec<UInt64<ConstraintF>>,
    completed_data_blocks: u64,
    pending: Vec<UInt8<ConstraintF>>,
    num_pending: usize,
}

impl<ConstraintF: PrimeField> Keccak256Gadget<ConstraintF> {
    /// default constructor
    pub fn new() -> Self {
        Self {
            state: vec![UInt64::constant(0); 25],
            completed_data_blocks: 0,
            pending: vec![UInt8::constant(0); 136],
            num_pending: 0,
        }
    }

    fn update_state(&mut self) {
        let input = self
            .pending
            .chunks(8)
            .map(|e| UInt64::from_bytes_le(e).expect("UInt64 from bytes error"))
            .collect::<Vec<_>>();

        assert_eq!(input.len(), 17);

        for i in 0..input.len() {
            self.state[i].bitxor_assign(&input[i]);
        }

        for i in 0..24 {
            self.state = round_1600(self.state.clone(), ROUND_CONSTANTS[i]);
        }
    }

    /// Consumes the given data and updates the internal state
    pub fn update(&mut self, data: &[UInt8<ConstraintF>]) {
        let mut offset = 0;
        if self.num_pending > 0 && self.num_pending + data.len() >= 136 {
            offset = 136 - self.num_pending;

            self.pending[self.num_pending..].clone_from_slice(&data[..offset]);
            self.update_state();

            self.completed_data_blocks += 1;
            self.num_pending = 0;
        }

        for chunk in data[offset..].chunks(136) {
            let chunk_size = chunk.len();

            if chunk_size == 136 {
                // If it's a full chunk, process it
                self.pending.clone_from_slice(chunk);
                self.update_state();
                self.completed_data_blocks += 1;
            } else {
                // Otherwise, add the bytes to the `pending` buffer
                self.pending[self.num_pending..self.num_pending + chunk_size]
                    .clone_from_slice(chunk);
                self.num_pending += chunk_size;
            }
        }
    }

    /// Outputs the final digest of all the inputted data
    pub fn finalize(mut self) -> Vec<UInt8<ConstraintF>> {
        // padding
        let offset = 136 - self.num_pending;

        let mut pending = vec![UInt8::constant(0); offset];
        pending[0] = UInt8::constant(0x01);

        pending[offset - 1] = UInt8::constant(0x80);

        self.update(&pending[..]);

        // Collect the state into big-endian bytes
        self.state
            .iter()
            .take(4)
            .flat_map(|i| UInt64::to_bytes_le(i).unwrap())
            .collect()
    }

    /// Computes the digest of the given data. This is a shortcut for
    /// `default()` followed by `update()` followed by `finalize()`.
    pub fn digest(data: &[UInt8<ConstraintF>]) -> Vec<UInt8<ConstraintF>> {
        let mut keccak256_var = Self::new();
        keccak256_var.update(data);
        keccak256_var.finalize()
    }
}

fn xor_2<F: PrimeField>(a: &UInt64<F>, b: &UInt64<F>) -> UInt64<F> {
    // a ^ b
    a.bitxor(b)
}

fn xor_5<F: PrimeField>(
    a: &UInt64<F>,
    b: &UInt64<F>,
    c: &UInt64<F>,
    d: &UInt64<F>,
    e: &UInt64<F>,
) -> UInt64<F> {
    // a ^ b ^ c ^ d ^ e
    let ab = a.bitxor(b);
    let abc = ab.bitxor(c);
    let abcd = abc.bitxor(d);
    abcd.bitxor(e)
}

fn xor_not_and<F: PrimeField>(a: &UInt64<F>, b: &UInt64<F>, c: &UInt64<F>) -> UInt64<F> {
    // a ^ ((!b) & c)
    let nb = b.not();
    let nbc = nb.bitand(c);
    a.bitxor(&nbc)
}

fn round_1600<F: PrimeField>(a: Vec<UInt64<F>>, rc: u64) -> Vec<UInt64<F>> {
    assert_eq!(a.len(), 25);

    // # θ step
    // C[x] = A[x,0] bitxor A[x,1] bitxor A[x,2] bitxor A[x,3] bitxor A[x,4],   for
    // x in 0…4
    let mut c = Vec::new();
    for x in 0..5 {
        c.push(xor_5(
            &a[x + 0usize],
            &a[x + 5usize],
            &a[x + 10usize],
            &a[x + 15usize],
            &a[x + 20usize],
        ));
    }

    // D[x] = C[x-1] bitxor rot(C[x+1],1),                             for x in 0…4
    let mut d = Vec::new();
    for x in 0..5 {
        d.push(xor_2(
            &c[(x + 4usize) % 5usize],
            &c[(x + 1usize) % 5usize].rotate_left(1),
        ));
    }

    // A[x,y] = A[x,y] bitxor D[x],                           for (x,y) in (0…4,0…4)
    let mut a_new1 = Vec::new();
    for y in 0..5 {
        for x in 0..5 {
            a_new1.push(xor_2(&a[x + (y * 5usize)], &d[x]));
        }
    }

    // # ρ and π steps
    // B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)
    let mut b = a_new1.clone();
    for y in 0..5 {
        for x in 0..5 {
            b[y + ((((2 * x) + (3 * y)) % 5) * 5usize)] =
                a_new1[x + (y * 5usize)].rotate_left(ROTR[x + (y * 5usize)]);
        }
    }

    let mut a_new2 = Vec::new();

    // # χ step
    // A[x,y] = B[x,y] bitxor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
    for y in 0..5 {
        for x in 0..5 {
            a_new2.push(xor_not_and(
                &b[x + (y * 5usize)],
                &b[((x + 1usize) % 5usize) + (y * 5usize)],
                &b[((x + 2usize) % 5usize) + (y * 5usize)],
            ));
        }
    }

    // // # ι step
    // // A[0,0] = A[0,0] bitxor RC
    let rc = UInt64::<F>::constant(rc);
    a_new2[0].bitxor_assign(&rc);

    a_new2
}

fn keccak_f_1600_bytes<F: PrimeField>(input: Vec<UInt8<F>>) -> Vec<UInt8<F>> {
    assert_eq!(input.len(), 200);

    let mut a = input
        .chunks(8)
        .map(|e| UInt64::from_bytes_le(e).expect("UInt64 from bytes error"))
        .collect::<Vec<_>>();

    for i in 0..24 {
        a = round_1600(a, ROUND_CONSTANTS[i]);
    }

    a.into_iter()
        .flat_map(|e| e.to_bytes_le().unwrap())
        .collect()
}

/// keccak256 for bytes inputs.
pub fn keccak256_bytes<F: PrimeField>(input: &[UInt8<F>]) -> Vec<UInt8<F>> {
    let block_size_in_bytes = 136;
    let input_len_in_bytes = input.len();
    let num_blocks = input_len_in_bytes / block_size_in_bytes + 1;

    let mut padded = vec![UInt8::<F>::constant(0); block_size_in_bytes * num_blocks];

    for i in 0..input.len() {
        padded[i] = input[i].clone();
    }

    padded[input_len_in_bytes] = UInt8::<F>::constant(0x01);

    let last_index = padded.len() - 1;

    padded[last_index] = UInt8::<F>::constant(0x80);

    let mut m: Vec<UInt8<F>> = vec![UInt8::<F>::constant(0); 200];
    for i in 0..num_blocks {
        for j in 0..block_size_in_bytes {
            m[j].bitxor_assign(&padded[i * block_size_in_bytes + j]);
        }
        m = keccak_f_1600_bytes(m);
    }

    let mut z = Vec::new();

    for i in 0..256 / 8 {
        z.push(m[i].clone());
    }

    return z;
}

fn keccak_f_1600<F: PrimeField>(input: Vec<Boolean<F>>) -> Vec<Boolean<F>> {
    assert_eq!(input.len(), 1600);

    let mut a = input
        .chunks(64)
        .map(|e| UInt64::from_bits_le(e))
        .collect::<Vec<_>>();

    for i in 0..24 {
        // let cs = &mut cs.namespace(|| format!("keccack round {}", i));

        a = round_1600(a, ROUND_CONSTANTS[i]);
    }

    a.into_iter()
        .flat_map(|e| e.to_bits_le().unwrap())
        .collect()
}

/// keccak256 for boolean inputs.
pub fn keccak256<F: PrimeField>(input: &[Boolean<F>]) -> Result<Vec<Boolean<F>>, SynthesisError> {
    assert_eq!(input.len() % 8, 0); // input should be bytes.
    let block_size_in_bits = 1088;
    let input_len_in_bits = input.len();
    let num_blocks = input_len_in_bits / block_size_in_bits + 1;

    let mut padded = vec![Boolean::<F>::Constant(false); block_size_in_bits * num_blocks];

    for i in 0..input.len() {
        padded[i] = input[i].clone();
    }

    padded[input_len_in_bits] = Boolean::<F>::Constant(true);

    let last_index = padded.len() - 1;

    padded[last_index] = Boolean::<F>::Constant(true);

    let mut m: Vec<Boolean<F>> = vec![Boolean::<F>::Constant(false); 1600];
    for i in 0..num_blocks {
        for j in 0..block_size_in_bits {
            m[j].bitxor_assign(&padded[i * block_size_in_bits + j]);
        }
        m = keccak_f_1600(m);
    }

    let mut z = Vec::new();

    for i in 0..256 {
        z.push(m[i].clone());
    }

    return Ok(z);
}
