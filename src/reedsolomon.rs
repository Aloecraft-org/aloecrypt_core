const SLIP39_RS1024_GEN: [u32; 4] = [0x0E0E, 0x1C71, 0x09A8, 0x10A9];

pub fn slip39_rs1024_polymod(values: impl IntoIterator<Item = u16>) -> u32 {
    let mut chk = 1u32;
    for v in values {
        let b = chk >> 20;
        chk = ((chk & 0xFFFFF) << 10) ^ (v as u32);
        for i in 0..4 {
            if (b >> i) & 1 != 0 {
                chk ^= SLIP39_RS1024_GEN[i];
            }
        }
    }
    chk
}

pub fn create_slip39_rs1024_checksum(data: &[u16]) -> [u16; 3] {
    let iter = b"shamir"
        .iter()
        .map(|&b| b as u16)
        .chain(data.iter().copied())
        .chain([0, 0, 0].into_iter());

    let polymod = slip39_rs1024_polymod(iter) ^ 1;

    [
        ((polymod >> 20) & 0x3FF) as u16,
        ((polymod >> 10) & 0x3FF) as u16,
        (polymod & 0x3FF) as u16,
    ]
}

pub fn verify_slip39_rs1024_checksum(data: &[u16]) -> bool {
    let iter = b"shamir"
        .iter()
        .map(|&b| b as u16)
        .chain(data.iter().copied());

    slip39_rs1024_polymod(iter) == 1
}
