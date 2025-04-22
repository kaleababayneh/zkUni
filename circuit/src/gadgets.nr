// Cryptographic gadgets for zkUni
use dep::std::hash::poseidon::Poseidon;
use crate::constants::{N_STUDENT_PREFERENCE, N_COLLEGE_QUOTA, MAX_PREFS, MAX_COLLEGE_CAPACITY, ENCRYPTED_SIZE, TOTAL_ENCRYPTIONS, UNMATCHED};

// Generate a mask by combining the student and college public keys with a nonce
fn mask(pk_s: Field, pk_c: Field, nonce: Field) -> Field {
    let mut poseidon = Poseidon::new();
    poseidon.update(pk_s);
    poseidon.update(pk_c);
    poseidon.update(nonce);
    poseidon.finalize()
}

// Encrypt a u32 message using the public keys and a nonce
fn encrypt_u32(msg: u32, pk_s: Field, pk_c: Field, nonce: Field) -> [Field; 4] {
    // Generate the encryption mask
    let encryption_mask = mask(pk_s, pk_c, nonce);
    
    // Convert message to Field and combine with mask
    let msg_field = msg as Field;
    let cipher = msg_field + encryption_mask;
    
    // Generate a tag for integrity verification
    let mut poseidon = Poseidon::new();
    poseidon.update(msg_field);
    poseidon.update(nonce);
    poseidon.update(pk_s);
    poseidon.update(pk_c);
    let tag = poseidon.finalize();
    
    // Return the cipher, nonce, tag, and a padding value (0)
    [cipher, nonce, tag, 0 as Field]
}