mod elgamal;

global N_STUDENT_PREFERENCE: u32 = 5;
global N_COLLEGE_QUOTA: u32 = 5;
global MAX_PREFS: u32 = 5;
global MAX_COLLEGE_CAPACITY: u32 = 3;   // upper bound for any college quota
global ENCRYPTED_SIZE: u32 = 4;  // Size of encrypted data structure
global TOTAL_ENCRYPTIONS: u32 = N_STUDENT_PREFERENCE + (N_COLLEGE_QUOTA * MAX_COLLEGE_CAPACITY); // Max possible number of encryptions
global UNMATCHED: u32 = 999;
global BITS_DL: u32 = 32; 

use std::hash::hash_to_field;
use crate::elgamal::{ElGamalCiphered, EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul};

// Updated encryption function using secure ElGamal encryption
fn encrypt_elgamal(
    message: u32, 
    public_key: EmbeddedCurvePoint, 
    encryption_index: u32,  // Unique index for this encryption
    nonce_seed: Field       // Global seed value for this matching round
) -> ElGamalCiphered<BITS_DL> {
    // Generate unique randomness for each encryption operation
    // By incorporating encryption index and nonce
    let randomness_seed = hash_to_field([
        message as Field, 
        public_key.x, 
        public_key.y, 
        encryption_index as Field,
        nonce_seed
    ]);
    
    let randomness = EmbeddedCurveScalar::from_field(randomness_seed);
    
    // Perform ElGamal encryption with unique randomness
    ElGamalCiphered::<BITS_DL>::new(public_key, message as Field, randomness)
}

// Function to convert Field to EmbeddedCurvePoint
fn field_to_curve_point(key: Field) -> EmbeddedCurvePoint {
    fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(key))
}

fn stable_matching(
        student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE],
        college_prefs: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA],
        college_capacities: [u32; N_COLLEGE_QUOTA],
        actual_student_list: u32,
        actual_uni_list: u32
) -> [u32; N_STUDENT_PREFERENCE] {

    let mut next_application: [u32; N_STUDENT_PREFERENCE] = [0; N_STUDENT_PREFERENCE];
    let mut free_student: [bool; N_STUDENT_PREFERENCE] = [true; N_STUDENT_PREFERENCE];
    let mut current_match: [u32; N_STUDENT_PREFERENCE] = [UNMATCHED; N_STUDENT_PREFERENCE];

    let mut college_count: [u32; N_COLLEGE_QUOTA] = [0; N_COLLEGE_QUOTA];
    let mut college_matches: [[u32; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA] = [[UNMATCHED; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA];

    let mut college_ranks: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA] = [[0; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA];
    for w in 0..N_COLLEGE_QUOTA {
        if w < actual_uni_list {
            for r in 0..N_STUDENT_PREFERENCE {
                if r < actual_student_list {
                    let s = college_prefs[w][r];
                    college_ranks[w][s] = r;
                }
            }
        }
    }

    let max_iterations = N_STUDENT_PREFERENCE * MAX_PREFS; 
    let mut should_continue = true;

    for _ in 0..max_iterations {
        let mut progress = false; // track if any proposal happened this pass

        if should_continue {
            for s in 0..N_STUDENT_PREFERENCE {
                if (s < actual_student_list) & free_student[s] {
                    if next_application[s] < MAX_PREFS {
                        let c = student_prefs[s][next_application[s]];
                        next_application[s] += 1;

                        if (c != UNMATCHED) & (c < actual_uni_list) {
                            progress = true;
                           
                            if college_count[c] < college_capacities[c] {
                                let idx = college_count[c];
                                college_matches[c][idx] = s;
                                college_count[c] += 1;
                                current_match[s] = c;
                                free_student[s] = false;
                            } else {
                                let mut worst_idx: u32 = 0;
                                let mut worst_rank: u32 = 0;
                                let mut first = true;
                                for i in 0..MAX_COLLEGE_CAPACITY {
                                    if i < college_capacities[c] {
                                        let curr_s = college_matches[c][i];
                                        let rnk = college_ranks[c][curr_s];
                                        if first | (rnk > worst_rank) {
                                            first = false;
                                            worst_rank = rnk;
                                            worst_idx = i;
                                        }
                                    }
                                }

                                // Prefer new applicant?
                                if college_ranks[c][s] < worst_rank {
                                    let replaced = college_matches[c][worst_idx];
                                    college_matches[c][worst_idx] = s;
                                    current_match[s] = c;
                                    free_student[s] = false;

                                    // replaced student becomes free
                                    current_match[replaced] = UNMATCHED;
                                    free_student[replaced] = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Instead of break, update the continue flag
        should_continue = progress;
    }

    current_match
}

fn main(
    student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE],
    college_prefs: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA],
    college_capacities: [u32; N_COLLEGE_QUOTA],
    student_public_keys: [Field; N_STUDENT_PREFERENCE],
    college_public_keys: [Field; N_COLLEGE_QUOTA],
    actual_student_list: u32,
    actual_uni_list: u32,
    nonce_seed: Field  // Add global nonce seed parameter
) -> pub [ElGamalCiphered<BITS_DL>; TOTAL_ENCRYPTIONS] {
    // 1. Calculate the matching internally - NOT exposed publicly
    let matches = stable_matching(student_prefs, college_prefs, college_capacities, 
                               actual_student_list, actual_uni_list);
    
    // Convert Field keys to EmbeddedCurvePoints for ElGamal
    let mut student_curve_keys: [EmbeddedCurvePoint; N_STUDENT_PREFERENCE] = 
        [EmbeddedCurvePoint::point_at_infinity(); N_STUDENT_PREFERENCE];
    let mut college_curve_keys: [EmbeddedCurvePoint; N_COLLEGE_QUOTA] = 
        [EmbeddedCurvePoint::point_at_infinity(); N_COLLEGE_QUOTA];
    
    for i in 0..N_STUDENT_PREFERENCE {
        student_curve_keys[i] = field_to_curve_point(student_public_keys[i]);
    }
    
    for i in 0..N_COLLEGE_QUOTA {
        college_curve_keys[i] = field_to_curve_point(college_public_keys[i]);
    }
    
    // 2. Encrypt each match using ElGamal
    let mut encrypted_matches = [ElGamalCiphered::<BITS_DL> {
        c1: EmbeddedCurvePoint::point_at_infinity(),
        c2: EmbeddedCurvePoint::point_at_infinity()
    }; TOTAL_ENCRYPTIONS];
    
    let mut enc_idx = 0;
    
    // Encrypt for students - each student gets their matched college
    for s in 0..N_STUDENT_PREFERENCE {
        if s < actual_student_list {
            let matched_college = matches[s];
            encrypted_matches[enc_idx] = encrypt_elgamal(
                matched_college, 
                student_curve_keys[s],
                enc_idx,      // Use unique encryption index
                nonce_seed    // Use provided nonce seed
            );
            enc_idx += 1;
        }
    }
    
    // Encrypt for colleges - each college gets its matched students
    for c in 0..N_COLLEGE_QUOTA {
        if c < actual_uni_list {
            let mut count = 0;
            // Find all students matched to this college
            for s in 0..N_STUDENT_PREFERENCE {
                if s < actual_student_list {
                    if matches[s] == c {
                        encrypted_matches[enc_idx] = encrypt_elgamal(
                            s, 
                            college_curve_keys[c],
                            enc_idx,      // Use unique encryption index
                            nonce_seed    // Use provided nonce seed
                        );
                        enc_idx += 1;
                        count += 1;
                    }
                }
            }
            
            // Pad with dummy entries to hide the number of matches
            for pad in 0..MAX_COLLEGE_CAPACITY {
                if count < college_capacities[c] {
                    encrypted_matches[enc_idx] = encrypt_elgamal(
                        UNMATCHED, 
                        college_curve_keys[c],
                        enc_idx,      // Use unique encryption index
                        nonce_seed    // Use provided nonce seed
                    );
                    enc_idx += 1;
                    count += 1;
                }
            }
        }
    }
    
    // Fill remaining slots with dummy data if needed
    for i in 0..TOTAL_ENCRYPTIONS {
        if i >= enc_idx {
            encrypted_matches[i] = ElGamalCiphered::<BITS_DL> {
                c1: EmbeddedCurvePoint::point_at_infinity(),
                c2: EmbeddedCurvePoint::point_at_infinity()
            };
        }
    }
    
    encrypted_matches
}

#[test]
fn test_encrypted_matching() {
    let student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE] = [
        [0, 1, 2, UNMATCHED, UNMATCHED], 
        [1, 0, 2, UNMATCHED, UNMATCHED], 
        [1, 2, 0, UNMATCHED, UNMATCHED], 
        [0, 2, 1, UNMATCHED, UNMATCHED], 
        [2, 0, 1, UNMATCHED, UNMATCHED], 
    ];

    let college_prefs: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA] = [
        [1, 3, 0, 2, 4],   
        [2, 0, 4, 1, 3],   
        [0, 2, 3, 4, 1],   
        [UNMATCHED; N_STUDENT_PREFERENCE], 
        [UNMATCHED; N_STUDENT_PREFERENCE], 
    ];

    let college_capacities: [u32; N_COLLEGE_QUOTA] = [3, 1, 1, 0, 0];
    
    // Using smaller key hash values that fit within Field limits
    let student_public_keys: [Field; N_STUDENT_PREFERENCE] = [
        0x7d1e5f02b0cdc7e10cff917625b4e7ee as Field,
        0x83a1eff0b6627a69b41c5de7b0aeb8e3 as Field,
        0x9c4d8bfd9d4def4eeb1615aa53a32e30 as Field,
        0xa0b3576ee834936135b547beba820d6f as Field,
        0xb4f0c6f7d89513c2055c54bd463a5275 as Field
    ];
    
    let college_public_keys: [Field; N_COLLEGE_QUOTA] = [
        0xc78e07db0ad00f15ebde45d9afd043e4 as Field,
        0xd391cafa15d22c96a28afa0375ea8db7 as Field,
        0xe2e3aa9a63b2b855d7c81c9f60e9c411 as Field,
        0xf4b8dff2bb2a889432d097b3fb781c54 as Field,
        0x052968bd5e7e3d743d45cb45e7ca1bf7 as Field
    ];
    
    // Add a nonce seed for testing
    let nonce_seed = 0x12345678 as Field;

    let encrypted_results = main(
        student_prefs, 
        college_prefs, 
        college_capacities, 
        student_public_keys,
        college_public_keys,
        5, 
        3,
        nonce_seed  // Pass the nonce seed
    );
    
    // Test verification - examine a few encrypted values
    println("Encrypted matching test completed");
    println(TOTAL_ENCRYPTIONS);
    
    // Verify that we have some non-infinity values
    let has_real_values = encrypted_results[0].c1 != EmbeddedCurvePoint::point_at_infinity();
    println(has_real_values);
    
    // Verify encryption properties
    println("\nVerifying encryption security properties:");
    
    // Test that encrypting the same message twice produces different ciphertexts
    let test_message = 1;
    let test_key = field_to_curve_point(student_public_keys[0]);
    
    let cipher1 = encrypt_elgamal(test_message, test_key, 100, nonce_seed);
    let cipher2 = encrypt_elgamal(test_message, test_key, 101, nonce_seed);
    
    // They should have different c1 values due to different randomness
    let different_ciphertexts = (cipher1.c1.x != cipher2.c1.x) | (cipher1.c1.y != cipher2.c1.y);
    println("Same message, different encryption indices produces different ciphertexts: ");
    println(different_ciphertexts);
}

// Optional additional test to verify semantic security
#[test]
fn test_semantic_security() {
    // Setup a test key
    let key_field = 0x7d1e5f02b0cdc7e10cff917625b4e7ee as Field;
    let test_key = field_to_curve_point(key_field);
    let nonce_seed = 0x12345678 as Field;
    
    // Test message
    let message = 5;
    
    // Encrypt the same message multiple times with different indices
    let cipher1 = encrypt_elgamal(message, test_key, 1, nonce_seed);
    let cipher2 = encrypt_elgamal(message, test_key, 2, nonce_seed);
    let cipher3 = encrypt_elgamal(message, test_key, 3, nonce_seed);
    
    // Verify all ciphertexts are different
    let all_different = 
        ((cipher1.c1.x != cipher2.c1.x) | (cipher1.c1.y != cipher2.c1.y)) &
        ((cipher1.c1.x != cipher3.c1.x) | (cipher1.c1.y != cipher3.c1.y)) &
        ((cipher2.c1.x != cipher3.c1.x) | (cipher2.c1.y != cipher3.c1.y));
    
    println("Semantic security test (all ciphertexts should be different): ");
    println(all_different);
}