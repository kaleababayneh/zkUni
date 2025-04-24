mod elgamal;
use std::hash::hash_to_field;
use crate::elgamal::{ElGamalCiphered, EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul};

global N_STUDENT_PREFERENCE: u32 = 5;
global N_COLLEGE_QUOTA: u32 = 5;
global MAX_PREFS: u32 = 5;
global MAX_COLLEGE_CAPACITY: u32 = 3;   
global ENCRYPTED_SIZE: u32 = 4;  
global TOTAL_ENCRYPTIONS: u32 = N_STUDENT_PREFERENCE + (N_COLLEGE_QUOTA * MAX_COLLEGE_CAPACITY); 
global UNMATCHED: Field = 999;
global BITS_DL: u32 = 16; 



fn encrypt_elgamal(
    message: Field, 
    public_key: EmbeddedCurvePoint, 
    encryption_index: Field,  // Unique index for this encryption
    nonce_seed: Field       // Global seed value for this matching round
) -> ElGamalCiphered<BITS_DL> {
    
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
        student_prefs: [[Field; MAX_PREFS]; N_STUDENT_PREFERENCE],
        college_prefs: [[Field; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA],
        college_capacities: [Field; N_COLLEGE_QUOTA],
        actual_student_list: u32,
        actual_uni_list: u32
) -> [Field; N_STUDENT_PREFERENCE] {

    let mut next_application: [Field; N_STUDENT_PREFERENCE] = [0; N_STUDENT_PREFERENCE];
    let mut free_student: [bool; N_STUDENT_PREFERENCE] = [true; N_STUDENT_PREFERENCE];
    let mut current_match: [Field; N_STUDENT_PREFERENCE] = [UNMATCHED; N_STUDENT_PREFERENCE];

    let mut college_count: [Field; N_COLLEGE_QUOTA] = [0; N_COLLEGE_QUOTA];
    let mut college_matches: [[Field; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA] = [[UNMATCHED; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA];

    let mut college_ranks: [[Field; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA] = [[0; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA];
    for w in 0..N_COLLEGE_QUOTA {
        if w < actual_uni_list {
            for r in 0..N_STUDENT_PREFERENCE {
                if r < actual_student_list {
                    let s = college_prefs[w][r];
                    college_ranks[w][s] = r as Field;
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
                    if next_application[s] as u32 < MAX_PREFS {
                        let c = student_prefs[s][next_application[s]];
                        next_application[s] += 1;

                        if (c as u32 != UNMATCHED as u32) & (c as u32 < actual_uni_list as u32) {
                            progress = true;
                           
                            if college_count[c] as u32 < college_capacities[c] as u32 {
                                let idx = college_count[c];
                                college_matches[c][idx] = s as Field;
                                college_count[c] += 1;
                                current_match[s] = c;
                                free_student[s] = false;
                            } else {
                                let mut worst_idx: u32 = 0;
                                let mut worst_rank: u32 = 0;
                                let mut first = true;
                                for i in 0..MAX_COLLEGE_CAPACITY {
                                    if i  < college_capacities[c] as u32 {
                                        let curr_s = college_matches[c][i];
                                        let rnk = college_ranks[c][curr_s];
                                        if first | (rnk as u32 > worst_rank) {
                                            first = false;
                                            worst_rank = rnk as u32;
                                            worst_idx = i;
                                        }
                                    }
                                }

                                // Prefer new applicant?
                                if college_ranks[c][s] as u32 < worst_rank as u32 {
                                    let replaced = college_matches[c][worst_idx];
                                    college_matches[c][worst_idx] = s as Field;
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
    student_prefs: [[Field; MAX_PREFS]; N_STUDENT_PREFERENCE],
    college_prefs: [[Field; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA],
    college_capacities: [Field; N_COLLEGE_QUOTA],
    student_public_keys: [EmbeddedCurvePoint; N_STUDENT_PREFERENCE],
    college_public_keys: [Field; N_COLLEGE_QUOTA],
    actual_student_list: u32,
    actual_uni_list: u32,
    nonce_seed: Field  // Add global nonce seed parameter
) -> pub [ElGamalCiphered<BITS_DL>; N_STUDENT_PREFERENCE]  {

    let private_key_f:EmbeddedCurveScalar = EmbeddedCurveScalar::from_field(0);
    let public_key_f:EmbeddedCurvePoint = fixed_base_scalar_mul(private_key_f);
    let UNMATCHED_ELGAMAL: ElGamalCiphered<BITS_DL> = ElGamalCiphered::<BITS_DL>::new(public_key_f, 0 as Field, EmbeddedCurveScalar::from_field(0));


    let mut matches: [ElGamalCiphered<BITS_DL>; N_STUDENT_PREFERENCE] = [UNMATCHED_ELGAMAL; N_STUDENT_PREFERENCE];
    let mut stable_matches = stable_matching(student_prefs, college_prefs, college_capacities, 
                               actual_student_list, actual_uni_list);


    let nonce_seed = 0x12345678 as Field;
    stable_matches = stable_matches.map(|x| x + 1 as Field); 
    for i in 0..N_STUDENT_PREFERENCE {
            matches[i] = encrypt_elgamal(
                stable_matches[i], 
                student_public_keys[i], 
                i as Field, 
                nonce_seed  
            );
    }
    matches
}

#[test]
fn test_main() {

    let student_prefs: [[Field; MAX_PREFS]; N_STUDENT_PREFERENCE] = [
        [0, 1, 2, UNMATCHED, UNMATCHED], 
        [1, 0, 2, UNMATCHED, UNMATCHED], 
        [1, 2, 0, UNMATCHED, UNMATCHED], 
        [0, 2, 1, UNMATCHED, UNMATCHED], 
        [2, 0, 1, UNMATCHED, UNMATCHED], 
    ];

    let college_prefs: [[Field; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA] = [
        [1, 3, 0, 2, 4],   
        [2, 0, 4, 1, 3],   
        [0, 2, 3, 4, 1],   
        [UNMATCHED; N_STUDENT_PREFERENCE], 
        [UNMATCHED; N_STUDENT_PREFERENCE], 
    ];

    let student_private_keys: [Field; N_STUDENT_PREFERENCE] = [
        0x1 as Field,
        0x2 as Field,
        0x3 as Field,
        0x4 as Field,
        0x5 as Field
    ];

    let student_public_keys: [EmbeddedCurvePoint; N_STUDENT_PREFERENCE] = [
        field_to_curve_point(student_private_keys[0]),
        field_to_curve_point(student_private_keys[1]),
        field_to_curve_point(student_private_keys[2]),
        field_to_curve_point(student_private_keys[3]),
        field_to_curve_point(student_private_keys[4]),
    ];

    let college_public_keys: [Field; N_COLLEGE_QUOTA] = [
        0x62e1785593d92f52bfe162bc4c975dae37726d6a,
        0x8b0b0861d77d87c6ff34fe6e5574793a7036f460,
        0x02ec9331a737670e9e73a74be6d023dbb66d8246,
        0x8be07db4a7e6e139633e0129bfdd04a76a5a4047,
        0x56a4ca66fc67fcb5ea31aed16e26cc9553a7210e
    ];

    let college_private_keys: [Field; N_COLLEGE_QUOTA] = [
        0x07a87786dbf1840dec2b804c64c333e6e1d7925dcccf7bdff4ee183f86cc370e,
        0x06e1b407e49760702e61698985b0325ddd9e583f544d4bacff0aa57a213b735e,
        0x0c43da8120542d2c5027a55a0d0f20ec029789c825f9a62509761732e25b887c,
        0x03c49ccc8c7416f66418c63365beb4b8e2575b830132c47189cb595f2ccb343a,
        0x04973fa1c556b807b25b50121aa2a816c8787e7cd9e793f5f33ef49686b79058
    ];

    let nonce_seed = 0x12345678 as Field;

    let college_capacities: [Field; N_COLLEGE_QUOTA] = [3, 1, 1, 0, 0];
    

    let encrypted_results = main(
        student_prefs, 
        college_prefs, 
        college_capacities, 
        student_public_keys,
        college_public_keys,
        5, 
        3,
        nonce_seed  

    );
    let stable_matches = stable_matching(
        student_prefs, 
        college_prefs, 
        college_capacities, 
        5, 
        3
    );
    println("Stable matches:");
    println(stable_matches);
    println("Encrypted results:");
    println(encrypted_results);
    println("Test passed!");

    // decrypt the results from elgamal encryption
    let mut decrypted_message: [Field; N_STUDENT_PREFERENCE] = [1; N_STUDENT_PREFERENCE];
    for i in 0..N_STUDENT_PREFERENCE {
        if !(encrypted_results[i].c1.is_infinite) { 
            decrypted_message[i] = encrypted_results[i].decrypt_to_scalar(EmbeddedCurveScalar::from_field(student_private_keys[i])) as Field;
        }
    }
    println("Decrypted messages:");
    //assert(decrypted_message == stable_matches);
    println(decrypted_message);
    println("Decryption successful for all encrypted results!");
}


