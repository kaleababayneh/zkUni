mod elgamal; 
use std::hash::hash_to_field; 
use crate::elgamal::{ElGamalCiphered, EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul}; 
use std::hash::pedersen_hash;
global N_STUDENT_PREFERENCE: u32 = 5; 
global N_COLLEGE_QUOTA: u32 = 5; 
global MAX_PREFS: u32 = 5; 
global MAX_COLLEGE_CAPACITY: u32 = 3; 
global ENCRYPTED_SIZE: u32 = 4; 
// 5 student encryptions + up to 3 slots for each of 5 colleges = 20 max
global TOTAL_ENCRYPTIONS: u32 = N_STUDENT_PREFERENCE + (N_COLLEGE_QUOTA * MAX_COLLEGE_CAPACITY);

global UNMATCHED: Field = 999; 
global BITS_DL: u32 = 16; 

struct MatchResults {
    student_matches: [ElGamalCiphered<BITS_DL>; N_STUDENT_PREFERENCE], 
    college_matches: [[ElGamalCiphered<BITS_DL>; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA] 
} 

fn encrypt_elgamal( 
    message: Field, 
    public_key: EmbeddedCurvePoint, 
    recipient_id: Field, // Used for routing in distributed systems 
    encryption_index: Field, // Unique index for this encryption 
    nonce_seed: Field 
) -> ElGamalCiphered<BITS_DL> {
    
    let randomness_seed = hash_to_field([
        message as Field,
        public_key.x,
        public_key.y,
        recipient_id,
        encryption_index as Field,
        nonce_seed
    ]);
    
    let randomness = EmbeddedCurveScalar::from_field(randomness_seed); 
    
    ElGamalCiphered::<BITS_DL>::new(public_key, message as Field, randomness) 
} 

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

    // Precompute college preference rankings for O(1) lookup during matching 
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

    // Maximum number of iterations needed (each student could try all preferences) 
    let max_iterations = N_STUDENT_PREFERENCE * MAX_PREFS; 
    let mut should_continue = true; 

    // Main matching algorithm loop 
    for _ in 0..max_iterations { 
        let mut progress = false; // Track if any new proposal happened in this iteration 

        if should_continue { 
            for s in 0..N_STUDENT_PREFERENCE { 
                if (s < actual_student_list) & free_student[s] { 
                    if next_application[s] as u32 < MAX_PREFS { 
                        let c = student_prefs[s][next_application[s]]; 
                        next_application[s] += 1; 

                        if (c as u32 != UNMATCHED as u32) & (c as u32 < actual_uni_list as u32) { 
                            progress = true; 
                           
                            if college_count[c] as u32 < college_capacities[c] as u32 { 
                                // College has space, accept student directly 
                                let idx = college_count[c]; 
                                college_matches[c][idx] = s as Field; 
                                college_count[c] += 1; 
                                current_match[s] = c; 
                                free_student[s] = false; 
                            } else { 
                                // College is full, check if student should replace another 
                                let mut worst_idx: u32 = 0; 
                                let mut worst_rank: u32 = 0; 
                                let mut first = true; 
                                
                                // Find the least preferred student currently matched to college c 
                                for i in 0..MAX_COLLEGE_CAPACITY { 
                                    if i < college_capacities[c] as u32 { 
                                        let curr_s = college_matches[c][i]; 
                                        let rnk = college_ranks[c][curr_s]; 
                                        if first | (rnk as u32 > worst_rank) { 
                                            first = false; 
                                            worst_rank = rnk as u32; 
                                            worst_idx = i; 
                                        } 
                                    } 
                                } 

                                // If current student is preferred over the worst match, replace 
                                if college_ranks[c][s] as u32 < worst_rank as u32 { 
                                    let replaced = college_matches[c][worst_idx]; 
                                    college_matches[c][worst_idx] = s as Field; 
                                    current_match[s] = c; 
                                    free_student[s] = false; 

                                    // Replaced student becomes free again 
                                    current_match[replaced] = UNMATCHED; 
                                    free_student[replaced] = true; 
                                } 
                            } 
                        } 
                    } 
                } 
            } 
        } 

        // Update the continue flag instead of using break 
        should_continue = progress; 
    } 

    current_match 
} 

/// Main function that performs matching and encrypts the results for all participants 
fn main( 
    student_prefs: [[Field; MAX_PREFS]; N_STUDENT_PREFERENCE], 
    college_prefs: [[Field; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA], 
    college_capacities: [Field; N_COLLEGE_QUOTA], 
    student_public_keys: [EmbeddedCurvePoint; N_STUDENT_PREFERENCE], 
    college_public_keys: [Field; N_COLLEGE_QUOTA], 
    actual_student_list: u32, 
    actual_uni_list: u32, 
    nonce_seed: Field, // Global seed value for randomness 
    committed_inputs: pub Field, // Public input containing commitment hash
) -> pub MatchResults { 

    let mut input_fields: [Field; N_STUDENT_PREFERENCE * MAX_PREFS + N_COLLEGE_QUOTA * N_STUDENT_PREFERENCE + N_COLLEGE_QUOTA + 2] = [0; N_STUDENT_PREFERENCE * MAX_PREFS + N_COLLEGE_QUOTA * N_STUDENT_PREFERENCE + N_COLLEGE_QUOTA + 2];
    
    // Flatten student preferences
    let mut index = 0;
    for i in 0..N_STUDENT_PREFERENCE {
        for j in 0..MAX_PREFS {
            input_fields[index] = student_prefs[i][j];
            index += 1;
        }
    }
    
    // Flatten college preferences
    for i in 0..N_COLLEGE_QUOTA {
        for j in 0..N_STUDENT_PREFERENCE {
            input_fields[index] = college_prefs[i][j];
            index += 1;
        }
    }
    
    // Add college capacities
    for i in 0..N_COLLEGE_QUOTA {
        input_fields[index] = college_capacities[i];
        index += 1;
    }
    
    // Add actual counts
    input_fields[index] = actual_student_list as Field;
    index += 1;
    input_fields[index] = actual_uni_list as Field;
    
    // Compute the hash of all inputs
    let computed_commitment = pedersen_hash(input_fields);
    assert(committed_inputs == computed_commitment); // Ensure the commitment matches the inputs
    // Create a placeholder for unmatched/dummy entries 
    let private_key_f: EmbeddedCurveScalar = EmbeddedCurveScalar::from_field(0); 
    let public_key_f: EmbeddedCurvePoint = fixed_base_scalar_mul(private_key_f); 
    let UNMATCHED_ELGAMAL: ElGamalCiphered<BITS_DL> = ElGamalCiphered::<BITS_DL>::new(public_key_f, 0 as Field, EmbeddedCurveScalar::from_field(0)); 

    // 1. Calculate the stable matching 
    let mut stable_matches = stable_matching( 
        student_prefs, 
        college_prefs, 
        college_capacities, 
        actual_student_list, 
        actual_uni_list 
    ); 
    
    stable_matches = stable_matches.map(|x| x + 1 as Field); 
    
    // 3. Initialize result structures 
    let mut result = MatchResults { 
        student_matches: [UNMATCHED_ELGAMAL; N_STUDENT_PREFERENCE], 
        college_matches: [[UNMATCHED_ELGAMAL; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA] 
    }; 
    
    // 4. Encrypt matches for students 
    for i in 0..N_STUDENT_PREFERENCE { 
        if i < actual_student_list { 
            result.student_matches[i] = encrypt_elgamal( 
                stable_matches[i], 
                student_public_keys[i], 
                i as Field, // recipient_id 
                i as Field, // encryption_index 
                nonce_seed 
            ); 
        } 
    } 
    
    // 5. Create and encrypt matches for colleges 
    let mut college_matches_array = [[UNMATCHED + 1 as Field; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA]; 
    
    // 5a. Populate college matches array from stable matching results 
    for c in 0..N_COLLEGE_QUOTA { 
        if c < actual_uni_list { 
            let mut slot = 0; 
            for s in 0..N_STUDENT_PREFERENCE { 
                if stable_matches[s] - 1 as Field == c as Field { // Subtract the +1 adjustment 
                    if slot < college_capacities[c] as u32 { 
                        college_matches_array[c][slot] = (s + 1) as Field; // Add 1 to avoid zero 
                        slot += 1; 
                    } 
                } 
            } 
        } 
    } 
    
    // 5b. Encrypt college matches with proper padding
    for c in 0..N_COLLEGE_QUOTA { 
        if c < actual_uni_list { 
            let college_pub_key = field_to_curve_point(college_public_keys[c]); 
            
            // Count how many real matches this college has
            let mut real_match_count = 0;
            for i in 0..MAX_COLLEGE_CAPACITY {
                if (i < college_capacities[c] as u32) & (college_matches_array[c][i] != UNMATCHED + 1) {
                    real_match_count += 1;
                }
            }
            
            // Encrypt all slots up to capacity using a fixed-size loop
            for i in 0..MAX_COLLEGE_CAPACITY { 
                if i < college_capacities[c] as u32 {
                    // Choose the correct value based on whether this is a real match or padding
                    let value_to_encrypt = if i < real_match_count {
                        college_matches_array[c][i] // Real match
                    } else {
                        UNMATCHED + 1 // Padding value
                    };
                    
                    // Encrypt either the real match or the padding
                    result.college_matches[c][i] = encrypt_elgamal( 
                        value_to_encrypt, 
                        college_pub_key, 
                        (N_STUDENT_PREFERENCE + c) as Field, 
                        (N_STUDENT_PREFERENCE + c*MAX_COLLEGE_CAPACITY + i) as Field, 
                        nonce_seed 
                    );
                }
            }
        } 
    }
    
    result 
} 

/// Decrypt student matches for verification 
fn decrypt_student_matches( 
    encrypted_results: MatchResults, 
    student_private_keys: [Field; N_STUDENT_PREFERENCE] 
) -> [Field; N_STUDENT_PREFERENCE] { 
    let mut decrypted_message: [Field; N_STUDENT_PREFERENCE] = [0; N_STUDENT_PREFERENCE]; 
    
    for i in 0..N_STUDENT_PREFERENCE { 
        if !(encrypted_results.student_matches[i].c1.is_infinite) { 
            let private_scalar = EmbeddedCurveScalar::from_field(student_private_keys[i]); 
            decrypted_message[i] = encrypted_results.student_matches[i].decrypt_to_scalar(private_scalar) as Field; 
        } 
    } 
    
    // Convert back to original values (remove the +1 adjustment) 
    decrypted_message.map(|x| x - 1 as Field) 
} 

/// Decrypt college matches for verification 
fn decrypt_college_matches( 
    encrypted_results: MatchResults, 
    college_private_keys: [Field; N_COLLEGE_QUOTA], 
    college_capacities: [Field; N_COLLEGE_QUOTA] 
) -> [[Field; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA] { 
    let mut decrypted_college_matches: [[Field; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA] = [[UNMATCHED; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA]; 
    
    for c in 0..N_COLLEGE_QUOTA { 
        if college_capacities[c] as u32 > 0 { 
            let private_scalar = EmbeddedCurveScalar::from_field(college_private_keys[c]); 
            
            for i in 0..MAX_COLLEGE_CAPACITY { 
                if i < college_capacities[c] as u32 { 
                    if !(encrypted_results.college_matches[c][i].c1.is_infinite) { 
                        decrypted_college_matches[c][i] = encrypted_results.college_matches[c][i].decrypt_to_scalar(private_scalar) as Field; 
                    } 
                } 
            } 
        } 
    } 
    
    // Convert back to original values (remove the +1 adjustment) 
    for c in 0..N_COLLEGE_QUOTA { 
        for i in 0..MAX_COLLEGE_CAPACITY { 
            if decrypted_college_matches[c][i] as u32 > 0 { 
                decrypted_college_matches[c][i] -= 1; 
            } 
        } 
    } 
    
    decrypted_college_matches 
} 

#[test] 
fn test_main() { 
    // 1. Setup test data 
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

    // 2. Setup cryptographic keys 
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

    // College keys - in production these would be elliptic curve keys 
    let college_private_keys: [Field; N_COLLEGE_QUOTA] = [ 
        0x6 as Field, 
        0x7 as Field, 
        0x8 as Field, 
        0x9 as Field, 
        0xA as Field 
    ]; 

    let college_public_keys: [Field; N_COLLEGE_QUOTA] = [ 
        college_private_keys[0], // These should be derived correctly in production 
        college_private_keys[1], 
        college_private_keys[2], 
        college_private_keys[3], 
        college_private_keys[4] 
    ]; 

    let college_capacities: [Field; N_COLLEGE_QUOTA] = [3, 1, 1, 0, 0]; 
    let nonce_seed = 0x12345678 as Field; 

    let mut input_fields: [Field; N_STUDENT_PREFERENCE * MAX_PREFS + N_COLLEGE_QUOTA * N_STUDENT_PREFERENCE + N_COLLEGE_QUOTA + 2] = [0; N_STUDENT_PREFERENCE * MAX_PREFS + N_COLLEGE_QUOTA * N_STUDENT_PREFERENCE + N_COLLEGE_QUOTA + 2];
    
    // Flatten student preferences
    let mut index = 0;
    for i in 0..N_STUDENT_PREFERENCE {
        for j in 0..MAX_PREFS {
            input_fields[index] = student_prefs[i][j];
            index += 1;
        }
    }
    
    // Flatten college preferences
    for i in 0..N_COLLEGE_QUOTA {
        for j in 0..N_STUDENT_PREFERENCE {
            input_fields[index] = college_prefs[i][j];
            index += 1;
        }
    }
    
    // Add college capacities
    for i in 0..N_COLLEGE_QUOTA {
        input_fields[index] = college_capacities[i];
        index += 1;
    }

    let actual_student_list = 5; // Number of students in the actual list
    let actual_uni_list = 3; // Number of colleges in the actual list
    
    // Add actual counts
    input_fields[index] = actual_student_list as Field;
    index += 1;
    input_fields[index] = actual_uni_list as Field;
    
    // Compute the hash of all inputs
    let computed_commitment = pedersen_hash(input_fields);
    // 3. Run the matching protocol 
    let encrypted_results = main( 
        student_prefs, 
        college_prefs, 
        college_capacities, 
        student_public_keys, 
        college_public_keys, 
        5, // actual_student_list 
        3, // actual_uni_list 
        nonce_seed,
        computed_commitment // commitment hash
    ); 
    
    // 4. Calculate expected matches for verification 
    let stable_matches = stable_matching( 
        student_prefs, 
        college_prefs, 
        college_capacities, 
        5, 
        3 
    ); 
    
    // 5. Print results 
    println("Expected stable matches:"); 
    println(stable_matches); 
    println(""); 
    
    println("Encrypted student results (showing first entry):"); 
    println(encrypted_results.student_matches[0]); 
    println(""); 
    
    println("Encrypted college results (showing first college's first entry):"); 
    println(encrypted_results.college_matches[0][0]); 
    println(""); 
    
    // 6. Decrypt and verify student matches 
    let decrypted_student_matches = decrypt_student_matches(encrypted_results, student_private_keys); 
    println("Decrypted student matches:"); 
    println(decrypted_student_matches); 
    println(""); 
    
    // 7. Verify that decrypted matches match expected results 
    assert(decrypted_student_matches == stable_matches); 
    
    // 8. Decrypt and verify college matches 
    let decrypted_college_matches = decrypt_college_matches(encrypted_results, college_private_keys, college_capacities); 
    
    println("Decrypted college matches (college_id -> [student_ids]):"); 
    for c in 0..3 { // Only the active colleges 
        println("College"); 
        println(c); 
        println(": "); 
        println(decrypted_college_matches[c]); 
    } 
    
    println(""); 
    println("=== Test completed successfully ==="); 
} 