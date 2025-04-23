mod elgamal;

global N_STUDENT_PREFERENCE: u32 = 5;
global N_COLLEGE_QUOTA: u32 = 5;
global MAX_PREFS: u32 = 5;
global MAX_COLLEGE_CAPACITY: u32 = 3;   // upper bound for any college quota
global ENCRYPTED_SIZE: u32 = 4;  // Size of encrypted data structure
global TOTAL_ENCRYPTIONS: u32 = N_STUDENT_PREFERENCE + (N_COLLEGE_QUOTA * MAX_COLLEGE_CAPACITY); // Max possible number of encryptions
global UNMATCHED: u32 = 999;
global BITS_DL: u32 = 16; 

use std::hash::hash_to_field;
use crate::elgamal::{ElGamalCiphered, EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul};

// Updated encryption function using secure ElGamal encryption
fn encrypt_elgamal(
    message: u32, 
    public_key: EmbeddedCurvePoint, 
    encryption_index: u32,  // Unique index for this encryption
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


// fn test_encrypted_matching() {
//     let student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE] = [
//         [0, 1, 2, UNMATCHED, UNMATCHED], 
//         [1, 0, 2, UNMATCHED, UNMATCHED], 
//         [1, 2, 0, UNMATCHED, UNMATCHED], 
//         [0, 2, 1, UNMATCHED, UNMATCHED], 
//         [2, 0, 1, UNMATCHED, UNMATCHED], 
//     ];

//     let college_prefs: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA] = [
//         [1, 3, 0, 2, 4],   
//         [2, 0, 4, 1, 3],   
//         [0, 2, 3, 4, 1],   
//         [UNMATCHED; N_STUDENT_PREFERENCE], 
//         [UNMATCHED; N_STUDENT_PREFERENCE], 
//     ];

//     let college_capacities: [u32; N_COLLEGE_QUOTA] = [3, 1, 1, 0, 0];
    
//     // Using smaller key hash values that fit within Field limits
//     let student_public_keys: [Field; N_STUDENT_PREFERENCE] = [
//         0x7d1e5f02b0cdc7e10cff917625b4e7ee as Field,
//         0x83a1eff0b6627a69b41c5de7b0aeb8e3 as Field,
//         0x9c4d8bfd9d4def4eeb1615aa53a32e30 as Field,
//         0xa0b3576ee834936135b547beba820d6f as Field,
//         0xb4f0c6f7d89513c2055c54bd463a5275 as Field
//     ];
    
//     let college_public_keys: [Field; N_COLLEGE_QUOTA] = [
//         0xc78e07db0ad00f15ebde45d9afd043e4 as Field,
//         0xd391cafa15d22c96a28afa0375ea8db7 as Field,
//         0xe2e3aa9a63b2b855d7c81c9f60e9c411 as Field,
//         0xf4b8dff2bb2a889432d097b3fb781c54 as Field,
//         0x052968bd5e7e3d743d45cb45e7ca1bf7 as Field
//     ];
    
//     // Add a nonce seed for testing
//     let nonce_seed = 0x12345678 as Field;

//     let encrypted_results = main(
//         student_prefs, 
//         college_prefs, 
//         college_capacities, 
//         student_public_keys,
//         college_public_keys,
//         5, 
//         3,
//         nonce_seed  // Pass the nonce seed
//     );
//     println("\n==== ENCRYPTED MATCHING TEST ====");
//     println(encrypted_results);
//     println("\n==== ENCRYPTED MATCHING TEST ====");
//     // Test verification - examine a few encrypted values
//     println("Encrypted matching test completed");
//     println(TOTAL_ENCRYPTIONS);
    
//     // Verify that we have some non-infinity values
//     let has_real_values = encrypted_results[0].c1 != EmbeddedCurvePoint::point_at_infinity();
//     println(has_real_values);
    
//     // Verify encryption properties
//     println("\nVerifying encryption security properties:");
    
//     // Test that encrypting the same message twice produces different ciphertexts
//     let test_message = 1;
//     let test_key = field_to_curve_point(student_public_keys[0]);
    
//     let cipher1 = encrypt_elgamal(test_message, test_key, 100, nonce_seed);
//     let cipher2 = encrypt_elgamal(test_message, test_key, 101, nonce_seed);
    
// }

// #[test]
// fn test_encrypted_matching_fixed() {
//     // Student preferences (rows = students, columns = their college choices in order)
//     let student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE] = [
//         [0, 1, 2, UNMATCHED, UNMATCHED], // Student 0 prefers College 0, then 1, then 2
//         [1, 0, 2, UNMATCHED, UNMATCHED], // Student 1 prefers College 1, then 0, then 2
//         [1, 2, 0, UNMATCHED, UNMATCHED], // Student 2 prefers College 1, then 2, then 0
//         [0, 2, 1, UNMATCHED, UNMATCHED], // Student 3 prefers College 0, then 2, then 1
//         [2, 0, 1, UNMATCHED, UNMATCHED], // Student 4 prefers College 2, then 0, then 1
//     ];

//     // College preferences (rows = colleges, columns = their student preferences in order)
//     let college_prefs: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA] = [
//         [1, 3, 0, 2, 4],   // College 0 prefers Students 1, 3, 0, 2, 4 (in that order)
//         [2, 0, 4, 1, 3],   // College 1 prefers Students 2, 0, 4, 1, 3
//         [0, 2, 3, 4, 1],   // College 2 prefers Students 0, 2, 3, 4, 1
//         [UNMATCHED; N_STUDENT_PREFERENCE], // College 3 has no preferences (not used)
//         [UNMATCHED; N_STUDENT_PREFERENCE], // College 4 has no preferences (not used)
//     ];

//     // College capacities (how many students each can accept)
//     let college_capacities: [u32; N_COLLEGE_QUOTA] = [3, 1, 1, 0, 0];
    
//     println("\n======= ZK UNIVERSITY MATCHING PROTOCOL TEST =======");
//     println("\nSETUP PARAMETERS:");
//     println("Number of students: 5");
//     println("Number of colleges: 3 (with capacities 3, 1, 1)");
    
//     // STEP 1: Generate very small private keys for testing
//     let student_private_keys: [Field; N_STUDENT_PREFERENCE] = [
//         0x3 as Field,
//         0x4 as Field,
//         0x5 as Field,
//         0x6 as Field,
//         0x7 as Field
//     ];
    
//     let college_private_keys: [Field; N_COLLEGE_QUOTA] = [
//         0x8 as Field,
//         0x9 as Field,
//         0xA as Field,
//         0xB as Field,
//         0xC as Field
//     ];
    
//     // STEP 2: Create public keys by directly generating EmbeddedCurvePoints
//     // and storing the Fields that created them for main()
//     let mut student_curve_points: [EmbeddedCurvePoint; N_STUDENT_PREFERENCE] = 
//         [EmbeddedCurvePoint::point_at_infinity(); N_STUDENT_PREFERENCE];
//     let mut college_curve_points: [EmbeddedCurvePoint; N_COLLEGE_QUOTA] = 
//         [EmbeddedCurvePoint::point_at_infinity(); N_COLLEGE_QUOTA];
    
//     // We'll also need Field versions for passing to main()
//     let mut student_public_keys: [Field; N_STUDENT_PREFERENCE] = [0; N_STUDENT_PREFERENCE];
//     let mut college_public_keys: [Field; N_COLLEGE_QUOTA] = [0; N_COLLEGE_QUOTA];
    
//     // Generate curve points for students and store original Field values
//     for i in 0..N_STUDENT_PREFERENCE {
//         student_curve_points[i] = field_to_curve_point(student_private_keys[i]);
//         // Use the original private key as the "public key" to ensure consistency
//         student_public_keys[i] = student_private_keys[i]; 
//     }
    
//     // Generate curve points for colleges and store original Field values
//     for i in 0..N_COLLEGE_QUOTA {
//         college_curve_points[i] = field_to_curve_point(college_private_keys[i]);
//         // Use the original private key as the "public key" to ensure consistency
//         college_public_keys[i] = college_private_keys[i];
//     }
    
//     // Global randomness seed for encryption
//     let nonce_seed = 0x12 as Field;
    
//     // STEP 3: Verify basic encryption/decryption works with our key setup
//     println("\nVERIFYING ELGAMAL ENCRYPTION & DECRYPTION:");
    
//     // Test with a simple message for each student
//     for i in 0..N_STUDENT_PREFERENCE {
//         let test_message = i as u32 + 1; // Simple test message (1, 2, 3, 4, 5)
        
//         // Encrypt the message
//         let ciphertext = encrypt_elgamal(
//             test_message,
//             student_curve_points[i],
//             100 + i as u32, // Unique encryption index
//             nonce_seed
//         );
        
//         // Decrypt the message
//         let private_scalar = EmbeddedCurveScalar::from_field(student_private_keys[i]);
//         let decrypted_message = ciphertext.decrypt_to_scalar(private_scalar) as u32;
        
//         println("Student");
//         println(i);
//         println("message");
//         println(test_message);
//         println("decrypted:");
//         println(decrypted_message);
        
//         // Verify decryption works
//         assert(decrypted_message == test_message, 
//                "Failed basic encryption/decryption test for student");
//     }
    
//     println("Basic encryption/decryption tests passed!");
    
//     // STEP 4: Run the full matching algorithm
//     println("\n1. RUNNING STABLE MATCHING ALGORITHM (not visible to participants)");
    
//     // Run the matching algorithm and encrypt results
//     let encrypted_results = main(
//         student_prefs, 
//         college_prefs, 
//         college_capacities, 
//         student_public_keys, // Use the original private keys as "public keys"
//         college_public_keys, // This ensures consistency between encryption and decryption
//         5,  // Number of students
//         3,  // Number of colleges
//         nonce_seed
//     );
    
//     println("\n2. ENCRYPTED MATCHES GENERATED");
//     println("Total number of encrypted entries:");
//     println(TOTAL_ENCRYPTIONS);
    
//     // Verify that we have non-infinity values (encryption worked)
//     let has_real_values = encrypted_results[0].c1 != EmbeddedCurvePoint::point_at_infinity();
//     println("Contains valid encryptions:");
//     println(has_real_values);
    
//     println("\n3. PARTICIPANTS DOWNLOAD ENCRYPTED MATCHES");
//     println("(Each participant can only decrypt their own matches)");
    
//     // STEP 5: Demonstrate decryption for students
//     println("\n4. STUDENTS DECRYPT THEIR MATCHES");
    
//     for student_id in 0..N_STUDENT_PREFERENCE {
//         // Each student decrypts their matched college
//         let private_scalar = EmbeddedCurveScalar::from_field(student_private_keys[student_id]);
//         let matched_college_id = encrypted_results[student_id].decrypt_to_scalar(private_scalar) as u32;
        
//         println("Student");
//         println(student_id);
//         println("is matched to:");
        
//         if matched_college_id == UNMATCHED {
//             println("UNMATCHED (no college)");
//         } else {
//             println("College");
//             println(matched_college_id);
//         }
//     }
    
//     // STEP 6: Demonstrate decryption for colleges
//     println("\n5. COLLEGES DECRYPT THEIR MATCHES");
    
//     // College matches start after all student matches
//     let college_start_idx = N_STUDENT_PREFERENCE;
//     let mut current_idx = college_start_idx;
    
//     for college_id in 0..3 { // Only for active colleges (0, 1, 2)
//         let capacity = college_capacities[college_id];
//         println("College");
//         println(college_id);
//         println("(capacity");
//         println(capacity);
//         println(") matched with:");
        
//         let private_scalar = EmbeddedCurveScalar::from_field(college_private_keys[college_id]);
        
//         // Decrypt all slots for this college
//         for slot in 0..capacity {
//             let matched_student_id = encrypted_results[current_idx].decrypt_to_scalar(private_scalar) as u32;
            
//             if matched_student_id == UNMATCHED {
//                 println("- Empty slot (no student)");
//             } else {
//                 println("- Student");
//                 println(matched_student_id);
//             }
            
//             current_idx += 1;
//         }
//     }
    
//     // STEP 7: Verify encryption security properties
//     println("\n6. VERIFYING ENCRYPTION SECURITY PROPERTIES");
    
//     // Test that encrypting the same message twice with different indices produces different ciphertexts
//     let test_message = 1;
//     let test_key = student_curve_points[0]; // Use the actual curve point directly
    
//     let cipher1 = encrypt_elgamal(test_message, test_key, 100, nonce_seed);
//     let cipher2 = encrypt_elgamal(test_message, test_key, 101, nonce_seed);
    
//     let different_ciphertexts = 
//         (cipher1.c1.x != cipher2.c1.x) | 
//         (cipher1.c1.y != cipher2.c1.y) | 
//         (cipher1.c2.x != cipher2.c2.x) | 
//         (cipher1.c2.y != cipher2.c2.y);
    
//     println("Same message encrypts to different ciphertexts:");
//     println(different_ciphertexts);
    
//     println("\n7. SUMMARY OF SECURITY GUARANTEES");
//     println("- Matching algorithm runs in zero-knowledge (inputs and outputs private)");
//     println("- Each participant can only decrypt their own matches");
//     println("- Same message encrypts to different ciphertexts each time");
//     println("- Observers cannot tell which students matched with which colleges");
    
//     // Verify the test was successful
//     assert(has_real_values);
//     assert(different_ciphertexts);
    
//     println("\n======= TEST COMPLETED SUCCESSFULLY =======");
// }

// #[test]
// fn test_encrypted_matching_fixed() {
//     // Student and college preferences remain the same...
//     let student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE] = [
//         [0, 1, 2, UNMATCHED, UNMATCHED], // Student 0 prefers College 0, then 1, then 2
//         [1, 0, 2, UNMATCHED, UNMATCHED], // Student 1 prefers College 1, then 0, then 2
//         [1, 2, 0, UNMATCHED, UNMATCHED], // Student 2 prefers College 1, then 2, then 0
//         [0, 2, 1, UNMATCHED, UNMATCHED], // Student 3 prefers College 0, then 2, then 1
//         [2, 0, 1, UNMATCHED, UNMATCHED], // Student 4 prefers College 2, then 0, then 1
//     ];

//     let college_prefs: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA] = [
//         [1, 3, 0, 2, 4],   // College 0 prefers Students 1, 3, 0, 2, 4 (in that order)
//         [2, 0, 4, 1, 3],   // College 1 prefers Students 2, 0, 4, 1, 3
//         [0, 2, 3, 4, 1],   // College 2 prefers Students 0, 2, 3, 4, 1
//         [UNMATCHED; N_STUDENT_PREFERENCE], // College 3 has no preferences (not used)
//         [UNMATCHED; N_STUDENT_PREFERENCE], // College 4 has no preferences (not used)
//     ];

//     let college_capacities: [u32; N_COLLEGE_QUOTA] = [3, 1, 1, 0, 0];

//     println("\n======= ZK UNIVERSITY MATCHING PROTOCOL TEST =======");
//     println("\nSETUP PARAMETERS:");
//     println("Number of students: 5");
//     println("Number of colleges: 3 (with capacities 3, 1, 1)");

//     // STEP 1: Generate mocked private keys and corresponding public keys
//     let student_private_keys: [Field; N_STUDENT_PREFERENCE] = [
//         0x1 as Field, // Mocked private key for Student 0
//         0x2 as Field, // Mocked private key for Student 1
//         0x3 as Field, // Mocked private key for Student 2
//         0x4 as Field, // Mocked private key for Student 3
//         0x5 as Field  // Mocked private key for Student 4
//     ];

//     let college_private_keys: [Field; N_COLLEGE_QUOTA] = [
//         0x6 as Field, // Mocked private key for College 0
//         0x7 as Field, // Mocked private key for College 1
//         0x8 as Field, // Mocked private key for College 2
//         0x9 as Field, // Mocked private key for College 3
//         0xA as Field  // Mocked private key for College 4
//     ];

//     let mut student_public_keys: [Field; N_STUDENT_PREFERENCE] = [0; N_STUDENT_PREFERENCE];
//     let mut college_public_keys: [Field; N_COLLEGE_QUOTA] = [0; N_COLLEGE_QUOTA];

//     for i in 0..N_STUDENT_PREFERENCE {
//         student_public_keys[i] = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(student_private_keys[i])).x;
//     }

//     for i in 0..N_COLLEGE_QUOTA {
//         college_public_keys[i] = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(college_private_keys[i])).x;
//     }

//     // Simple nonce seed
//     let nonce_seed = 0x1 as Field;

//     // STEP 2: Run the main function
//     let encrypted_results = main(
//         student_prefs,
//         college_prefs,
//         college_capacities,
//         student_public_keys,
//         college_public_keys,
//         5, // Number of students
//         3, // Number of colleges
//         nonce_seed
//     );

//     println("\nEncrypted results generated. Attempting decryption:");

//     // STEP 3: Decrypt and verify results for students
//     for i in 0..N_STUDENT_PREFERENCE {
//         let private_scalar = EmbeddedCurveScalar::from_field(student_private_keys[i]);
//         let decrypted_college = encrypted_results[i].decrypt_to_scalar(private_scalar) as u32;

//         println("Student");
//         println(i);
//         println("matched with college:");
//         if decrypted_college == UNMATCHED {
//             println("UNMATCHED");
//         } else {
//             println(decrypted_college);
//         }
//     }

//     println("\nDecryption for students completed successfully!");

//     // STEP 4: Decrypt and verify results for colleges
//     let mut current_idx = N_STUDENT_PREFERENCE;
//     for c in 0..3 { // Only for active colleges (0, 1, 2)
//         let private_scalar = EmbeddedCurveScalar::from_field(college_private_keys[c]);

//         println("College");
//         println(c);
//         println("matched with students:");

//         for _ in 0..college_capacities[c] {
//             let decrypted_student = encrypted_results[current_idx].decrypt_to_scalar(private_scalar) as u32;

//             if decrypted_student == UNMATCHED {
//                 println("- Empty slot (no student)");
//             } else {
//                 println("- Student");
//                 println(decrypted_student);
//             }

//             current_idx += 1;
//         }
//     }

//     println("\nDecryption for colleges completed successfully!");

//     println("\n======= TEST COMPLETED SUCCESSFULLY =======");
// }
// #[test]
// fn test_super_minimal_elgamal() {
//     // The smallest possible private key
//     let private_key = 0x1 as Field;
    
//     // Convert to scalar directly
//     let scalar = EmbeddedCurveScalar::from_field(private_key);
    
//     // Generate public key point
//     let public_key = fixed_base_scalar_mul(scalar);
    
//     println("PUBLIC KEY GENERATED:");
//     println(public_key.x);
//     println(public_key.y);
    
//     // Extremely simple message - just 1
//     let message = 1;
//     println("MESSAGE TO ENCRYPT:");
//     println(message);
    
//     // Simplest possible encryption parameters
//     let encryption_index = 1 as u32;
//     let nonce_seed = 0x1 as Field;
    
//     // Debug the encryption
//     println("ATTEMPTING ENCRYPTION");
    
//     // Create randomness with very specific seed
//     let randomness_seed = hash_to_field([
//         message as Field, 
//         public_key.x, 
//         public_key.y, 
//         encryption_index as Field,
//         nonce_seed
//     ]);
    
//     println("RANDOMNESS SEED:");
//     println(randomness_seed);
    
//     // Create scalar from randomness
//     let randomness = EmbeddedCurveScalar::from_field(randomness_seed);
    
//     // Temporary debugging: don't use the full encryption, just check if the curve operations work
//     println("TESTING BASIC CURVE OPERATIONS:");
    
//     // Test if fixed_base_scalar_mul works with this randomness
//     let r_point = fixed_base_scalar_mul(randomness);
//     println("r_point.x:");
//     println(r_point.x);
//     println("r_point.y:");
//     println(r_point.y);
    
//     // If we got here, the test passed the first stage
//     println("Basic curve operations test passed!");
    
//     // Now try a full encryption
//     println("ATTEMPTING FULL ENCRYPTION");
//     let ciphertext = ElGamalCiphered::<BITS_DL>::new(public_key, message as Field, randomness);
    
//     println("ENCRYPTION SUCCESSFUL!");
//     println("c1.x:");
//     println(ciphertext.c1.x);
//     println("c1.y:");
//     println(ciphertext.c1.y);
//     println("c2.x:");
//     println(ciphertext.c2.x);
//     println("c2.y:");
//     println(ciphertext.c2.y);
    
//     // Try decryption
//     println("ATTEMPTING DECRYPTION");
//     // Use a simple direct approach first
//     let decrypted = ciphertext.decrypt_to_scalar(scalar) as u32;
    
//     println("DECRYPTION SUCCESSFUL!");
//     println("Decrypted message:");
//     println(decrypted);
    
//     // Verify
//     assert(decrypted == message);
// }
// // Optional additional test to verify semantic security
// #[test]
// fn test_semantic_security() {
//     // Setup a test key
//     let key_field = 0x7d1e5f02b0cdc7e10cff917625b4e7ee as Field;
//     let test_key = field_to_curve_point(key_field);
//     let nonce_seed = 0x12345678 as Field;
    
//     // Test message
//     let message = 5;
    
//     // Encrypt the same message multiple times with different indices
//     let cipher1 = encrypt_elgamal(message, test_key, 1, nonce_seed);
//     let cipher2 = encrypt_elgamal(message, test_key, 2, nonce_seed);
//     let cipher3 = encrypt_elgamal(message, test_key, 3, nonce_seed);
    
//     // Verify all ciphertexts are different
//     let all_different = 
//         ((cipher1.c1.x != cipher2.c1.x) | (cipher1.c1.y != cipher2.c1.y)) &
//         ((cipher1.c1.x != cipher3.c1.x) | (cipher1.c1.y != cipher3.c1.y)) &
//         ((cipher2.c1.x != cipher3.c1.x) | (cipher2.c1.y != cipher3.c1.y));
    
//     println("Semantic security test (all ciphertexts should be different): ");
//     println(all_different);
// }

// // Add this new test function to your main.nr file

// fn test_elgamal_encryption_decryption() {
//     println("\n==== ELGAMAL ENCRYPTION & DECRYPTION DEMONSTRATION ====");
    
//     // Step 1: Create a private/public key pair
//     // We'll simulate a student's key pair
//     let private_scalar = 0x12345678abcdef as Field;
//     println("Private key (scalar):");
//     println(private_scalar);
    
//     // Generate the public key point
//     // In ElGamal: public_key = g^(private_key) where g is the base point
//     let public_key = field_to_curve_point(private_scalar);
//     println("Public key point x:");
//     println(public_key.x);
//     println("Public key point y:");
//     println(public_key.y);
    
//     // Step 2: Create a message to encrypt (college ID 2)
//     let message = 2;
//     println("Original message (college ID):");
//     println(message);
    
//     // Step 3: Encrypt the message using ElGamal
//     let encryption_index = 1 as u32;
//     let nonce_seed = 0x87654321 as Field;
//     println("\n--- ENCRYPTION PROCESS ---");
//     println("Using encryption index:");
//     println(encryption_index);
//     println("Using nonce seed:");
//     println(nonce_seed);
    
//     // Generate randomness from our inputs
//     let randomness_seed = hash_to_field([
//         message as Field, 
//         public_key.x, 
//         public_key.y, 
//         encryption_index as Field,
//         nonce_seed
//     ]);
//     println("Generated randomness seed:");
//     println(randomness_seed);
    
//     // Perform the encryption
//     let ciphertext = encrypt_elgamal(message, public_key, encryption_index, nonce_seed);
//     println("Encrypted ciphertext c1 x:");
//     println(ciphertext.c1.x);
//     println("Encrypted ciphertext c1 y:");
//     println(ciphertext.c1.y);
//     println("Encrypted ciphertext c2 x:");
//     println(ciphertext.c2.x);
//     println("Encrypted ciphertext c2 y:");
//     println(ciphertext.c2.y);
    
//     // Step 4: Decrypt the message
//     println("\n--- DECRYPTION PROCESS ---");
    
//     // Convert private field to EmbeddedCurveScalar for decryption
//     let private_key_scalar = EmbeddedCurveScalar::from_field(private_scalar);
    
//     // Use decrypt_to_scalar instead of decrypt
//     let recovered_message = ciphertext.decrypt_to_scalar(private_key_scalar);
//     println("Recovered message:");
//     println(recovered_message);
//     println("Decryption successful?");
//     println(recovered_message as u32 == message);
    
//     // Verify decryption works correctly
//     assert(recovered_message as u32 == message);
// }
// Optional: Add another test to demonstrate full encryption/decryption with output matching format


// #[test]
// fn test_matching_encryption_decryption() {
//     println("\n==== MATCHING PROTOCOL ENCRYPTION & DECRYPTION ====");
    
//     // Sample private keys (in a real system, each participant would have their own)
//     let student_private_key = 0x7d1e5f02b0cdc7e10cff917625b4e7ee as Field;
//     let college_private_key = 0xc78e07db0ad00f15ebde45d9afd043e4 as Field;
    
//     // Generate public keys
//     let student_public_key = field_to_curve_point(student_private_key);
//     let college_public_key = field_to_curve_point(college_private_key);
    
//     println(  "Student public key: ");
//     println( student_public_key.x);
//     println(student_public_key.y);
//     println("  College public key: ");
//     println(college_public_key.x);
//     println(college_public_key.y);
    
//     // Sample matching output: Student 0 matched to College 2
//     let student_id = 0;
//     let college_id = 2;
//     let nonce_seed = 0x12345678 as Field;
    
//     // Encrypt the college ID for the student
//     let encryption_index = 42; // Arbitrary unique index
//     println("\nEncrypting college ID {} for student {}...");
//     println(college_id);
//     println(student_id);
    
//     let encrypted_college = encrypt_elgamal(
//         college_id, 
//         student_public_key,
//         encryption_index,
//         nonce_seed
//     );
    
//     // Encrypt the student ID for the college
//     let encryption_index2 = 43; // Different index
//     println("Encrypting student ID {} for college {}...")
//     println(student_id);
//     println(college_id);

//     let encrypted_student = encrypt_elgamal(
//         student_id, 
//         college_public_key,
//         encryption_index2,
//         nonce_seed
//     );
    
//     // Display encrypted matches format (as they would appear in the output array)
//     println("\nEncrypted matches (array elements):");
//     println("[0]: Student");
//     println(student_id);
//     println("-> Encrypted College ID");
    
//     println("  c1:");
//     println( encrypted_college.c1.x);
    
//     println(encrypted_college.c1.y);
//     println("  c2:");
//     println( encrypted_college.c2.x);
//     println( encrypted_college.c2.y);
    
//     println("[1]: College");
//     println(college_id);
//     println("-> Encrypted Student ID");
    
//     println("  c1:");
//     println(encrypted_student.c1.x);
//     println(encrypted_student.c1.y);
//     println("  c2:");
//     println(encrypted_student.c2.x)
//     println(encrypted_student.c2.y);
    
//     // Demonstrate decryption (simulating what would happen on client side)
//     println("\nDecryption demonstration:");
    
//     // Student decrypts their match
//     let student_private_scalar = EmbeddedCurveScalar::from_field(student_private_key);
    
//     // Calculate shared secret: s = private_key * c1
//     let shared_secret1 = encrypted_college.c1.scalar_mul(student_private_scalar);
    
//     // Calculate message point: m*g = c2 - s
//     let negated_secret1 = shared_secret1.neg();
//     let message_point1 = encrypted_college.c2.add(negated_secret1);
    
//     // Find the discrete log (which college ID)
//     let mut recovered_college_id = UNMATCHED;
//     for i in 0..5 {  // Try college IDs 0-4
//         let test_scalar = EmbeddedCurveScalar::from_field(i as Field);
//         let test_point = fixed_base_scalar_mul(test_scalar);
        
//         if (test_point.x == message_point1.x) & (test_point.y == message_point1.y) {
//             recovered_college_id = i;
//             break;
//         }
//     }
    
//     // College decrypts their match (same process)
//     let college_private_scalar = EmbeddedCurveScalar::from_field(college_private_key);
//     let shared_secret2 = encrypted_student.c1.scalar_mul(college_private_scalar);
//     let negated_secret2 = shared_secret2.neg();
//     let message_point2 = encrypted_student.c2.add(negated_secret2);
    
//     let mut recovered_student_id = UNMATCHED;
//     for i in 0..5 {  // Try student IDs 0-4
//         let test_scalar = EmbeddedCurveScalar::from_field(i as Field);
//         let test_point = fixed_base_scalar_mul(test_scalar);
        
//         if (test_point.x == message_point2.x) & (test_point.y == message_point2.y) {
//             recovered_student_id = i;
//             break;
//         }
//     }
    
//     println("Student {} decrypted their match: College {}");
//     println(student_id);
//     println(recovered_college_id);
//     println("College {} decrypted their match: Student {}");
//     println(college_id);
//     println( recovered_student_id);
    
//     // Verify decryption worked correctly
//     assert(recovered_college_id == college_id);
//     assert(recovered_student_id == student_id);
// }

// #[test]
// fn test_matching_encryption_decryption() {
//     println("\n==== MATCHING PROTOCOL ENCRYPTION & DECRYPTION ====");
    
//     // Sample private keys (in a real system, each participant would have their own)
//     let student_private_key = 0x7d1e5f02b0cdc7e10cff917625b4e7ee as Field;
//     let college_private_key = 0xc78e07db0ad00f15ebde45d9afd043e4 as Field;
    
//     // Generate public keys
//     let student_public_key = field_to_curve_point(student_private_key);
//     let college_public_key = field_to_curve_point(college_private_key);
    
//     println("Student public key: ");
//     println(student_public_key.x);
//     println(student_public_key.y);
//     println("College public key: ");
//     println(college_public_key.x);
//     println(college_public_key.y);
    
//     // Sample matching output: Student 0 matched to College 2
//     let student_id = 0;
//     let college_id = 2;
//     let nonce_seed = 0x12345678 as Field;
    
//     // Encrypt the college ID for the student
//     let encryption_index = 42; // Arbitrary unique index
//     println("\nEncrypting college ID for student:");
//     println(college_id);
//     println(student_id);
    
//     let encrypted_college = encrypt_elgamal(
//         college_id, 
//         student_public_key,
//         encryption_index,
//         nonce_seed
//     );
    
//     // Encrypt the student ID for the college
//     let encryption_index2 = 43; // Different index
//     println("Encrypting student ID for college:");
//     println(student_id);
//     println(college_id);

//     let encrypted_student = encrypt_elgamal(
//         student_id, 
//         college_public_key,
//         encryption_index2,
//         nonce_seed
//     );
    
//     // Display encrypted matches format (as they would appear in the output array)
//     println("\nEncrypted matches (array elements):");
//     println("[0]: Student");
//     println(student_id);
//     println("-> Encrypted College ID");
    
//     println("  c1:");
//     println(encrypted_college.c1.x);
//     println(encrypted_college.c1.y);
//     println("  c2:");
//     println(encrypted_college.c2.x);
//     println(encrypted_college.c2.y);
    
//     println("[1]: College");
//     println(college_id);
//     println("-> Encrypted Student ID");
    
//     println("  c1:");
//     println(encrypted_student.c1.x);
//     println(encrypted_student.c1.y);
//     println("  c2:");
//     println(encrypted_student.c2.x);
//     println(encrypted_student.c2.y);
    
//     // Demonstrate decryption (simulating what would happen on client side)
//     println("\nDecryption demonstration:");
    
//     // Since we can't directly use scalar_mul and neg methods, we'll use decrypt_to_scalar
//     // Use the appropriate private keys to decrypt
//     let student_private_scalar = EmbeddedCurveScalar::from_field(student_private_key);
//     let recovered_college_id = encrypted_college.decrypt_to_scalar(student_private_scalar) as u32;
    
//     let college_private_scalar = EmbeddedCurveScalar::from_field(college_private_key);
//     let recovered_student_id = encrypted_student.decrypt_to_scalar(college_private_scalar) as u32;
    
//     println("Student decrypted their match - College:");
//     println(student_id);
//     println(recovered_college_id);
//     println("College decrypted their match - Student:");
//     println(college_id);
//     println(recovered_student_id);
    
//     // Verify decryption worked correctly
//     assert(recovered_college_id == college_id);
//     assert(recovered_student_id == student_id);
// }

// fn test_elgamal_minimal() {
//     let private_scalar = 0x12345678 as Field;
//     let public_key = field_to_curve_point(private_scalar);
    
//     let message = 2;
//     let encryption_index = 1 as u32;
//     let nonce_seed = 0x456 as Field;
    
//     let ciphertext = encrypt_elgamal(message, public_key, encryption_index, nonce_seed);
    
//     let private_key_scalar = EmbeddedCurveScalar::from_field(private_scalar);
//     let recovered_message = ciphertext.decrypt_to_scalar(private_key_scalar);
    
//     assert(recovered_message as u32 == message);
//     println("Test passed - message encrypted and decrypted correctly");
//     println("Original message:");
//     println(message);
//     println("Recovered message:");
//     println(recovered_message);
// }


#[test]
fn test_elgamal_super_minimal() {
    // Use tiny values 
    let private_scalar = 0x0bc602b9b5eefc24d8a85fdabc6c4cb078fb8dc54d59513bda848d1db8054abf as Field;  // Tiny key

    // 1Private Key: 0x093a81d401cfe73de66d1358d21ee33c7bd99bff5746efe49bbfcc6fc417e9cf
    // Address: 0x4f231f90f0145ec48e542fa8ff29965c0b93fc3a

    // 2Private Key: 0x0c99cce7152015867c8fa84c37c3b30f76d771f122b22e6d415488766d3511d1
    // Address: 0x430dec00ca60cdab0dd6db83ffc43aff69cc9ff5
    
    // 3Private Key: 0x0a829d859e631467497dcd4485dd7f73d9a43e1cc0cb706dda3a90d74fcaaebf
    // Address: 0xe6257dfa04e44899dacd8aa1eca9fbc679375f7d

    // 4Private Key: 0x016ef0710bc774374f8fbf6cd3c59612ca91d2a8ae004be8f9126675f69e90c9
    // Address: 0x88c535039c9ecbc27e2d87c97bddcc52dd1fe83b

    // 5Private Key: 0x077a88196620fd122b5f9100a052d810c86e81af577059fc3319c19f248a71f2
    // Address: 0x6e100593d2411b3f093b724beeb3a252b8e6a7be
    
    let public_key = field_to_curve_point(private_scalar);
    let message = 3;  // Tiny message
    
    // Use simple encryption parameters
    let nonce_seed = 0x5 as Field;
    
    // IMPORTANT: Use ElGamalCiphered with 8 bits instead of 32!
    let randomness = EmbeddedCurveScalar::from_field(nonce_seed);
    let ciphertext = ElGamalCiphered::<8>::new(public_key, message as Field, randomness);
    
    // Convert private key to scalar and decrypt
    let private_key_scalar = EmbeddedCurveScalar::from_field(private_scalar);
    let recovered_message = ciphertext.decrypt_to_scalar(private_key_scalar);
    
    // Simple assertion
    assert(recovered_message as u32 == message);
    
    // Only print at the end after success
    println("Test passed with message:");
    println(message);
}