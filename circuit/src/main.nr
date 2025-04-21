global N_STUDENT_PREFERENCE: u32 = 5;
global N_COLLEGE_QUOTA: u32 = 5;
global MAX_PREFS: u32 = 5;
global MAX_COLLEGE_CAPACITY: u32 = 3;   // upper bound for any college quota
global ENCRYPTED_SIZE: u32 = 4;  // Size of encrypted data structure
global TOTAL_ENCRYPTIONS: u32 = N_STUDENT_PREFERENCE + (N_COLLEGE_QUOTA * MAX_COLLEGE_CAPACITY); // Max possible number of encryptions

global UNMATCHED: u32 = 999;

use std::hash::hash_to_field;

fn encrypt(message: u32, recipient_id: u32, public_key: Field) -> [Field; 4] {
    // Create a unique nonce from the recipient ID
    let nonce = hash_to_field([recipient_id as Field]);

    // Combine message with public key to create ciphertext
    let message_field = message as Field;
    let combined = hash_to_field([message_field, public_key]);

    // Create encrypted structure: [recipient_id, encrypted data, nonce, verification]
    let verification = hash_to_field([message_field, nonce, public_key]);

    [recipient_id as Field, combined, nonce, verification]
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
    actual_uni_list: u32
) -> pub [[Field; ENCRYPTED_SIZE]; TOTAL_ENCRYPTIONS] {
    // 1. Calculate the matching internally - NOT exposed publicly
    let matches = stable_matching(student_prefs, college_prefs, college_capacities, 
                               actual_student_list, actual_uni_list);
    
    // 2. Encrypt each match for the appropriate recipients
    let mut encrypted_matches = [[0 as Field; ENCRYPTED_SIZE]; TOTAL_ENCRYPTIONS];
    let mut enc_idx = 0;
    
    // Encrypt for students - each student gets their matched college
    for s in 0..N_STUDENT_PREFERENCE {
        if s < actual_student_list {
            let matched_college = matches[s];
            encrypted_matches[enc_idx] = encrypt(matched_college, s, student_public_keys[s]);
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
                        encrypted_matches[enc_idx] = encrypt(s, N_STUDENT_PREFERENCE + c, college_public_keys[c]);
                        enc_idx += 1;
                        count += 1;
                    }
                }
            }
            
            // Pad with dummy entries to hide the number of matches
            for _ in 0..MAX_COLLEGE_CAPACITY {
                if count < college_capacities[c] {
                    encrypted_matches[enc_idx] = encrypt(UNMATCHED, N_STUDENT_PREFERENCE + c, college_public_keys[c]);
                    enc_idx += 1;
                    count += 1;
                }
            }
        }
    }
    
    // Fill remaining slots with dummy data
    for i in 0..TOTAL_ENCRYPTIONS {
        if i >= enc_idx {
            encrypted_matches[i] = [0 as Field, 0 as Field, 0 as Field, 0 as Field];
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
    
    // Mock public keys (would be provided by participants in real system)
    let student_public_keys: [Field; N_STUDENT_PREFERENCE] = [
        1 as Field, 2 as Field, 3 as Field, 4 as Field, 5 as Field
    ];
    
    let college_public_keys: [Field; N_COLLEGE_QUOTA] = [
        101 as Field, 102 as Field, 103 as Field, 104 as Field, 105 as Field
    ];

    let encrypted_results = main(
        student_prefs, 
        college_prefs, 
        college_capacities, 
        student_public_keys,
        college_public_keys,
        5, 
        3
    );
    
    // This only prints the recipient IDs - the actual matches remain encrypted
    println("Encrypted matches (only recipient IDs shown):");
    for i in 0..10 {
        println(encrypted_results[i][0]); 
    }
}