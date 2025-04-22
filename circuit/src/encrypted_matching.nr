// Encrypted matching implementation for zkUni
use crate::constants::{N_STUDENT_PREFERENCE, N_COLLEGE_QUOTA, MAX_PREFS, MAX_COLLEGE_CAPACITY, ENCRYPTED_SIZE, TOTAL_ENCRYPTIONS, UNMATCHED, commit_inputs};
use crate::gadgets::{mask, encrypt_u32};
use crate::stable_matching::stable_matching;

fn main(
    student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE],
    college_prefs: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA],
    college_capacities: [u32; N_COLLEGE_QUOTA],
    student_public_keys: [Field; N_STUDENT_PREFERENCE],
    college_public_keys: [Field; N_COLLEGE_QUOTA],
    actual_student_list: u32,
    actual_uni_list: u32,
    nonce_stu: [Field; 5],
    nonce_col: [Field; 15],
    instance_H: pub Field
) -> pub [Field; TOTAL_ENCRYPTIONS * 4] {
    // 1. Calculate the hash commitment of all inputs
    let hash = commit_inputs(student_prefs, college_prefs, college_capacities);
    
    // 2. Assert that the hash matches the public input instance_H
    assert(hash == instance_H);
    
    // 3. Calculate the matching
    let matches = stable_matching(student_prefs, college_prefs, college_capacities, 
                               actual_student_list, actual_uni_list);
    
    // 4. Encrypt each match for the appropriate recipients
    let mut encrypted_matches = [[0 as Field; ENCRYPTED_SIZE]; TOTAL_ENCRYPTIONS];
    let mut enc_idx = 0;
    
    // Encrypt for students - each student gets their matched college
    for s in 0..N_STUDENT_PREFERENCE {
        if s < actual_student_list {
            let matched_college = matches[s];
            encrypted_matches[enc_idx] = encrypt_u32(matched_college, student_public_keys[s], college_public_keys[matched_college], nonce_stu[s]);
            enc_idx += 1;
        }
    }
    
    // Encrypt for colleges - each college gets its matched students
    for c in 0..N_COLLEGE_QUOTA {
        if c < actual_uni_list {
            let mut count = 0;
            let mut nonce_idx = 0;
            
            // Find all students matched to this college
            for s in 0..N_STUDENT_PREFERENCE {
                if s < actual_student_list {
                    if matches[s] == c {
                        let nonce_index = c * MAX_COLLEGE_CAPACITY + nonce_idx;
                        encrypted_matches[enc_idx] = encrypt_u32(s, student_public_keys[s], college_public_keys[c], nonce_col[nonce_index]);
                        enc_idx += 1;
                        count += 1;
                        nonce_idx += 1;
                    }
                }
            }
            
            // Pad with dummy entries to hide the number of matches
            for i in 0..MAX_COLLEGE_CAPACITY {
                if count < college_capacities[c] {
                    let nonce_index = c * MAX_COLLEGE_CAPACITY + nonce_idx;
                    encrypted_matches[enc_idx] = encrypt_u32(UNMATCHED, 0 as Field, college_public_keys[c], nonce_col[nonce_index]);
                    enc_idx += 1;
                    count += 1;
                    nonce_idx += 1;
                }
            }
        }
    }
    
    // 5. Fill remaining slots with dummy data
    for i in 0..TOTAL_ENCRYPTIONS {
        if i >= enc_idx {
            encrypted_matches[i] = [0 as Field, 0 as Field, 0 as Field, 0 as Field];
        }
    }
    
    // 6. Flatten the encrypted matches array for return
    let mut flattened = [0 as Field; TOTAL_ENCRYPTIONS * 4];
    for i in 0..TOTAL_ENCRYPTIONS {
        for j in 0..4 {
            flattened[i * 4 + j] = encrypted_matches[i][j];
        }
    }
    
    flattened
}