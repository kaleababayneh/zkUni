// Constants for zkUni matching system
global N_STUDENT_PREFERENCE: u32 = 5;
global N_COLLEGE_QUOTA: u32 = 5;
global MAX_PREFS: u32 = 5;
global MAX_COLLEGE_CAPACITY: u32 = 3;   // upper bound for any college quota
global ENCRYPTED_SIZE: u32 = 4;  // Size of encrypted data structure
global TOTAL_ENCRYPTIONS: u32 = N_STUDENT_PREFERENCE + (N_COLLEGE_QUOTA * MAX_COLLEGE_CAPACITY); // Max possible number of encryptions

global UNMATCHED: u32 = 999;

use dep::std::hash::poseidon::Poseidon;

// Hash all the inputs using poseidon to create a commitment
fn commit_inputs(
    student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE],
    college_prefs: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA],
    capacities: [u32; N_COLLEGE_QUOTA]
) -> Field {
    let mut poseidon = Poseidon::new();
    
    // Hash student preferences (5×5)
    for s in 0..N_STUDENT_PREFERENCE {
        for p in 0..MAX_PREFS {
            poseidon.update(student_prefs[s][p] as Field);
        }
    }
    
    // Hash college preferences (5×5)
    for c in 0..N_COLLEGE_QUOTA {
        for p in 0..N_STUDENT_PREFERENCE {
            poseidon.update(college_prefs[c][p] as Field);
        }
    }
    
    // Hash capacities (5)
    for c in 0..N_COLLEGE_QUOTA {
        poseidon.update(capacities[c] as Field);
    }
    
    poseidon.finalize()
}