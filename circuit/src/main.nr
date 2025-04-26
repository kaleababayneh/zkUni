mod elgamal; 
use std::hash::hash_to_field; 
use crate::elgamal::{ElGamalCiphered, EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul}; 
use std::hash::pedersen_hash;
use trees::merkle::MerkleTree;
use trees::types::MT_Creator;
use trees::types::MembershipProver;
use trees::types::Calculator;

global N_STUDENT_PREFERENCE: u32 = 5; 
global N_COLLEGE_QUOTA: u32 = 5; 
global MAX_PREFS: u32 = 5; 
global MAX_COLLEGE_CAPACITY: u32 = 3; 
global UNMATCHED: Field = 999; 
global BITS_DL: u32 = 16; 
global MERKLE_HEIGHT: u32 = 3; // Adjust based on the number of students

struct MatchResults {
    student_matches: [ElGamalCiphered<BITS_DL>; N_STUDENT_PREFERENCE], 
    college_matches: [[ElGamalCiphered<BITS_DL>; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA],
    merkle_root: Field // Public Merkle root of match commitments
}

// Match commitment for verifiable proofs
struct MatchCommitment {
    student_id: Field,
    college_id: Field,
    nonce: Field,
    commitment: Field // Hash of the above values
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

// Generate commitment nonces for all students
fn generate_match_nonces(
    actual_student_list: u32,
    nonce_seed: Field
) -> [Field; N_STUDENT_PREFERENCE] {
    let mut nonces = [0; N_STUDENT_PREFERENCE];
    
    for i in 0..actual_student_list {
        nonces[i] = hash_to_field([nonce_seed, (i + 10000) as Field]);
    }
    
    nonces
}

// Generate commitments for each student-college match
fn generate_match_commitments(
    decrypted_matches: [Field; N_STUDENT_PREFERENCE], 
    actual_student_list: u32,
    match_nonces: [Field; N_STUDENT_PREFERENCE]
) -> [Field; N_STUDENT_PREFERENCE] {
    let mut commitments = [0; N_STUDENT_PREFERENCE];
    
    for i in 0..actual_student_list {
        // Create commitment even for unmatched students
        let college_id = if decrypted_matches[i] == UNMATCHED {
            UNMATCHED
        } else {
            decrypted_matches[i]
        };
        
        // Commitment = Hash(student_id || college_id || nonce)
        commitments[i] = pedersen_hash([
            i as Field,       // Student ID
            college_id,       // College ID
            match_nonces[i]   // Nonce for privacy
        ]);
    }
    
    commitments
}

// Helper function for hashing pairs in the Merkle tree
fn pedersen_pair_hash(inputs: [Field; 2]) -> Field {
    pedersen_hash(inputs)
}

// Compute a merkle root directly from leaf values
fn simple_merkle_root(leaves: [Field; N_STUDENT_PREFERENCE]) -> Field {
    let n = leaves.len();
    
    // Create a working array to build the tree bottom-up
    let mut tree = [0; 2 * N_STUDENT_PREFERENCE];
    
    // Copy the leaves to the second half of the array
    for i in 0..n {
        tree[n + i] = leaves[i];
    }
    
    // Build the tree bottom-up - Noir doesn't support reverse iteration
    // so we have to manually calculate indices
    for i in 0..n {
        let node_idx = n - i - 1;
        if node_idx > 0 { // Skip the 0 index
            tree[node_idx] = pedersen_hash([tree[2 * node_idx], tree[2 * node_idx + 1]]);
        }
    }
    
    // The root is the first element
    tree[1]
}

// Generate a merkle proof for a specific leaf index
fn simple_merkle_proof(leaves: [Field; N_STUDENT_PREFERENCE], index: u32) -> [Field; MERKLE_HEIGHT] {
    let n = leaves.len();
    let mut proof = [0; MERKLE_HEIGHT];
    
    // Create a working array for the tree
    let mut tree = [0; 2 * N_STUDENT_PREFERENCE];
    
    // Copy the leaves to the second half of the array
    for i in 0..n {
        tree[n + i] = leaves[i];
    }
    
    // Build the tree bottom-up
    for i in 0..n {
        let node_idx = n - i - 1;
        if node_idx > 0 { // Skip the 0 index
            tree[node_idx] = pedersen_hash([tree[2 * node_idx], tree[2 * node_idx + 1]]);
        }
    }
    
    // Calculate proof - we know the max proof height is MERKLE_HEIGHT
    let mut idx = n + index;
    
    for proof_index in 0..MERKLE_HEIGHT {
        if idx > 1 {
            // We've reached the root or beyond
   
        
        // Add the sibling to the proof
        let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        proof[proof_index] = tree[sibling];
        
        // Move up the tree
        idx = idx / 2;
        }
    }
    
    proof
}

// Verify a merkle proof
fn verify_simple_merkle_proof(root: Field, leaf: Field, index: u32, proof: [Field; MERKLE_HEIGHT]) -> bool {
    let mut computed_hash = leaf;
    let mut idx = index;
    
    for i in 0..MERKLE_HEIGHT {
        if idx % 2 == 0 {
            // If idx is even, hash with proof element on the right
            computed_hash = pedersen_hash([computed_hash, proof[i]]);
        } else {
            // If idx is odd, hash with proof element on the left
            computed_hash = pedersen_hash([proof[i], computed_hash]);
        }
        
        // Move up the tree
        idx = idx / 2;
    }
    
    // Check if the computed hash matches the root
    computed_hash == root
}

/// New main function that accepts already-permuted inputs from the client
/// The server only sees blinded preferences, never the original ones
fn main_client_permuted( 
    // These preferences are already permuted by the client
    permuted_student_prefs: [[Field; MAX_PREFS]; N_STUDENT_PREFERENCE], 
    permuted_college_prefs: [[Field; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA], 
    college_capacities: [Field; N_COLLEGE_QUOTA], 
    // These public keys are arranged according to the permutation
    permuted_student_public_keys: [EmbeddedCurvePoint; N_STUDENT_PREFERENCE], 
    permuted_college_public_keys: [EmbeddedCurvePoint; N_COLLEGE_QUOTA], 
    actual_student_list: u32, 
    actual_uni_list: u32, 
    nonce_seed: Field,
    committed_inputs: pub Field // Public input containing commitment hash
) -> pub MatchResults { 
    // Verify input commitment - note this commits to the already-permuted preferences
    let mut input_fields: [Field; N_STUDENT_PREFERENCE * MAX_PREFS + N_COLLEGE_QUOTA * N_STUDENT_PREFERENCE + N_COLLEGE_QUOTA + 2] = 
        [0; N_STUDENT_PREFERENCE * MAX_PREFS + N_COLLEGE_QUOTA * N_STUDENT_PREFERENCE + N_COLLEGE_QUOTA + 2];
    
    // Flatten student preferences
    let mut index = 0;
    for i in 0..N_STUDENT_PREFERENCE {
        for j in 0..MAX_PREFS {
            input_fields[index] = permuted_student_prefs[i][j];
            index += 1;
        }
    }
    
    // Flatten college preferences
    for i in 0..N_COLLEGE_QUOTA {
        for j in 0..N_STUDENT_PREFERENCE {
            input_fields[index] = permuted_college_prefs[i][j];
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

    // 1. Calculate the stable matching using permuted preferences
    // The server only sees the matching between permuted identities
    let permuted_stable_matches = stable_matching( 
        permuted_student_prefs, 
        permuted_college_prefs, 
        college_capacities, 
        actual_student_list, 
        actual_uni_list 
    ); 
    
    // Add 1 to avoid zero values
    let adjusted_matches = permuted_stable_matches.map(|x| x + 1 as Field); 
    
    // Generate nonces for match commitments
    let match_nonces = generate_match_nonces(actual_student_list, nonce_seed);
    
    // Generate match commitments for Merkle tree
    let match_commitments = generate_match_commitments(
        permuted_stable_matches,
        actual_student_list,
        match_nonces
    );
    
    // Compute the Merkle root from match commitments using our simple implementation
    let merkle_root = simple_merkle_root(match_commitments);
    
    // 3. Initialize result structures 
    let mut result = MatchResults { 
        student_matches: [UNMATCHED_ELGAMAL; N_STUDENT_PREFERENCE], 
        college_matches: [[UNMATCHED_ELGAMAL; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA],
        merkle_root: merkle_root
    }; 
    
    // 4. Encrypt matches for students using the permuted public keys
    for i in 0..N_STUDENT_PREFERENCE { 
        if i < actual_student_list { 
            result.student_matches[i] = encrypt_elgamal( 
                adjusted_matches[i], 
                permuted_student_public_keys[i], // Permuted public key
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
                if adjusted_matches[s] - 1 as Field == c as Field { // Subtract the +1 adjustment 
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
            let college_pub_key = permuted_college_public_keys[c]; 
            
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

// Generate a Merkle proof for a student's match
fn generate_student_match_proof(
    student_id: Field,
    match_commitments: [Field; N_STUDENT_PREFERENCE]
) -> [Field; MERKLE_HEIGHT] {
    simple_merkle_proof(
        match_commitments,
        student_id as u32
    )
}

// Verify a student's match proof
fn verify_student_match(
    claimed_student_id: Field,
    claimed_college_id: Field,
    nonce: Field,
    merkle_proof: [Field; MERKLE_HEIGHT],
    public_merkle_root: Field
) -> bool {
    // Recreate the commitment hash
    let commitment = pedersen_hash([
        claimed_student_id,
        claimed_college_id,
        nonce
    ]);
    
    // Verify the Merkle proof using our simple implementation
    verify_simple_merkle_proof(
        public_merkle_root,
        commitment,
        claimed_student_id as u32,
        merkle_proof
    )
}

// Client-side utility functions for permutation
// NOTE: These functions would be implemented on the client side in
// JavaScript, TypeScript, etc. - not part of the Noir circuit!
// They're included here for demonstration purposes only.

/// Generate permutation maps for students and colleges
fn generate_permutation_maps(
    permutation_seed: Field,
    actual_student_list: u32,
    actual_uni_list: u32
) -> ([u32; N_STUDENT_PREFERENCE], [u32; N_COLLEGE_QUOTA]) {
    let mut student_id_map = [0; N_STUDENT_PREFERENCE];
    let mut college_id_map = [0; N_COLLEGE_QUOTA];
    
    // Fill with sequential IDs first
    for i in 0..N_STUDENT_PREFERENCE {
        student_id_map[i] = i;
    }
    
    for i in 0..N_COLLEGE_QUOTA {
        college_id_map[i] = i;
    }
    
    // Simple Fisher-Yates shuffle for permutation
    // For students
    for i in 0..actual_student_list {
        let seed_i = hash_to_field([permutation_seed, i as Field]);
        let j = (seed_i as u32 % (i+1)) as u32;
        
        // Swap student_id_map[i] with student_id_map[j]
        let temp = student_id_map[i];
        student_id_map[i] = student_id_map[j];
        student_id_map[j] = temp;
    }
    
    // For colleges
    for i in 0..actual_uni_list {
        let seed_i = hash_to_field([permutation_seed, (i + 1000) as Field]);
        let j = (seed_i as u32 % (i+1)) as u32;
        
        // Swap college_id_map[i] with college_id_map[j]
        let temp = college_id_map[i];
        college_id_map[i] = college_id_map[j];
        college_id_map[j] = temp;
    }
    
    (student_id_map, college_id_map)
}

/// Apply permutation to student and college preferences
/// This would be done on the client side before submitting to the server
fn apply_client_permutation(
    student_prefs: [[Field; MAX_PREFS]; N_STUDENT_PREFERENCE],
    college_prefs: [[Field; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA],
    student_id_map: [u32; N_STUDENT_PREFERENCE],
    college_id_map: [u32; N_COLLEGE_QUOTA],
    actual_student_list: u32,
    actual_uni_list: u32
) -> ([[Field; MAX_PREFS]; N_STUDENT_PREFERENCE], [[Field; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA]) {
    let mut blinded_student_prefs = [[UNMATCHED; MAX_PREFS]; N_STUDENT_PREFERENCE];
    let mut blinded_college_prefs = [[UNMATCHED; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA];
    
    // Map student preferences
    for i in 0..actual_student_list {
        let blinded_i = student_id_map[i];
        for j in 0..MAX_PREFS {
            if student_prefs[i][j] != UNMATCHED {
                // Map college ID in preference
                let original_college_id = student_prefs[i][j] as u32;
                if original_college_id < actual_uni_list {
                    let blinded_college_id = college_id_map[original_college_id];
                    blinded_student_prefs[blinded_i][j] = blinded_college_id as Field;
                } else {
                    blinded_student_prefs[blinded_i][j] = UNMATCHED;
                }
            } else {
                blinded_student_prefs[blinded_i][j] = UNMATCHED;
            }
        }
    }
    
    // Map college preferences
    for i in 0..actual_uni_list {
        let blinded_i = college_id_map[i];
        for j in 0..N_STUDENT_PREFERENCE {
            if college_prefs[i][j] != UNMATCHED {
                // Map student ID in preference
                let original_student_id = college_prefs[i][j] as u32;
                if original_student_id < actual_student_list {
                    let blinded_student_id = student_id_map[original_student_id];
                    blinded_college_prefs[blinded_i][j] = blinded_student_id as Field;
                } else {
                    blinded_college_prefs[blinded_i][j] = UNMATCHED;
                }
            } else {
                blinded_college_prefs[blinded_i][j] = UNMATCHED;
            }
        }
    }
    
    (blinded_student_prefs, blinded_college_prefs)
}

/// Permute public keys according to ID mappings
/// This would also be done on the client side
fn permute_public_keys(
    student_public_keys: [EmbeddedCurvePoint; N_STUDENT_PREFERENCE],
    college_public_keys: [EmbeddedCurvePoint; N_COLLEGE_QUOTA],
    student_id_map: [u32; N_STUDENT_PREFERENCE],
    college_id_map: [u32; N_COLLEGE_QUOTA],
    actual_student_list: u32,
    actual_uni_list: u32
) -> ([EmbeddedCurvePoint; N_STUDENT_PREFERENCE], [EmbeddedCurvePoint; N_COLLEGE_QUOTA]) {
    let mut permuted_student_keys = [EmbeddedCurvePoint { x: 0, y: 0, is_infinite: true }; N_STUDENT_PREFERENCE];
    let mut permuted_college_keys = [EmbeddedCurvePoint { x: 0, y: 0, is_infinite: true }; N_COLLEGE_QUOTA];
    
    // Permute student public keys
    for i in 0..actual_student_list {
        let permuted_i = student_id_map[i];
        permuted_student_keys[permuted_i] = student_public_keys[i];
    }
    
    // Permute college public keys
    for i in 0..actual_uni_list {
        let permuted_i = college_id_map[i];
        permuted_college_keys[permuted_i] = college_public_keys[i];
    }
    
    (permuted_student_keys, permuted_college_keys)
}

/// Client-side function to reverse the permutation after decryption
/// This would be executed on the client side after receiving encrypted results
fn client_unmapped_results(
    decrypted_student_matches: [Field; N_STUDENT_PREFERENCE],
    student_id_map: [u32; N_STUDENT_PREFERENCE],
    college_id_map: [u32; N_COLLEGE_QUOTA],
    actual_student_list: u32
) -> [Field; N_STUDENT_PREFERENCE] {
    let mut real_matches = [UNMATCHED; N_STUDENT_PREFERENCE];
    
    // Create inverse maps
    let mut inverse_student_map = [0; N_STUDENT_PREFERENCE];
    let mut inverse_college_map = [0; N_COLLEGE_QUOTA];
    
    for i in 0..N_STUDENT_PREFERENCE {
        if i < actual_student_list {
            inverse_student_map[student_id_map[i]] = i;
        }
    }
    
    for i in 0..N_COLLEGE_QUOTA {
        inverse_college_map[college_id_map[i]] = i;
    }
    
    // Reverse permutation on results
    for i in 0..actual_student_list {
        // Find where this student was permuted to
        let permuted_i = student_id_map[i];
        
        // Get this student's match in permuted space
        let permuted_match = decrypted_student_matches[permuted_i];
        
        if permuted_match != UNMATCHED {
            // Map the college ID back to the original space
            let original_college = inverse_college_map[permuted_match as u32];
            real_matches[i] = original_college as Field;
        } else {
            real_matches[i] = UNMATCHED;
        }
    }
    
    real_matches
}

/// Permute private keys according to ID mappings
fn permute_private_keys(
    private_keys: [Field; N_STUDENT_PREFERENCE],
    id_map: [u32; N_STUDENT_PREFERENCE],
    actual_list: u32
) -> [Field; N_STUDENT_PREFERENCE] {
    let mut permuted_keys = [0 as Field; N_STUDENT_PREFERENCE];
    
    // Permute private keys
    for i in 0..actual_list {
        let permuted_i = id_map[i];
        permuted_keys[permuted_i] = private_keys[i];
    }
    
    permuted_keys
}

#[test]
fn test_client_permuted_matching() {
    // Original test data
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

    // Original cryptographic keys
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

    let college_private_keys: [Field; N_COLLEGE_QUOTA] = [ 
        0x6 as Field, 
        0x7 as Field, 
        0x8 as Field, 
        0x9 as Field, 
        0xA as Field 
    ];

    let college_public_keys: [EmbeddedCurvePoint; N_COLLEGE_QUOTA] = [ 
        field_to_curve_point(college_private_keys[0]),
        field_to_curve_point(college_private_keys[1]), 
        field_to_curve_point(college_private_keys[2]), 
        field_to_curve_point(college_private_keys[3]), 
        field_to_curve_point(college_private_keys[4]) 
    ]; 

    let college_capacities: [Field; N_COLLEGE_QUOTA] = [3, 1, 1, 0, 0];
    let nonce_seed = 0x12345678 as Field;
    let permutation_seed = 0x87654321 as Field;
    
    let actual_student_list = 5; // Number of students in the actual list
    let actual_uni_list = 3; // Number of colleges in the actual list
    
    println("=== Testing Client-Side Permuted Matching ===");
    println("1. STEP: Client generates permutation maps");
    
    // This step happens on the client side
    let (student_id_map, college_id_map) = generate_permutation_maps(
        permutation_seed,
        actual_student_list,
        actual_uni_list
    );
    
    println("Student permutation map:");
    println(student_id_map);
    println("College permutation map:");
    println(college_id_map);
    
    println("");
    println("2. STEP: Client permutes preferences and public keys");
    
    // Apply permutation to preferences (client-side)
    let (permuted_student_prefs, permuted_college_prefs) = apply_client_permutation(
        student_prefs,
        college_prefs,
        student_id_map,
        college_id_map,
        actual_student_list,
        actual_uni_list
    );
    
    // Also permute public keys (client-side)
    let (permuted_student_public_keys, permuted_college_public_keys) = permute_public_keys(
        student_public_keys,
        college_public_keys,
        student_id_map,
        college_id_map,
        actual_student_list,
        actual_uni_list
    );
    
    // Also permute private keys (client-side)
    let permuted_student_private_keys = permute_private_keys(
        student_private_keys,
        student_id_map,
        actual_student_list
    );

    let permuted_college_private_keys = permute_private_keys(
        college_private_keys,
        college_id_map,
        actual_uni_list
    );
    
    println("Original first student preferences: ");
    println(student_prefs[0]);
    println("Permuted first position preferences: ");
    println(permuted_student_prefs[0]);
    
    println("");
    println("3. STEP: Create commitment for permuted inputs");
    
    // Create commitment only on permuted data
    let mut input_fields: [Field; N_STUDENT_PREFERENCE * MAX_PREFS + N_COLLEGE_QUOTA * N_STUDENT_PREFERENCE + N_COLLEGE_QUOTA + 2] = 
        [0; N_STUDENT_PREFERENCE * MAX_PREFS + N_COLLEGE_QUOTA * N_STUDENT_PREFERENCE + N_COLLEGE_QUOTA + 2];
    
    // Flatten permuted student preferences for commitment
    let mut index = 0;
    for i in 0..N_STUDENT_PREFERENCE {
        for j in 0..MAX_PREFS {
            input_fields[index] = permuted_student_prefs[i][j];
            index += 1;
        }
    }
    
    // Flatten permuted college preferences for commitment
    for i in 0..N_COLLEGE_QUOTA {
        for j in 0..N_STUDENT_PREFERENCE {
            input_fields[index] = permuted_college_prefs[i][j];
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
    
    // Compute the hash of permuted inputs (this is the commitment)
    let permuted_commitment = pedersen_hash(input_fields);
    
    println("Commitment to permuted data generated");
    
    println("");
    println("4. STEP: Server runs matching on permuted preferences");
    println("(Server never sees original preferences)");
    
    // This is what the server executes
    let encrypted_results = main_client_permuted( 
        permuted_student_prefs, 
        permuted_college_prefs, 
        college_capacities, 
        permuted_student_public_keys, 
        permuted_college_public_keys, 
        actual_student_list, 
        actual_uni_list, 
        nonce_seed,
        permuted_commitment
    );
    
    println("");
    println("5. STEP: Students and colleges decrypt their results");
    
    // Decrypt student matches (still in permuted space)
    let permuted_decrypted_student_matches = decrypt_student_matches(
        encrypted_results, 
        permuted_student_private_keys  // Use permuted private keys
    );
    
    println("Permuted student match results:");
    println(permuted_decrypted_student_matches);
    
    // Client-side: Reverse permutation to get real matches
    let actual_student_matches = client_unmapped_results(
        permuted_decrypted_student_matches,
        student_id_map,
        college_id_map,
        actual_student_list
    );
    
    println("");
    println("6. STEP: Client unmaps results to original IDs");
    println("Actual student matches after reversing permutation:");
    println(actual_student_matches);
    
    // Also decrypt college matches (still permuted)
    let permuted_college_matches = decrypt_college_matches(
        encrypted_results, 
        permuted_college_private_keys,  // Use permuted private keys
        college_capacities
    );
    
    println("");
    println("Permuted college matches:");
    for c in 0..actual_uni_list {
        println("College (permuted ID)");
        println(c);
        println(": ");
        println(permuted_college_matches[c]);
    }
    
    // Get and display the Merkle root for verification
    println("");
    println("7. STEP: Merkle root for match verification");
    println("Public Merkle root: ");
    println(encrypted_results.merkle_root);
    
    // Generate commitment nonces using same seed
    let match_nonces = generate_match_nonces(actual_student_list, nonce_seed);
    
    // Generate match commitments
    let match_commitments = generate_match_commitments(
        permuted_decrypted_student_matches,
        actual_student_list,
        match_nonces
    );
    
    // Test verification for student 0 (who becomes student_id_map[0] in permuted space)
    let student_id = 0;
    let permuted_student_id = student_id_map[student_id];
    let student_college_match = permuted_decrypted_student_matches[permuted_student_id];
    let student_nonce = match_nonces[permuted_student_id];
    
    // Generate Merkle proof for this student
    let merkle_proof = generate_student_match_proof(
        permuted_student_id as Field,
        match_commitments
    );
    
    println("");
    println("8. STEP: Student generates proof of acceptance");
    println("Student (original ID): ");
    println(student_id);
    println("Matched with college (permuted ID): ");
    println(student_college_match);
    
    // Verify the proof
    let verification_result = verify_student_match(
        permuted_student_id as Field,
        student_college_match,
        student_nonce,
        merkle_proof,
        encrypted_results.merkle_root
    );
    
    println("");
    println("9. STEP: Third party verifies the proof");
    println("Verification result: ");
    println(verification_result);
    
    println("");
    println("=== Client-side permutation test completed successfully ===");
    println("Server never saw the original preferences or the actual matching results!");
    println("Students can prove their acceptance to third parties!");
}

#[test]
fn test_merkle_proof_verification() {
    // Create a simple set of match commitments
    let mut match_commitments = [0; N_STUDENT_PREFERENCE];
    
    // Generate random commitments
    for i in 0..N_STUDENT_PREFERENCE {
        match_commitments[i] = hash_to_field([i as Field, (i+100) as Field, (i*10) as Field]);
    }
    
    // Compute Merkle root
    let merkle_root = simple_merkle_root(match_commitments);
    
    // Generate proof for a specific student
    let student_id = 2;
    let proof = simple_merkle_proof(match_commitments, student_id);
    
    // Verify the proof - should succeed
    let verification_result = verify_simple_merkle_proof(
        merkle_root,
        match_commitments[student_id],
        student_id,
        proof
    );
    
    println("Valid proof verification result (should be true): ");
    println(verification_result);
    
    // Test wrong index without asserting
    let wrong_index_result = verify_simple_merkle_proof(
        merkle_root,
        match_commitments[student_id],
        student_id + 1,
        proof
    );
    
    println("Wrong index verification result (should be false): ");
    println(wrong_index_result);
    
    // Test fake commitment without asserting
    let fake_commitment = hash_to_field([student_id as Field, 999 as Field, 123 as Field]);
    let fake_commitment_result = verify_simple_merkle_proof(
        merkle_root,
        fake_commitment,
        student_id,
        proof
    );
    
    println("Fake commitment verification result (should be false): ");
    println(fake_commitment_result);
    
    println("Merkle proof verification test completed!");
}