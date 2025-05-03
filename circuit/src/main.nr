mod elgamal; 

use std::hash::hash_to_field; 
use std::hash::pedersen_hash;
use crate::elgamal::{ElGamalCiphered, EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul}; 

//===== GLOBAL CONSTANTS =====
global MAX_HOSPITALS: u32 = 10;
global MAX_PATIENTS_PER_HOSPITAL: u32 = 20;
global MAX_DONORS_PER_HOSPITAL: u32 = 20;
global MAX_EDGES: u32 = 100;
global MAX_CYCLES: u32 = 15;
global MAX_CYCLE_LENGTH: u32 = 5;
global NO_MATCH: Field = 999;
global BITS_DL: u32 = 16; 

// Blood types encoded as Field values
global BLOOD_TYPE_A: Field = 0;
global BLOOD_TYPE_B: Field = 1;
global BLOOD_TYPE_AB: Field = 2;
global BLOOD_TYPE_O: Field = 3;

//===== DATA STRUCTURES =====
// Medical profile for a donor or recipient
struct MedicalProfile {
    blood_type: Field,          // Encoded blood type (A=0, B=1, AB=2, O=3)
    hla_antigens: [Field; 6],   // HLA typing data
    pra_score: Field,           // Panel Reactive Antibody (0-100)
    age: Field,                 // Age of donor/patient
    additional_factors: Field   // Hash of other medical factors
}

// Represents a donor
struct Donor {
    id: Field,                  // Unique donor ID
    hospital_id: Field,         // Hospital ID
    medical_profile: MedicalProfile
}

// Represents a recipient
struct Recipient {
    id: Field,                  // Unique recipient ID
    hospital_id: Field,         // Hospital ID
    medical_profile: MedicalProfile, 
    donor_id: Field             // ID of paired donor
}

// A pair of donor and recipient (typically family members)
struct DonorRecipientPair {
    donor: Donor,
    recipient: Recipient
}

// Zero-knowledge proof that verifies compatibility without revealing medical data
struct CompatibilityProof {
    hospital_id: Field,             // ID of the hospital that generated the proof
    donor_commitment: Field,        // Commitment to donor data
    recipient_commitment: Field,    // Commitment to recipient data
    compatibility_result: Field,    // 1 = compatible, 0 = incompatible
    proof_signature: Field          // Hospital's signature on the proof
}

// Represents an edge in the compatibility graph
struct CompatibilityEdge {
    from_hospital_id: Field,
    from_pair_id: Field,
    to_hospital_id: Field, 
    to_pair_id: Field,
    compatibility_proof: CompatibilityProof
}

// Results of the kidney exchange
struct ExchangeResult {
    cycles: [[Field; MAX_CYCLE_LENGTH]; MAX_CYCLES], // Each cycle is a sequence of pair IDs
    cycle_lengths: [Field; MAX_CYCLES],              // Length of each cycle
    cycle_count: Field                               // Number of cycles found
}

// Encrypted results for each hospital
struct EncryptedHospitalResult {
    hospital_id: Field,
    encrypted_cycles: [[ElGamalCiphered<BITS_DL>; MAX_CYCLE_LENGTH]; MAX_CYCLES],
    cycle_lengths: [ElGamalCiphered<BITS_DL>; MAX_CYCLES],
    encrypted_cycle_count: ElGamalCiphered<BITS_DL>
}

// Collection of results for all hospitals
struct KidneyExchangeResults {
    hospital_results: [EncryptedHospitalResult; MAX_HOSPITALS]
}

//===== UTILITY FUNCTIONS =====
fn field_to_curve_point(key: Field) -> EmbeddedCurvePoint { 
    fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(key)) 
}

fn encrypt_elgamal(
    message: Field, 
    public_key: EmbeddedCurvePoint, 
    recipient_id: Field, 
    encryption_index: Field, 
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

//===== COMPATIBILITY CHECKING FUNCTIONS =====
// Check blood type compatibility
// Returns true if donor blood type is compatible with recipient
fn check_blood_compatibility(donor_blood: Field, recipient_blood: Field) -> bool {
    // Blood type compatibility rules:
    // O can donate to anyone
    // A can donate to A and AB
    // B can donate to B and AB
    // AB can donate only to AB
    
    // O donor
    let mut return_value = false;
    if donor_blood == BLOOD_TYPE_O {
        return_value = true;
    } 
    
    // A donor
    if donor_blood == BLOOD_TYPE_A {
        if (recipient_blood == BLOOD_TYPE_A) | (recipient_blood == BLOOD_TYPE_AB) {
            return_value = true;
        }
    }
    
    // B donor
    if donor_blood == BLOOD_TYPE_B {
       if(recipient_blood == BLOOD_TYPE_B) | (recipient_blood == BLOOD_TYPE_AB) {
            return_value = true;
        }
    }
    
    // AB donor
    if donor_blood == BLOOD_TYPE_AB {
        if recipient_blood == BLOOD_TYPE_AB {
            return_value = true;
        }
    }
    
    return_value
}

// Check HLA compatibility
fn check_hla_compatibility(donor_hla: [Field; 6], recipient_hla: [Field; 6], pra_score: Field) -> bool {
    let mut match_count = 0;
    let mut mismatch_count = 0;
    
    // Count matching and mismatching HLA antigens
    for i in 0..6 {
        if donor_hla[i] == recipient_hla[i] {
            match_count += 1;
        } else if (donor_hla[i]  != 0) & (recipient_hla[i] != 0 ){
            // Both have antigens but they don't match
            mismatch_count += 1;
        }
    }
    
    // Simplified compatibility check
    // Higher PRA means more antibodies, so we need more matches
    // This is a simplified model - real HLA matching is more complex
    let pra_threshold = pra_score / 20; // Convert 0-100 to 0-5 scale
    let compatibility_score = match_count - mismatch_count;
    
    compatibility_score > pra_threshold as u32
}

// Check age and other medical factors compatibility
fn check_additional_compatibility(donor_age: Field, donor_factors: Field, 
                                 recipient_age: Field, recipient_factors: Field) -> bool {
    // Simplified compatibility check
    // In reality, this would involve many medical factors
    // For this demonstration, we'll use simple rules:
    let mut age_diff = 0;
    // Age difference should not be too large (simplified)
    if donor_age as u32 > recipient_age as u32 { 
        age_diff = donor_age as u32 - recipient_age  as u32;
    } else { 
        age_diff = recipient_age as u32 - donor_age  as u32;
    };
    
    // Simple check: if factors hash to same parity, they're compatible
    let factors_compatible = (donor_factors as u32 % 2) == (recipient_factors as u32 % 2);
    
    // Combined check
    (age_diff as u32 < 30) & factors_compatible
}

// Comprehensive compatibility check combining all factors
fn check_donor_recipient_compatibility(
    donor: MedicalProfile, 
    recipient: MedicalProfile
) -> bool {
    // Check blood type compatibility
    let blood_compatible = check_blood_compatibility(donor.blood_type, recipient.blood_type);
    
    // Check HLA compatibility
    let hla_compatible = check_hla_compatibility(
        donor.hla_antigens, 
        recipient.hla_antigens, 
        recipient.pra_score
    );
    
    // Check additional factors
    let additional_compatible = check_additional_compatibility(
        donor.age, 
        donor.additional_factors,
        recipient.age, 
        recipient.additional_factors
    );
    
    // All checks must pass
    blood_compatible & hla_compatible & additional_compatible
}

//===== ZERO-KNOWLEDGE PROOFS =====
// Generate a ZK proof of compatibility without revealing medical details
fn generate_compatibility_proof(
    donor: Donor,
    recipient: Recipient,
    hospital_private_key: Field
) -> CompatibilityProof {
    // Compute compatibility
    let is_compatible = check_donor_recipient_compatibility(
        donor.medical_profile, 
        recipient.medical_profile
    );
    
    // Create commitments to medical data
    let donor_commitment = pedersen_hash([
        donor.id,
        donor.hospital_id,
        donor.medical_profile.blood_type,
        donor.medical_profile.pra_score,
        donor.medical_profile.age,
        donor.medical_profile.additional_factors
        // We'd include HLA data too in a real implementation
    ]);
    
    let recipient_commitment = pedersen_hash([
        recipient.id,
        recipient.hospital_id,
        recipient.medical_profile.blood_type,
        recipient.medical_profile.pra_score,
        recipient.medical_profile.age,
        recipient.medical_profile.additional_factors,
        recipient.donor_id
        // We'd include HLA data too in a real implementation
    ]);
    
    // Result: 1 for compatible, 0 for incompatible
    let compatibility_result = if is_compatible { 1 } else { 0 };
    
    // Sign the proof using the hospital's private key
    let signature_input = [
        donor_commitment,
        recipient_commitment,
        compatibility_result,
        hospital_private_key
    ];
    
    let proof_signature = pedersen_hash(signature_input);
    
    CompatibilityProof {
        hospital_id: donor.hospital_id,
        donor_commitment,
        recipient_commitment,
        compatibility_result,
        proof_signature
    }
}

// Verify a compatibility proof using the hospital's public key
fn verify_compatibility_proof(
    proof: CompatibilityProof,
    hospital_public_key: Field
) -> bool {
    // Reconstruct what the signature should be
    let expected_signature_input = [
        proof.donor_commitment,
        proof.recipient_commitment,
        proof.compatibility_result,
        hospital_public_key
    ];
    
    let expected_signature = pedersen_hash(expected_signature_input);
    
    // Verify the signature
    expected_signature == proof.proof_signature
}

//===== GRAPH CONSTRUCTION =====
// Build the compatibility graph from ZK proofs
fn build_compatibility_graph(
    compatibility_proofs: [CompatibilityProof; MAX_EDGES],
    proof_count: Field,
    hospital_public_keys: [Field; MAX_HOSPITALS]
) -> [CompatibilityEdge; MAX_EDGES] {
    let mut graph = [CompatibilityEdge {
        from_hospital_id: 0,
        from_pair_id: 0,
        to_hospital_id: 0,
        to_pair_id: 0,
        compatibility_proof: CompatibilityProof {
            hospital_id: 0,
            donor_commitment: 0,
            recipient_commitment: 0,
            compatibility_result: 0,
            proof_signature: 0
        }
    }; MAX_EDGES];
    
    let mut valid_edge_count = 0;
    
    for i in 0..MAX_EDGES {
        if i < proof_count as u32 {
            let proof = compatibility_proofs[i];
            
            // Verify the proof using the hospital's public key
            let hospital_id = proof.hospital_id as u32;
            let is_valid = verify_compatibility_proof(
                proof,
                hospital_public_keys[hospital_id]
            );
            
            // Only add to graph if proof is valid and shows compatibility
            if is_valid & (proof.compatibility_result == 1) {
                // We'd extract IDs from the proofs in practice
                // For simplicity, we're using i as the edge ID
                graph[valid_edge_count] = CompatibilityEdge {
                    from_hospital_id:  (i / 10) as Field, // Simplified for demo
                    from_pair_id: (i % 10) as Field,     // Simplified for demo
                    to_hospital_id: ((i*3) % MAX_HOSPITALS) as Field, // Simplified for demo
                    to_pair_id: ((i*7) % 10) as Field,   // Simplified for demo
                    compatibility_proof: proof
                };
                
                valid_edge_count += 1;
            }
        }
    }
    
    graph
}

//===== MATCHING ALGORITHM =====
// Find cycles in the compatibility graph
fn find_exchange_cycles(
    graph: [CompatibilityEdge; MAX_EDGES],
    valid_edge_count: Field
) -> ExchangeResult {
    let mut cycles = [[NO_MATCH; MAX_CYCLE_LENGTH]; MAX_CYCLES];
    let mut cycle_lengths = [0; MAX_CYCLES];
    let mut cycle_count = 0;
    
    // For simplicity, we'll just find 2-way and 3-way cycles
    // In practice, a more sophisticated algorithm would be used
    
    // Find 2-way cycles (A->B, B->A)
    for i in 0..MAX_EDGES {
        if i < valid_edge_count as u32 {
            let edge_i = graph[i];
            
            for j in 0..MAX_EDGES {
                if j < valid_edge_count as u32 & (j != i) {
                    let edge_j = graph[j];
                    
                    // Check if the edges form a 2-way cycle
                    if (edge_i.to_hospital_id == edge_j.from_hospital_id) &
                       (edge_i.to_pair_id == edge_j.from_pair_id) &
                       (edge_j.to_hospital_id == edge_i.from_hospital_id) &
                       (edge_j.to_pair_id == edge_i.from_pair_id) {
                        
                        // Found a 2-way cycle
                        if cycle_count < MAX_CYCLES as u32 {
                            cycles[cycle_count][0] = i as Field;
                            cycles[cycle_count][1] = j as Field;
                            cycle_lengths[cycle_count] = 2;
                            cycle_count += 1;
                        }
                    }
                }
            }
        }
    }
    
    // Find 3-way cycles (A->B, B->C, C->A)
    for i in 0..MAX_EDGES {
        if i < valid_edge_count as u32 {
            let edge_i = graph[i];
            
            for j in 0..MAX_EDGES {
                if (j < valid_edge_count as u32) & (j != i) {
                    let edge_j = graph[j];
                    
                    // Check if edge_j continues from where edge_i ends
                    if (edge_i.to_hospital_id == edge_j.from_hospital_id) &
                       (edge_i.to_pair_id == edge_j.from_pair_id) {
                        
                        for k in 0..MAX_EDGES {
                            if (k < valid_edge_count as u32) & ((k != i) & (k != j)) {
                                let edge_k = graph[k];
                                
                                // Check if the edges form a 3-way cycle
                                if (edge_j.to_hospital_id == edge_k.from_hospital_id) &
                                   (edge_j.to_pair_id == edge_k.from_pair_id) &
                                   (edge_k.to_hospital_id == edge_i.from_hospital_id) &
                                   (edge_k.to_pair_id == edge_i.from_pair_id) {
                                    
                                    // Found a 3-way cycle
                                    if cycle_count < MAX_CYCLES as u32 {
                                        cycles[cycle_count][0] = i as Field;
                                        cycles[cycle_count][1] = j as Field;
                                        cycles[cycle_count][2] = k as Field;
                                        cycle_lengths[cycle_count] = 3;
                                        cycle_count += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    ExchangeResult {
        cycles,
        cycle_lengths,
        cycle_count: cycle_count as Field
    }
}

// Function to select optimal cycles that maximize the number of transplants
fn select_optimal_cycles(
    all_cycles: ExchangeResult,
    graph: [CompatibilityEdge; MAX_EDGES]
) -> ExchangeResult {
    // In practice, this would implement a sophisticated optimization algorithm
    // For simplicity, we'll just prioritize longer cycles
    
    let mut selected_cycles = [[NO_MATCH; MAX_CYCLE_LENGTH]; MAX_CYCLES];
    let mut selected_lengths = [0; MAX_CYCLES];
    let mut selected_count = 0;
    
    let mut used_edges = [false; MAX_EDGES];
    
    // Sort cycles by length (descending)
    // This is a simplified approach - in practice we'd use a proper sorting algorithm
    
    // First include 3-way cycles
    for i in 0..MAX_CYCLES {
        if i < all_cycles.cycle_count as u32 {
            if all_cycles.cycle_lengths[i] == 3 {
                let mut can_use = true;
                
                // Check if any edge is already used
                for j in 0..3 {
                    let edge_idx = all_cycles.cycles[i][j] as u32;
                    if used_edges[edge_idx] {
                        can_use = false;
                    }
                }
                
                if can_use {
                    // Add this cycle
                    selected_cycles[selected_count] = all_cycles.cycles[i];
                    selected_lengths[selected_count] = 3;
                    selected_count += 1;
                    
                    // Mark edges as used
                    for j in 0..3 {
                        let edge_idx = all_cycles.cycles[i][j] as u32;
                        used_edges[edge_idx] = true;
                    }
                }
            }
        }
    }
    
    // Then include 2-way cycles
    for i in 0..MAX_CYCLES {
        if i < all_cycles.cycle_count as u32 {
            if all_cycles.cycle_lengths[i] == 2 {
                let mut can_use = true;
                
                // Check if any edge is already used
                for j in 0..2 {
                    let edge_idx = all_cycles.cycles[i][j] as u32;
                    if used_edges[edge_idx] {
                        can_use = false;
                    }
                }
                
                if can_use {
                    // Add this cycle
                    selected_cycles[selected_count] = all_cycles.cycles[i];
                    selected_lengths[selected_count] = 2;
                    selected_count += 1;
                    
                    // Mark edges as used
                    for j in 0..2 {
                        let edge_idx = all_cycles.cycles[i][j] as u32;
                        used_edges[edge_idx] = true;
                    }
                }
            }
        }
    }
    
    ExchangeResult {
        cycles: selected_cycles,
        cycle_lengths: selected_lengths,
        cycle_count: selected_count as Field
    }
}

//===== RESULT ENCRYPTION =====
// Encrypt the exchange results for each hospital
fn encrypt_exchange_results(
    exchange_result: ExchangeResult,
    graph: [CompatibilityEdge; MAX_EDGES],
    hospital_public_keys: [EmbeddedCurvePoint; MAX_HOSPITALS],
    nonce_seed: Field
) -> KidneyExchangeResults {
    let empty_encrypted_result = ElGamalCiphered::<BITS_DL>::new(
        EmbeddedCurvePoint { x: 0, y: 0, is_infinite: true },
        0,
        EmbeddedCurveScalar::from_field(0)
    );
    
    let mut hospital_results = [EncryptedHospitalResult {
        hospital_id: 0,
        encrypted_cycles: [[empty_encrypted_result; MAX_CYCLE_LENGTH]; MAX_CYCLES],
        cycle_lengths: [empty_encrypted_result; MAX_CYCLES],
        encrypted_cycle_count: empty_encrypted_result
    }; MAX_HOSPITALS];
    
    // For each hospital, encrypt only the parts of the results they need to know
    for h in 0..MAX_HOSPITALS {
        let mut relevant_cycles = [[NO_MATCH; MAX_CYCLE_LENGTH]; MAX_CYCLES];
        let mut relevant_lengths = [0; MAX_CYCLES];
        let mut relevant_count = 0;
        
        // Find cycles relevant to this hospital
        for c in 0..MAX_CYCLES {
            if c < exchange_result.cycle_count as u32 {
                let mut hospital_involved = false;
                
                // Check if this hospital is involved in the cycle
                for e in 0..MAX_CYCLE_LENGTH {
                    if e < exchange_result.cycle_lengths[c] as u32 {
                        let edge_idx = exchange_result.cycles[c][e] as u32;
                        let edge = graph[edge_idx];
                        
                        if (edge.from_hospital_id == h as Field) | (edge.to_hospital_id == h as Field) {
                            hospital_involved = true;
                        }
                    }
                }
                
                if hospital_involved {
                    relevant_cycles[relevant_count] = exchange_result.cycles[c];
                    relevant_lengths[relevant_count] = exchange_result.cycle_lengths[c];
                    relevant_count += 1;
                }
            }
        }
        
        // Encrypt the relevant results for this hospital
        let hospital_pub_key = hospital_public_keys[h];
        
        // Encrypt cycle count
        hospital_results[h].hospital_id = h as Field;
        hospital_results[h].encrypted_cycle_count = encrypt_elgamal(
            relevant_count as Field,
            hospital_pub_key,
            h as Field,
            0,
            nonce_seed
        );
        
        // Encrypt cycle lengths
        for c in 0..MAX_CYCLES {
            if c < relevant_count {
                hospital_results[h].cycle_lengths[c] = encrypt_elgamal(
                    relevant_lengths[c],
                    hospital_pub_key,
                    h as Field,
                    c as Field + 1,
                    nonce_seed
                );
            }
        }
        
        // Encrypt cycle details
        for c in 0..MAX_CYCLES {
            if c < relevant_count {
                for e in 0..MAX_CYCLE_LENGTH {
                    if e < relevant_lengths[c] as u32 {
                        hospital_results[h].encrypted_cycles[c][e] = encrypt_elgamal(
                            relevant_cycles[c][e],
                            hospital_pub_key,
                            h as Field,
                            (MAX_CYCLES + c) as Field + e as Field,
                            nonce_seed
                        );
                    }
                }
            }
        }
    }
    
    KidneyExchangeResults {
        hospital_results
    }
}

// Decrypt results for a specific hospital
fn decrypt_hospital_result(
    encrypted_result: EncryptedHospitalResult,
    hospital_private_key: Field
) -> ExchangeResult {
    let private_scalar = EmbeddedCurveScalar::from_field(hospital_private_key);
    
    // Decrypt cycle count
    let cycle_count = encrypted_result.encrypted_cycle_count.decrypt_to_scalar(private_scalar) as Field;
    
    let mut cycles = [[NO_MATCH; MAX_CYCLE_LENGTH]; MAX_CYCLES];
    let mut cycle_lengths = [0; MAX_CYCLES];
    
    // Decrypt cycle lengths
    for c in 0..MAX_CYCLES {
        if c < cycle_count as u32 {
            cycle_lengths[c] = encrypted_result.cycle_lengths[c].decrypt_to_scalar(private_scalar) as Field;
        }
    }
    
    // Decrypt cycle details
    for c in 0..MAX_CYCLES {
        if c < cycle_count as u32 {
            for e in 0..MAX_CYCLE_LENGTH {
                if e < cycle_lengths[c] as u32 {
                    cycles[c][e] = encrypted_result.encrypted_cycles[c][e].decrypt_to_scalar(private_scalar) as Field;
                }
            }
        }
    }
    
    ExchangeResult {
        cycles,
        cycle_lengths,
        cycle_count
    }
}

//===== MAIN CIRCUIT FUNCTION =====
// Main function for the ZK-based kidney exchange system
fn main(
    compatibility_proofs: [CompatibilityProof; MAX_EDGES],
    proof_count: Field,
    hospital_public_keys: [Field; MAX_HOSPITALS],
    hospital_public_ec_keys: [EmbeddedCurvePoint; MAX_HOSPITALS],
    nonce_seed: Field,
    input_commitment: pub Field
) -> pub KidneyExchangeResults {
    // Verify input commitment
    let mut input_fields: [Field; MAX_EDGES * 5 + 1 + MAX_HOSPITALS] = [0; MAX_EDGES * 5 + 1 + MAX_HOSPITALS];
    
    // Flatten compatibility proofs
    let mut index = 0;
    for i in 0..MAX_EDGES {
        if i < proof_count as u32 {
            input_fields[index] = compatibility_proofs[i].hospital_id;
            index += 1;
            input_fields[index] = compatibility_proofs[i].donor_commitment;
            index += 1;
            input_fields[index] = compatibility_proofs[i].recipient_commitment;
            index += 1;
            input_fields[index] = compatibility_proofs[i].compatibility_result;
            index += 1;
            input_fields[index] = compatibility_proofs[i].proof_signature;
            index += 1;
        }
    }
    
    // Add proof count
    input_fields[index] = proof_count;
    index += 1;
    
    // Add hospital public keys
    for i in 0..MAX_HOSPITALS {
        input_fields[index] = hospital_public_keys[i];
        index += 1;
    }
    
    // Compute the hash of all inputs
    let computed_commitment = pedersen_hash(input_fields);
    assert(input_commitment == computed_commitment); 
    
    // 1. Build compatibility graph from ZK proofs
    let graph = build_compatibility_graph(
        compatibility_proofs,
        proof_count,
        hospital_public_keys
    );
    
    // 2. Find all possible exchange cycles
    let all_cycles = find_exchange_cycles(graph, proof_count);
    
    // 3. Select optimal cycles
    let selected_cycles = select_optimal_cycles(all_cycles, graph);
    
    // 4. Encrypt results for each hospital
    let encrypted_results = encrypt_exchange_results(
        selected_cycles,
        graph,
        hospital_public_ec_keys,
        nonce_seed
    );
    
    encrypted_results
}

//===== TEST FUNCTION =====
#[test]
fn test_kidney_exchange() {
    println("=== Testing Privacy-Preserving Kidney Exchange ===");
    
    // Setup test data for hospitals
    let hospital_private_keys: [Field; MAX_HOSPITALS] = [
        0x101 as Field, 0x102 as Field, 0x103 as Field, 0x104 as Field, 0x105 as Field,
        0x106 as Field, 0x107 as Field, 0x108 as Field, 0x109 as Field, 0x10A as Field
    ];
    
    let hospital_public_keys: [Field; MAX_HOSPITALS] = [
        0x201 as Field, 0x202 as Field, 0x203 as Field, 0x204 as Field, 0x205 as Field,
        0x206 as Field, 0x207 as Field, 0x208 as Field, 0x209 as Field, 0x20A as Field
    ];
    
    let hospital_public_ec_keys: [EmbeddedCurvePoint; MAX_HOSPITALS] = [
        field_to_curve_point(hospital_public_keys[0]),
        field_to_curve_point(hospital_public_keys[1]),
        field_to_curve_point(hospital_public_keys[2]),
        field_to_curve_point(hospital_public_keys[3]),
        field_to_curve_point(hospital_public_keys[4]),
        field_to_curve_point(hospital_public_keys[5]),
        field_to_curve_point(hospital_public_keys[6]),
        field_to_curve_point(hospital_public_keys[7]),
        field_to_curve_point(hospital_public_keys[8]),
        field_to_curve_point(hospital_public_keys[9])
    ];
    
    // Create sample medical profiles
    println("1. STEP: Creating sample medical profiles");
    
    let donor_profiles: [MedicalProfile; 5] = [
        MedicalProfile { 
            blood_type: BLOOD_TYPE_O, 
            hla_antigens: [1, 2, 3, 4, 5, 6], 
            pra_score: 10, 
            age: 35, 
            additional_factors: 0x1234 as Field 
        },
        MedicalProfile { 
            blood_type: BLOOD_TYPE_A, 
            hla_antigens: [2, 3, 5, 7, 8, 9], 
            pra_score: 15, 
            age: 28, 
            additional_factors: 0x2345 as Field 
        },
        MedicalProfile { 
            blood_type: BLOOD_TYPE_B, 
            hla_antigens: [1, 3, 5, 7, 9, 11], 
            pra_score: 5, 
            age: 42, 
            additional_factors: 0x3456 as Field 
        },
        MedicalProfile { 
            blood_type: BLOOD_TYPE_AB, 
            hla_antigens: [2, 4, 6, 8, 10, 12], 
            pra_score: 20, 
            age: 50, 
            additional_factors: 0x4567 as Field 
        },
        MedicalProfile { 
            blood_type: BLOOD_TYPE_O, 
            hla_antigens: [1, 3, 6, 9, 12, 15], 
            pra_score: 25, 
            age: 33, 
            additional_factors: 0x5678 as Field 
        }
    ];
    
    let recipient_profiles: [MedicalProfile; 5] = [
        MedicalProfile { 
            blood_type: BLOOD_TYPE_A, 
            hla_antigens: [2, 4, 6, 8, 10, 12], 
            pra_score: 30, 
            age: 40, 
            additional_factors: 0x6789 as Field 
        },
        MedicalProfile { 
            blood_type: BLOOD_TYPE_B, 
            hla_antigens: [1, 3, 5, 7, 9, 11], 
            pra_score: 45, 
            age: 25, 
            additional_factors: 0x789A as Field 
        },
        MedicalProfile { 
            blood_type: BLOOD_TYPE_AB, 
            hla_antigens: [2, 3, 5, 7, 8, 9], 
            pra_score: 10, 
            age: 55, 
            additional_factors: 0x89AB as Field 
        },
        MedicalProfile { 
            blood_type: BLOOD_TYPE_O, 
            hla_antigens: [1, 2, 3, 4, 5, 6], 
            pra_score: 60, 
            age: 30, 
            additional_factors: 0x9ABC as Field 
        },
        MedicalProfile { 
            blood_type: BLOOD_TYPE_A, 
            hla_antigens: [1, 3, 6, 9, 12, 15], 
            pra_score: 15, 
            age: 45, 
            additional_factors: 0xABCD as Field 
        }
    ];
    
    // Create donors and recipients
    let mut donors: [Donor; 5] = [
        Donor { id: 0, hospital_id: 0, medical_profile: donor_profiles[0] },
        Donor { id: 0, hospital_id: 0, medical_profile: donor_profiles[1] },
        Donor { id: 0, hospital_id: 0, medical_profile: donor_profiles[2] },
        Donor { id: 0, hospital_id: 0, medical_profile: donor_profiles[3] },
        Donor { id: 0, hospital_id: 0, medical_profile: donor_profiles[4] }
    ];
    
    let mut recipients: [Recipient; 5] = [
        Recipient { id: 0, hospital_id: 0, medical_profile: recipient_profiles[0], donor_id: 0 },
        Recipient { id: 0, hospital_id: 0, medical_profile: recipient_profiles[1], donor_id: 0 },
        Recipient { id: 0, hospital_id: 0, medical_profile: recipient_profiles[2], donor_id: 0 },
        Recipient { id: 0, hospital_id: 0, medical_profile: recipient_profiles[3], donor_id: 0 },
        Recipient { id: 0, hospital_id: 0, medical_profile: recipient_profiles[4], donor_id: 0 }
    ];
    
    // Assign IDs and hospital IDs
    for i in 0..5 {
        donors[i].id = i as Field;
        donors[i].hospital_id = (i % 3) as Field;
        
        recipients[i].id = (i + 100) as Field;
        recipients[i].hospital_id = (i % 3) as Field;
        recipients[i].donor_id = i as Field;
    }
    
    println("2. STEP: Checking compatibility and generating ZK proofs");
    
    // Test compatibility and generate proofs
    let mut compatibility_proofs: [CompatibilityProof; MAX_EDGES] = [CompatibilityProof {
        hospital_id: 0,
        donor_commitment: 0,
        recipient_commitment: 0,
        compatibility_result: 0,
        proof_signature: 0
    }; MAX_EDGES];
    
    let mut proof_count = 0;
    
    // Generate proofs for all donor-recipient combinations
    for i in 0..5 {
        for j in 0..5 {
            // Skip own donor-recipient pair (they're already incompatible)
            if i != j {
                // Each hospital checks compatibility between their donor and another hospital's recipient
                let hospital_id = donors[i].hospital_id as u32;
                
                let proof = generate_compatibility_proof(
                    donors[i],
                    recipients[j],
                    hospital_private_keys[hospital_id]
                );
                
                compatibility_proofs[proof_count] = proof;
                proof_count += 1;
                
                println(f"Generated proof: donor {i} -> recipient {j}");
                //println(f"Compatible: {proof.compatibility_result}");
            }
        }
    }
    
    println(f"Generated {proof_count} compatibility proofs");
    
    // Create input commitment
    println("3. STEP: Creating commitment for ZK proofs");
    
    let mut input_fields: [Field; MAX_EDGES * 5 + 1 + MAX_HOSPITALS] = [0; MAX_EDGES * 5 + 1 + MAX_HOSPITALS];
    
    // Flatten compatibility proofs
    let mut index = 0;
    for i in 0..MAX_EDGES {
        if i < proof_count as u32 {
            input_fields[index] = compatibility_proofs[i].hospital_id;
            index += 1;
            input_fields[index] = compatibility_proofs[i].donor_commitment;
            index += 1;
            input_fields[index] = compatibility_proofs[i].recipient_commitment;
            index += 1;
            input_fields[index] = compatibility_proofs[i].compatibility_result;
            index += 1;
            input_fields[index] = compatibility_proofs[i].proof_signature;
            index += 1;
        }
    }
    
    // Add proof count
    input_fields[index] = proof_count as Field;
    index += 1;
    
    // Add hospital public keys
    for i in 0..MAX_HOSPITALS {
        input_fields[index] = hospital_public_keys[i];
        index += 1;
    }
    
    // Compute the hash of all inputs
    let input_commitment = pedersen_hash(input_fields);
    
    println("Created commitment to all ZK proofs");
    
    // Run the main circuit
    println("4. STEP: Running main kidney exchange circuit");
    
    let nonce_seed = 0x12345678 as Field;
    
    let kidney_exchange_results = main(
        compatibility_proofs,
        proof_count as Field,
        hospital_public_keys,
        hospital_public_ec_keys,
        nonce_seed,
        input_commitment
    );
    
    // Decrypt and verify results
    println("5. STEP: Hospitals decrypt their results");
    
    // Each hospital decrypts their results
    for h in 0..3 { // Just first 3 hospitals for test
        let hospital_result = decrypt_hospital_result(
            kidney_exchange_results.hospital_results[h],
            hospital_private_keys[h]
        );
        
        println("");
        println(f"Hospital {h} results:");
        //println(f"Number of cycles: {hospital_result.cycle_count}");
        
        for c in 0..hospital_result.cycle_count as u32 {
         //   println(f"Cycle {c} (length {hospital_result.cycle_lengths[c]}):");
            
            for e in 0..hospital_result.cycle_lengths[c] as u32 {
              //  println(f"Edge ID: {hospital_result.cycles[c][e]}");
            }
        }
    }
    
    println("");
    println("=== Privacy-Preserving Kidney Exchange Test Completed ===");
}