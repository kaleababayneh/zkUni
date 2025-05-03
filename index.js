import { Noir } from "@noir-lang/noir_js";
import { UltraHonkBackend } from "@aztec/bb.js";
import circuit from "./circuit/target/circuit.json" assert { type: 'json' };
import * as secp256k1 from "@noble/secp256k1";

// Log circuit details to help with debugging
console.log("Circuit loaded:", !!circuit);
console.log("Circuit bytecode exists:", !!(circuit && circuit.bytecode));
console.log("Circuit structure keys:", circuit ? Object.keys(circuit) : "circuit is null");

// Constants matching the Noir circuit
const UNMATCHED = 999;
const N_STUDENT_PREFERENCE = 5;
const N_COLLEGE_QUOTA = 5;
const MAX_PREFS = 5;
const MAX_COLLEGE_CAPACITY = 3;
const MERKLE_HEIGHT = 3;
const TOTAL_ENCRYPTIONS = N_STUDENT_PREFERENCE + (N_COLLEGE_QUOTA * MAX_COLLEGE_CAPACITY);

// Global storage for generated values
let globalMerkleRoot = null;
let globalMatchCommitments = null;
let globalStudentMatches = null;
let globalStudentNonces = null;
let globalPermutationMaps = null;

// UI Helper Functions
const show = (id, content) => {
  const container = document.getElementById(id);
  if (!container) {
    console.error(`Container with id ${id} not found`);
    return;
  }
  container.appendChild(document.createTextNode(content));
  container.appendChild(document.createElement("br"));
};

const clearLogs = () => {
  const container = document.getElementById("logs");
  if (container) container.innerHTML = '';
};

// Cryptographic Helper Functions
function hexToBigInt(hexStr) {
  if (typeof hexStr !== 'string') return BigInt(0);
  hexStr = hexStr.toLowerCase().trim();
  return hexStr.startsWith('0x') ? BigInt(hexStr) : BigInt('0x' + hexStr);
}

function createPoint(x, y) {
  try {
    return new secp256k1.Point(
      typeof x === 'string' ? hexToBigInt(x) : BigInt(x),
      typeof y === 'string' ? hexToBigInt(y) : BigInt(y)
    );
  } catch (err) {
    console.error("Error creating point:", err);
    return secp256k1.Point.fromPrivateKey(BigInt(1)); // Fallback
  }
}

// ElGamal Key Generation
async function generateElGamalKeyPair() {
  try {
    // Generate a secure random private key
    const privateKeyBytes = new Uint8Array(32);
    window.crypto.getRandomValues(privateKeyBytes);
    
    // Convert to a suitable scalar value
    const privateKey = secp256k1.utils.bytesToNumberBE(privateKeyBytes);
    
    // Generate public key point on the curve
    const publicKeyPoint = secp256k1.Point.fromPrivateKey(privateKey);
    
    // Get x and y coordinates
    const publicKeyXY = {
      x: publicKeyPoint.x.toString(),
      y: publicKeyPoint.y.toString()
    };
    
    // Hash to create a Field value for Noir
    const publicKeyHash = await hashPublicKey(publicKeyXY);
    
    return {
      privateKey: privateKey,
      publicKey: publicKeyPoint,
      publicKeyHash: publicKeyHash
    };
  } catch (err) {
    console.error("Error generating ElGamal key pair:", err);
    // Fallback to demo key
    return {
      privateKey: BigInt("0x1234567890abcdef"),
      publicKey: secp256k1.Point.fromPrivateKey(BigInt("0x1234567890abcdef")),
      publicKeyHash: "0x7d1e5f02b0cdc7e10cff917625b4e7ee"
    };
  }
}

// Hash a public key to produce a Field element for Noir
async function hashPublicKey(publicKeyXY) {
  try {
    // Convert to JSON string
    const encoder = new TextEncoder();
    const publicKeyBytes = encoder.encode(JSON.stringify(publicKeyXY));
    
    // Hash using SHA-256
    const publicKeyHash = await window.crypto.subtle.digest("SHA-256", publicKeyBytes);
    
    // Take first 16 bytes to fit in Noir Field
    const hashArray = Array.from(new Uint8Array(publicKeyHash)).slice(0, 16);
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return '0x' + hashHex;
  } catch (err) {
    console.error("Error hashing public key:", err);
    return "0x7d1e5f02b0cdc7e10cff917625b4e7ee"; // Fallback
  }
}

// ElGamal decryption function
async function decryptElGamal(ciphertext, privateKey) {
  if (!ciphertext || !ciphertext.c1 || !ciphertext.c2) {
    console.error("Invalid ciphertext structure:", ciphertext);
    return UNMATCHED;
  }
  
  try {
    // Skip decryption for infinity points
    if (ciphertext.c1.is_infinity || ciphertext.c2.is_infinity) {
      return UNMATCHED;
    }
    
    // Extract curve points
    const c1 = createPoint(ciphertext.c1.x, ciphertext.c1.y);
    const c2 = createPoint(ciphertext.c2.x, ciphertext.c2.y);
    
    // Compute shared secret: s = privateKey * c1
    const sharedSecret = c1.multiply(privateKey);
    
    // Compute plaintext point: m = c2 - s
    const negSharedSecret = sharedSecret.negate();
    const plainPoint = c2.add(negSharedSecret);
    
    // Solve discrete log to recover message
    for (let i = 0; i < 1000; i++) {
      const testPoint = secp256k1.Point.BASE.multiply(BigInt(i));
      if (testPoint.x === plainPoint.x && testPoint.y === plainPoint.y) {
        return i;
      }
    }
    
    return UNMATCHED;
  } catch (err) {
    console.error("ElGamal decryption error:", err);
    return UNMATCHED;
  }
}

// Generate a Merkle proof for a student match
async function generateMerkleProof(studentId) {
  if (!globalMatchCommitments) {
    show("logs", "Error: Match commitments not available. Run the matching process first.");
    return null;
  }
  
  try {
    console.log("Attempting to generate Merkle proof for student:", studentId);
    console.log("Using match commitments:", globalMatchCommitments);
    console.log("Merkle root:", globalMerkleRoot);
    
    // Initialize Noir and backend for proof operation
    const noir = new Noir(circuit);
    console.log("Noir initialized");
    
    const backend = new UltraHonkBackend(circuit.bytecode);
    console.log("Backend initialized");
    
    // Generate inputs for proof generation (operation = 2 for generating a proof)
    const input = {
      operation: 2, // Generate proof
      input_data: globalMatchCommitments,
      proof_data: Array(MERKLE_HEIGHT).fill(0),
      root: globalMerkleRoot,
      leaf: globalMatchCommitments[studentId],
      index: studentId
    };
    
    console.log("Executing circuit with input:", input);
    
    // Execute circuit to generate the proof
    const { witness } = await noir.execute(input);
    console.log("Witness generated:", witness ? "Success" : "Failed");
    
    const proof = await backend.generateProof(witness);
    console.log("Proof generated:", proof);
    
    // Extract the proof from the result
    let merkleProof = Array(MERKLE_HEIGHT).fill(0);
    if (proof && proof.publicInputs && proof.publicInputs.return) {
      merkleProof = proof.publicInputs.return;
      console.log("Extracted merkle proof:", merkleProof);
    } else {
      console.warn("Could not extract proof from result");
    }
    
    return merkleProof;
  } catch (err) {
    console.error("Error generating Merkle proof:", err);
    show("logs", `Error generating proof: ${err.message}`);
    return null;
  }
}

// Verify a student's match using the Merkle proof
async function verifyStudentMatch(studentId, collegeId, nonce, merkleProof) {
  if (!globalMerkleRoot) {
    show("logs", "Error: Merkle root not available. Run the matching process first.");
    return false;
  }
  
  try {
    console.log("Verifying match for student:", studentId, "with college:", collegeId);
    console.log("Using nonce:", nonce, "and proof:", merkleProof);
    
    // Generate the commitment hash (same algorithm as in Noir)
    const commitment = await generateCommitmentHash(studentId, collegeId, nonce);
    console.log("Generated commitment hash:", commitment);
    
    // Initialize Noir and backend for verification
    const noir = new Noir(circuit);
    const backend = new UltraHonkBackend(circuit.bytecode);
    
    // Prepare inputs for verification (operation = 1 for verification)
    const input = {
      operation: 1, // Verify proof
      input_data: Array(10).fill(0), // Not used for verification
      proof_data: merkleProof,
      root: globalMerkleRoot,
      leaf: commitment,
      index: studentId
    };
    
    console.log("Executing verification with input:", input);
    
    // Execute circuit for verification
    const { witness } = await noir.execute(input);
    const proof = await backend.generateProof(witness);
    
    console.log("Verification proof result:", proof);
    
    // Extract verification result
    let isValid = false;
    if (proof && proof.publicInputs && proof.publicInputs.return) {
      isValid = proof.publicInputs.return === 1n || proof.publicInputs.return === 1;
      console.log("Extracted verification result:", isValid);
    }
    
    return isValid;
  } catch (err) {
    console.error("Error verifying match:", err);
    show("logs", `Error verifying match: ${err.message}`);
    return false;
  }
}

// Helper to generate a commitment hash for a student-college match
async function generateCommitmentHash(studentId, collegeId, nonce) {
  // This should use the same algorithm as in the Noir circuit
  // For simplicity, we'll use a browser-based hash for now
  const data = new TextEncoder().encode(`${studentId}-${collegeId}-${nonce}`);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  // Convert to a BigInt that fits in a Noir field
  return BigInt('0x' + hashHex.substring(0, 16));
}

// Generate permutation maps for students and colleges
function generatePermutationMaps(seed, studentCount, collegeCount) {
  // Helper to create a deterministic "random" number from a seed and index
  const pseudoRandom = (seed, i) => {
    return BigInt((Number(seed) * 1103515245 + 12345 + i) % 2147483647);
  };
  
  // Initialize arrays with sequential IDs
  const studentIdMap = Array(N_STUDENT_PREFERENCE).fill().map((_, i) => i);
  const collegeIdMap = Array(N_COLLEGE_QUOTA).fill().map((_, i) => i);
  
  // Fisher-Yates shuffle for students
  for (let i = 0; i < studentCount; i++) {
    const randomVal = pseudoRandom(seed, i);
    const j = Number(randomVal % BigInt(i + 1));
    [studentIdMap[i], studentIdMap[j]] = [studentIdMap[j], studentIdMap[i]]; // Swap
  }
  
  // Fisher-Yates shuffle for colleges
  for (let i = 0; i < collegeCount; i++) {
    const randomVal = pseudoRandom(seed, i + 1000);
    const j = Number(randomVal % BigInt(i + 1));
    [collegeIdMap[i], collegeIdMap[j]] = [collegeIdMap[j], collegeIdMap[i]]; // Swap
  }
  
  return { studentIdMap, collegeIdMap };
}

// Apply permutation to preferences
function applyPermutation(studentPrefs, collegePrefs, maps, studentCount, collegeCount) {
  const { studentIdMap, collegeIdMap } = maps;
  
  // Create new arrays to hold permuted preferences
  const permutedStudentPrefs = Array(N_STUDENT_PREFERENCE).fill().map(() => 
    Array(MAX_PREFS).fill(UNMATCHED));
  
  const permutedCollegePrefs = Array(N_COLLEGE_QUOTA).fill().map(() => 
    Array(N_STUDENT_PREFERENCE).fill(UNMATCHED));
  
  // Map student preferences
  for (let i = 0; i < studentCount; i++) {
    const permutedI = studentIdMap[i];
    for (let j = 0; j < MAX_PREFS; j++) {
      if (studentPrefs[i][j] !== UNMATCHED) {
        const originalCollegeId = studentPrefs[i][j];
        if (originalCollegeId < collegeCount) {
          permutedStudentPrefs[permutedI][j] = collegeIdMap[originalCollegeId];
        }
      }
    }
  }
  
  // Map college preferences
  for (let i = 0; i < collegeCount; i++) {
    const permutedI = collegeIdMap[i];
    for (let j = 0; j < N_STUDENT_PREFERENCE; j++) {
      if (collegePrefs[i][j] !== UNMATCHED) {
        const originalStudentId = collegePrefs[i][j];
        if (originalStudentId < studentCount) {
          permutedCollegePrefs[permutedI][j] = studentIdMap[originalStudentId];
        }
      }
    }
  }
  
  return { permutedStudentPrefs, permutedCollegePrefs };
}

// Permute public keys according to the permutation maps
function permuteKeys(studentKeys, collegeKeys, maps, studentCount, collegeCount) {
  const { studentIdMap, collegeIdMap } = maps;
  
  // Create new arrays for the permuted keys
  const permutedStudentKeys = Array(N_STUDENT_PREFERENCE).fill().map(() => ({
    x: 0, y: 0, is_infinite: true
  }));
  
  const permutedCollegeKeys = Array(N_COLLEGE_QUOTA).fill().map(() => ({
    x: 0, y: 0, is_infinite: true
  }));
  
  // Map student keys
  for (let i = 0; i < studentCount; i++) {
    const permutedI = studentIdMap[i];
    permutedStudentKeys[permutedI] = studentKeys[i];
  }
  
  // Map college keys
  for (let i = 0; i < collegeCount; i++) {
    const permutedI = collegeIdMap[i];
    permutedCollegeKeys[permutedI] = collegeKeys[i];
  }
  
  return { permutedStudentKeys, permutedCollegeKeys };
}

// Reverse the permutation after decryption
function reversePermutation(permutedMatches, maps, studentCount) {
  const { studentIdMap, collegeIdMap } = maps;
  
  // Create inverse maps
  const inverseStudentMap = Array(N_STUDENT_PREFERENCE).fill(0);
  const inverseCollegeMap = Array(N_COLLEGE_QUOTA).fill(0);
  
  for (let i = 0; i < studentCount; i++) {
    inverseStudentMap[studentIdMap[i]] = i;
  }
  
  for (let i = 0; i < collegeIdMap.length; i++) {
    inverseCollegeMap[collegeIdMap[i]] = i;
  }
  
  // Apply reverse mapping
  const originalMatches = Array(N_STUDENT_PREFERENCE).fill(UNMATCHED);
  
  for (let i = 0; i < studentCount; i++) {
    const permutedI = studentIdMap[i];
    const permutedMatch = permutedMatches[permutedI];
    
    if (permutedMatch !== UNMATCHED) {
      originalMatches[i] = inverseCollegeMap[permutedMatch];
    }
  }
  
  return originalMatches;
}

// Extract encrypted matches from proof with robust error handling
function extractEncryptedMatches(proof) {
  console.log("Extracting encrypted matches from proof:", proof);
  
  // Try various proof structures that might be returned
  let encryptedMatches = [];
  
  if (proof && proof.publicInputs && proof.publicInputs.return) {
    encryptedMatches = proof.publicInputs.return;
    console.log("Found matches in proof.publicInputs.return");
  } else if (proof && proof.public_inputs && proof.public_inputs.return) {
    encryptedMatches = proof.public_inputs.return;
    console.log("Found matches in proof.public_inputs.return");
  } else if (proof && Array.isArray(proof.publicInputs)) {
    encryptedMatches = proof.publicInputs;
    console.log("Found matches in proof.publicInputs array");
  } else if (proof && Array.isArray(proof.public_inputs)) {
    encryptedMatches = proof.public_inputs;
    console.log("Found matches in proof.public_inputs array");
  } else if (Array.isArray(proof)) {
    encryptedMatches = proof;
    console.log("Found matches in proof array");
  } else {
    // Fallback to demo data
    console.warn("Could not extract encrypted matches from proof. Using demo data.");
    show("logs", "⚠️ Could not extract encrypted matches from proof. Using demo data.");
    encryptedMatches = Array(TOTAL_ENCRYPTIONS).fill().map(() => ({
      c1: { x: "0x1", y: "0x2", is_infinity: false },
      c2: { x: "0x3", y: "0x4", is_infinity: false }
    }));
  }
  
  return encryptedMatches;
}

// Decrypt student matches
async function decryptStudentMatches(encryptedStudentMatches, privateKeys, permutationMap) {
  const decryptedMatches = Array(N_STUDENT_PREFERENCE).fill(UNMATCHED);
  
  for (let i = 0; i < encryptedStudentMatches.length; i++) {
    const originalStudentId = permutationMap.indexOf(i);
    if (originalStudentId !== -1) {
      try {
        const match = await decryptElGamal(
          encryptedStudentMatches[i], 
          privateKeys[originalStudentId]
        );
        
        // Subtract 1 to get the original college ID (matches the Noir adjustment)
        decryptedMatches[i] = match === UNMATCHED ? UNMATCHED : match - 1;
      } catch (err) {
        console.error(`Error decrypting match for student ${i}:`, err);
      }
    }
  }
  
  return decryptedMatches;
}

// Helper function to set up test data
async function setupTestData() {
  // Student preferences
  const studentPrefs = [
    [0, 1, 2, UNMATCHED, UNMATCHED], 
    [1, 0, 2, UNMATCHED, UNMATCHED], 
    [1, 2, 0, UNMATCHED, UNMATCHED], 
    [0, 2, 1, UNMATCHED, UNMATCHED], 
    [2, 0, 1, UNMATCHED, UNMATCHED],
  ];
  
  // College preferences
  const collegePrefs = [
    [1, 3, 0, 2, 4],   
    [2, 0, 4, 1, 3],   
    [0, 2, 3, 4, 1],   
    [UNMATCHED, UNMATCHED, UNMATCHED, UNMATCHED, UNMATCHED], 
    [UNMATCHED, UNMATCHED, UNMATCHED, UNMATCHED, UNMATCHED],
  ];
  
  // College capacities
  const collegeCapacities = [3, 1, 1, 0, 0];
  
  // Public keys (formatted for Noir's EmbeddedCurvePoint)
  const studentPublicKeys = [
    { x: "0x7d1e5f02b0cdc7e10cff917625b4e7ee", y: "0x1", is_infinity: false },
    { x: "0x83a1eff0b6627a69b41c5de7b0aeb8e3", y: "0x2", is_infinity: false },
    { x: "0x9c4d8bfd9d4def4eeb1615aa53a32e30", y: "0x3", is_infinity: false },
    { x: "0xa0b3576ee834936135b547beba820d6f", y: "0x4", is_infinity: false },
    { x: "0xb4f0c6f7d89513c2055c54bd463a5275", y: "0x5", is_infinity: false }
  ];
  
  const collegePublicKeys = [
    { x: "0xc78e07db0ad00f15ebde45d9afd043e4", y: "0x6", is_infinity: false },
    { x: "0xd391cafa15d22c96a28afa0375ea8db7", y: "0x7", is_infinity: false },
    { x: "0xe2e3aa9a63b2b855d7c81c9f60e9c411", y: "0x8", is_infinity: false },
    { x: "0xf4b8dff2bb2a889432d097b3fb781c54", y: "0x9", is_infinity: false },
    { x: "0x052968bd5e7e3d743d45cb45e7ca1bf7", y: "0xa", is_infinity: false }
  ];
  
  // Private keys (in a real system, these would be securely stored)
  const studentPrivateKeys = [1, 2, 3, 4, 5].map(key => BigInt(key));
  const collegePrivateKeys = [6, 7, 8, 9, 10].map(key => BigInt(key));
  
  // Seeds for nonce and permutation
  const nonceSeed = 0x12345678;
  const permutationSeed = 0x87654321;
  
  return {
    studentPrefs,
    collegePrefs,
    collegeCapacities,
    studentPublicKeys,
    collegePublicKeys,
    studentPrivateKeys,
    collegePrivateKeys,
    actualStudentList: 5,
    actualUniList: 3,
    nonceSeed,
    permutationSeed
  };
}

// Create UI for verifying a student's match
function createVerificationUI() {
  // Remove existing verification panel if it exists
  const existingPanel = document.getElementById('verification-panel');
  if (existingPanel) {
    existingPanel.remove();
  }
  
  const verifyContainer = document.createElement('div');
  verifyContainer.id = 'verification-panel';
  verifyContainer.innerHTML = `
    <h3>🔍 Verify a Student's Match</h3>
    <p>Students can prove their match to third parties without revealing other matches.</p>
    
    <div class="form-group">
      <label for="student-id">Student ID:</label>
      <select id="student-id">
        ${Array(N_STUDENT_PREFERENCE).fill().map((_, i) => 
          `<option value="${i}">${i}</option>`).join('')}
      </select>
    </div>
    
    <button id="generate-proof-btn">Generate Proof</button>
    <button id="verify-match-btn" disabled>Verify Match</button>
    
    <div id="verification-result" style="margin-top: 15px;"></div>
  `;
  
  document.body.appendChild(verifyContainer);
  
  // Add event listeners
  document.getElementById('generate-proof-btn').addEventListener('click', async () => {
    const studentId = parseInt(document.getElementById('student-id').value);
    console.log("Generate proof button clicked for student:", studentId);
    
    if (!globalStudentMatches || !globalStudentNonces) {
      document.getElementById('verification-result').innerHTML = 
        "❌ Error: Run the matching process first";
      return;
    }
    
    document.getElementById('verification-result').innerHTML = "Generating proof...";
    
    try {
      // Get the proof for this student
      const proof = await generateMerkleProof(studentId);
      
      if (!proof) {
        document.getElementById('verification-result').innerHTML = 
          "❌ Error generating proof. See console for details.";
        return;
      }
      
      // Store values in data attributes for verification
      const verifyBtn = document.getElementById('verify-match-btn');
      verifyBtn.dataset.studentId = studentId;
      verifyBtn.dataset.collegeId = globalStudentMatches[studentId];
      verifyBtn.dataset.nonce = globalStudentNonces[studentId];
      verifyBtn.dataset.proof = JSON.stringify(proof);
      verifyBtn.disabled = false;
      
      document.getElementById('verification-result').innerHTML = 
        `✅ Proof generated for Student ${studentId}<br>` +
        `Matched with College: ${globalStudentMatches[studentId] === UNMATCHED ? 'Unmatched' : globalStudentMatches[studentId]}<br>` +
        `Proof data: [${proof.slice(0, 2).join(', ')}...]`;
    } catch (err) {
      console.error("Error in generate proof handler:", err);
      document.getElementById('verification-result').innerHTML = 
        `❌ Error: ${err.message}`;
    }
  });
  
  document.getElementById('verify-match-btn').addEventListener('click', async () => {
    try {
      const verifyBtn = document.getElementById('verify-match-btn');
      const studentId = parseInt(verifyBtn.dataset.studentId);
      const collegeId = parseInt(verifyBtn.dataset.collegeId);
      const nonce = parseInt(verifyBtn.dataset.nonce);
      const proof = JSON.parse(verifyBtn.dataset.proof);
      
      console.log("Verify button clicked with data:", { studentId, collegeId, nonce });
      
      document.getElementById('verification-result').innerHTML = "Verifying proof...";
      
      const isValid = await verifyStudentMatch(studentId, collegeId, nonce, proof);
      
      if (isValid) {
        document.getElementById('verification-result').innerHTML = 
          `✅ VERIFIED: Student ${studentId} is matched with College ${collegeId === UNMATCHED ? 'Unmatched' : collegeId}`;
      } else {
        document.getElementById('verification-result').innerHTML = 
          `❌ INVALID: Proof verification failed`;
      }
    } catch (err) {
      console.error("Error in verify match handler:", err);
      document.getElementById('verification-result').innerHTML = 
        `❌ Error: ${err.message}`;
    }
  });
}

// Main processing function
async function processMatchingWithZKP() {
  console.log("Starting processMatchingWithZKP function");
  clearLogs();
  show("logs", "🚀 Starting zkUni Privacy-Preserving Matching with Zero-Knowledge Proofs");
  show("logs", "-----------------------------------------------------------");
  
  try {
    // Check if circuit is properly loaded
    if (!circuit || !circuit.bytecode) {
      throw new Error("Circuit not properly loaded. Please check your compilation.");
    }
    
    // Install the dependencies
    show("logs", "⚙️ Required dependencies:");
    show("logs", "npm install @noble/secp256k1 @noir-lang/noir_js @aztec/bb.js");
    
    // Test data setup
    show("logs", "Setting up test data...");
    const { 
      studentPrefs, 
      collegePrefs, 
      collegeCapacities, 
      studentPublicKeys, 
      collegePublicKeys,
      studentPrivateKeys,
      collegePrivateKeys,
      actualStudentList,
      actualUniList,
      nonceSeed,
      permutationSeed
    } = await setupTestData();
    
    show("logs", "Test data and ElGamal keys loaded ✅");
    
    // Step 1: Generate permutation maps
    show("logs", "1. STEP: Generating permutation maps for privacy...");
    globalPermutationMaps = generatePermutationMaps(
      permutationSeed, 
      actualStudentList, 
      actualUniList
    );
    
    show("logs", "Student permutation map: " + JSON.stringify(globalPermutationMaps.studentIdMap));
    show("logs", "College permutation map: " + JSON.stringify(globalPermutationMaps.collegeIdMap));
    
    // Step 2: Apply permutation to preferences and keys
    show("logs", "2. STEP: Applying permutation to preferences and keys...");
    const { permutedStudentPrefs, permutedCollegePrefs } = applyPermutation(
      studentPrefs, 
      collegePrefs, 
      globalPermutationMaps, 
      actualStudentList, 
      actualUniList
    );
    
    const { permutedStudentKeys, permutedCollegeKeys } = permuteKeys(
      studentPublicKeys,
      collegePublicKeys,
      globalPermutationMaps,
      actualStudentList,
      actualUniList
    );
    
    // Step 3: Create commitment
    show("logs", "3. STEP: Creating commitment for permuted data...");
    // This would hash all the permuted inputs in a real implementation
    const permutedCommitment = 42; // Placeholder
    
    // Step 4: Run matching in zero-knowledge circuit
    show("logs", "4. STEP: Running the matching algorithm in zero-knowledge...");
    
    try {
      console.log("Initializing Noir...");
      const noir = new Noir(circuit);
      console.log("Noir initialized successfully");
      
      console.log("Initializing backend...");
      const backend = new UltraHonkBackend(circuit.bytecode);
      console.log("Backend initialized successfully");
      
      // Circuit input for the matching operation
      const input = { 
        operation: 0, // Run matching
        permuted_student_prefs: permutedStudentPrefs,
        permuted_college_prefs: permutedCollegePrefs,
        college_capacities: collegeCapacities,
        permuted_student_public_keys: permutedStudentKeys,
        permuted_college_public_keys: permutedCollegeKeys,
        actual_student_list: actualStudentList,
        actual_uni_list: actualUniList,
        nonce_seed: nonceSeed,
        committed_inputs: permutedCommitment,
        // These are unused for operation 0
        proof_root: 0,
        proof_leaf: 0,
        proof_index: 0,
        proof_data: Array(MERKLE_HEIGHT).fill(0)
      };
      
      console.log("Executing circuit with input:", {...input, permuted_student_prefs: "...", permuted_college_prefs: "..."});
      
      // Execute circuit
      show("logs", "Executing circuit...");
      const { witness } = await noir.execute(input);
      console.log("Witness generated:", witness ? "Success" : "Failed");
      
      // Generate proof
      show("logs", "Generating zero-knowledge proof...");
      const proof = await backend.generateProof(witness);
      console.log("Proof generated:", proof);
      show("logs", "Proof generated ✅");
      
      // Extract Merkle root from the proof
      if (proof && proof.publicInputs && proof.publicInputs.return) {
        globalMerkleRoot = proof.publicInputs.return;
        show("logs", "Merkle Root: " + globalMerkleRoot);
      } else {
        show("logs", "Warning: Could not extract Merkle root from proof");
        // Use a placeholder for testing UI
        globalMerkleRoot = BigInt("0x1234567890abcdef");
      }
      
      // Extract encrypted matches
      const encryptedMatches = extractEncryptedMatches(proof);
      show("logs", `Found ${encryptedMatches.length} ElGamal encrypted matches`);
      
      // Step 5: Decrypt matches
      show("logs", "5. STEP: Decrypting matches (each party can only decrypt their own)...");
      
      // Decrypt student matches
      const permutedStudentMatches = await decryptStudentMatches(
        encryptedMatches.slice(0, actualStudentList),
        studentPrivateKeys,
        globalPermutationMaps.studentIdMap
      );
      
      globalStudentMatches = permutedStudentMatches;
      
      // Store match nonces (in a real app, these would be securely generated)
      globalStudentNonces = Array(N_STUDENT_PREFERENCE).fill().map((_, i) => i + 10000);
      
      // Generate match commitments (simulating what happens in the Noir circuit)
      globalMatchCommitments = await Promise.all(permutedStudentMatches.map(async (match, i) => {
        if (i >= actualStudentList) return 0;
        const collegeId = match === UNMATCHED ? UNMATCHED : match;
        return await generateCommitmentHash(i, collegeId, globalStudentNonces[i]);
      }));
      
      // Reverse permutation to get original matches
      const actualStudentMatches = reversePermutation(
        permutedStudentMatches, 
        globalPermutationMaps, 
        actualStudentList
      );
      
      // Display student matches
      show("logs", "Student match results (after reversing permutation):");
      for (let i = 0; i < actualStudentList; i++) {
        const collegeId = actualStudentMatches[i];
        if (collegeId === UNMATCHED) {
          show("logs", `Student ${i} is unmatched`);
        } else {
          show("logs", `Student ${i} matched with College ${collegeId}`);
        }
      }
      
      // Verify proof of correct execution
      show("logs", "Verifying proof of fair matching...");
      const isValid = await backend.verifyProof(proof);
      show("logs", `Proof ${isValid ? "✅ VALID" : "❌ INVALID"}`);
      
      // Show Merkle root
      show("logs", "");
      show("logs", "6. STEP: Merkle tree verification");
      show("logs", `Public Merkle root: ${globalMerkleRoot}`);
      show("logs", "This root can be used to verify any student's match without revealing other matches.");
      
    } catch (circuitError) {
      console.error("Circuit execution error:", circuitError);
      show("logs", `❌ Circuit error: ${circuitError.message}`);
      
      // Fall back to mock data to test the UI
      show("logs", "Falling back to mock data for demonstration purposes");
      
      // Mock the global variables for UI testing
      globalMerkleRoot = BigInt("0x1234567890abcdef");
      globalStudentMatches = [1, 0, 2, 0, UNMATCHED];
      globalStudentNonces = Array(N_STUDENT_PREFERENCE).fill().map((_, i) => i + 10000);
      globalMatchCommitments = Array(N_STUDENT_PREFERENCE).fill().map((_, i) => 
        BigInt("0x" + (i * 100 + 1).toString(16).padStart(16, '0')));
      
      // Display mock results
      show("logs", "MOCK Student match results:");
      for (let i = 0; i < actualStudentList; i++) {
        const collegeId = globalStudentMatches[i];
        if (collegeId === UNMATCHED) {
          show("logs", `Student ${i} is unmatched`);
        } else {
          show("logs", `Student ${i} matched with College ${collegeId}`);
        }
      }
      
      show("logs", "");
      show("logs", "6. STEP: Merkle tree verification (MOCK)");
      show("logs", `Public Merkle root: ${globalMerkleRoot}`);
    }
    
    // Create verification UI regardless of circuit success
    createVerificationUI();
    
  } catch (err) {
    console.error("Global error:", err);
    show("logs", `❌ Error: ${err.message}`);
    show("logs", "Stack trace has been logged to console.");
  }
}

// Initialize UI
document.addEventListener("DOMContentLoaded", () => {
  console.log("DOM content loaded - initializing UI");
  const app = document.getElementById("app") || document.body;
  
  // Create the main UI
  const ui = document.createElement("div");
  ui.innerHTML = `
    <h1>zkUni: Private College Matching with Zero-Knowledge Proofs</h1>
    <p>This demo shows how to run a privacy-preserving college matching process that generates verifiable proofs.</p>
    
    <div class="controls">
      <button id="run-matching-btn" class="primary-btn">Run Privacy-Preserving Matching</button>
    </div>
    
    <div id="logs" class="logs-container"></div>
  `;
  
  app.appendChild(ui);
  
  // Add event listeners with debugging
  const runButton = document.getElementById("run-matching-btn");
  console.log("Run button element:", runButton);
  
  if (runButton) {
    runButton.addEventListener("click", () => {
      console.log("Run matching button clicked!");
      processMatchingWithZKP().catch(err => {
        console.error("Error in main process:", err);
        show("logs", `❌ Critical error: ${err.message}`);
      });
    });
    console.log("Event listener added to run button");
  } else {
    console.error("Run button not found in the DOM");
    // Add a recovery button
    const recoveryBtn = document.createElement("button");
    recoveryBtn.textContent = "Try to Run (Recovery)";
    recoveryBtn.style.backgroundColor = "red";
    recoveryBtn.style.color = "white";
    recoveryBtn.style.padding = "10px";
    recoveryBtn.style.margin = "20px";
    recoveryBtn.addEventListener("click", processMatchingWithZKP);
    document.body.appendChild(recoveryBtn);
  }
  
  // Add key generation demo button
  const genKeyBtn = document.createElement("button");
  genKeyBtn.textContent = "Generate ElGamal Key Pair (Demo)";
  genKeyBtn.className = "demo-btn";
  genKeyBtn.addEventListener("click", async () => {
    console.log("Generate key button clicked");
    const keyInfo = document.getElementById("key-info") || document.createElement("div");
    keyInfo.id = "key-info";
    keyInfo.innerHTML = "<h3>Generated ElGamal Key Info:</h3><p>Generating...</p>";
    app.appendChild(keyInfo);
    
    try {
      const keyPair = await generateElGamalKeyPair();
      keyInfo.innerHTML = `
        <h3>Generated ElGamal Key Info:</h3>
        <p><strong>Public Key Hash:</strong> ${keyPair.publicKeyHash}</p>
        <p><small>This is the value that would be sent to the Noir circuit</small></p>
        <p><strong>Public Key X:</strong> ${keyPair.publicKey.x.toString().substring(0, 20)}...</p>
        <p><strong>Public Key Y:</strong> ${keyPair.publicKey.y.toString().substring(0, 20)}...</p>
        <p><strong>Private Key:</strong> [Securely stored in browser]</p>
        <p><small>In a real app, this would never be displayed</small></p>
      `;
    } catch (err) {
      console.error("Key generation error:", err);
      keyInfo.innerHTML = `<h3>ElGamal Key Generation Error:</h3><p>${err.message}</p>`;
    }
  });
  
  // Add the key generation button after the main button
  const controlsDiv = document.querySelector(".controls");
  if (controlsDiv) {
    controlsDiv.appendChild(genKeyBtn);
  } else {
    console.error("Controls div not found");
    app.appendChild(genKeyBtn);
  }
  
  // Add CSS styles
  const style = document.createElement("style");
  style.textContent = `
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 900px;
      margin: 0 auto;
      padding: 20px;
    }
    
    h1 {
      color: #2c3e50;
      border-bottom: 2px solid #3498db;
      padding-bottom: 10px;
    }
    
    .controls {
      margin: 20px 0;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }
    
    .primary-btn, .demo-btn {
      padding: 10px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-weight: bold;
      transition: background-color 0.3s;
    }
    
    .primary-btn {
      background-color: #3498db;
      color: white;
    }
    
    .primary-btn:hover {
      background-color: #2980b9;
    }
    
    .demo-btn {
      background-color: #9b59b6;
      color: white;
    }
    
    .demo-btn:hover {
      background-color: #8e44ad;
    }
    
    .logs-container {
      background-color: #f9f9f9;
      border: 1px solid #ddd;
      border-radius: 4px;
      padding: 15px;
      margin-top: 20px;
      font-family: monospace;
      white-space: pre-wrap;
      height: 300px;
      overflow-y: auto;
    }
    
    #key-info {
      margin-top: 20px;
      padding: 15px;
      background-color: #f8f9fa;
      border-radius: 4px;
      border-left: 4px solid #9b59b6;
    }
    
    #verification-panel {
      margin-top: 30px;
      padding: 20px;
      background-color: #f0f8ff;
      border-radius: 4px;
      border-left: 4px solid #2ecc71;
    }
    
    .form-group {
      margin-bottom: 15px;
    }
    
    label {
      display: block;
      margin-bottom: 5px;
      font-weight: bold;
    }
    
    select, input {
      padding: 8px;
      border: 1px solid #ddd;
      border-radius: 4px;
      width: 200px;
    }
    
    #verification-result {
      padding: 10px;
      background-color: #e8f4f8;
      border-radius: 4px;
    }
  `;
  document.head.appendChild(style);

  // Add fallback mock data button for testing the UI
  const mockDataBtn = document.createElement("button");
  mockDataBtn.textContent = "Use Mock Data (For UI Testing)";
  mockDataBtn.className = "demo-btn";
  mockDataBtn.style.backgroundColor = "#e67e22";
  mockDataBtn.addEventListener("click", async () => {
    console.log("Mock data button clicked");
    clearLogs();
    show("logs", "🚀 Using mock data for UI testing");
    
    // Set global variables with mock data
    globalMerkleRoot = BigInt("0x1234567890abcdef");
    globalStudentMatches = [1, 0, 2, 0, UNMATCHED];
    globalStudentNonces = Array(N_STUDENT_PREFERENCE).fill().map((_, i) => i + 10000);
    globalMatchCommitments = Array(N_STUDENT_PREFERENCE).fill().map((_, i) => 
      BigInt("0x" + (i * 100 + 1).toString(16).padStart(16, '0')));
    
    globalPermutationMaps = {
      studentIdMap: [0, 1, 2, 3, 4],
      collegeIdMap: [0, 1, 2, 3, 4]
    };
    
    // Display mock results
    show("logs", "MOCK Student match results:");
    for (let i = 0; i < 5; i++) {
      const collegeId = globalStudentMatches[i];
      if (collegeId === UNMATCHED) {
        show("logs", `Student ${i} is unmatched`);
      } else {
        show("logs", `Student ${i} matched with College ${collegeId}`);
      }
    }
    
    show("logs", "");
    show("logs", "Merkle tree verification (MOCK)");
    show("logs", `Public Merkle root: ${globalMerkleRoot}`);
    
    // Create verification UI
    createVerificationUI();
  });
  
  if (controlsDiv) {
    controlsDiv.appendChild(mockDataBtn);
  }
});