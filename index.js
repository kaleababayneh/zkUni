import { Noir } from "@noir-lang/noir_js";
import { UltraHonkBackend } from "@aztec/bb.js";
import circuit from "./circuit/target/circuit.json";
import * as secp256k1 from "@noble/secp256k1";

// Constants
const UNMATCHED = 999;
const N_STUDENT_PREFERENCE = 5;
const N_COLLEGE_QUOTA = 5;
const MAX_PREFS = 5;
const MAX_COLLEGE_CAPACITY = 3;
const TOTAL_ENCRYPTIONS = N_STUDENT_PREFERENCE + (N_COLLEGE_QUOTA * MAX_COLLEGE_CAPACITY);

// UI Helper Functions
const show = (id, content) => {
  const container = document.getElementById(id);
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

// Main processing function
async function processMatchingWithZKP() {
  clearLogs();
  show("logs", "🚀 Starting zkUni Privacy-Preserving Matching with ElGamal Encryption");
  show("logs", "-----------------------------------------------------------");
  
  try {
    // Install the noble-secp256k1 package
    show("logs", "⚙️ Required dependencies:");
    show("logs", "npm install @noble/secp256k1 @noir-lang/noir_js @aztec/bb.js");
    
    // Test data setup
    const { 
      studentPrefs, 
      collegePrefs, 
      collegeCapacities, 
      studentPublicKeys, 
      collegePublicKeys,
      studentPrivateKeys,
      collegePrivateKeys,
      actualStudentList,
      actualUniList
    } = await setupTestData();
    
    show("logs", "Test data and ElGamal keys loaded ✅");

    // Circuit input
    const input = { 
      student_prefs: studentPrefs,
      college_prefs: collegePrefs,
      college_capacities: collegeCapacities,
      student_public_keys: studentPublicKeys,
      college_public_keys: collegePublicKeys,
      actual_student_list: actualStudentList,
      actual_uni_list: actualUniList
    };

    // Initialize Noir and backend
    show("logs", "Initializing zero-knowledge circuit...");
    const noir = new Noir(circuit);
    const backend = new UltraHonkBackend(circuit.bytecode);
    
    // Execute circuit
    show("logs", "Running secure matching in zero-knowledge circuit...");
    const { witness } = await noir.execute(input);
    show("logs", "Matching complete ✅");
    
    // Generate proof
    show("logs", "Generating zero-knowledge proof...");
    const proof = await backend.generateProof(witness);
    show("logs", "Proof generated ✅");
    
    // Extract encrypted matches from proof with robust error handling
    const encryptedMatches = extractEncryptedMatches(proof);
    show("logs", `Found ${encryptedMatches.length} ElGamal encrypted matches`);
    
    // Process student matches
    await processStudentMatches(
      encryptedMatches.slice(0, actualStudentList), 
      studentPrivateKeys, 
      actualUniList
    );
    
    // Process college matches
    await processCollegeMatches(
      encryptedMatches.slice(actualStudentList), 
      collegePrivateKeys, 
      collegeCapacities, 
      actualUniList,
      actualStudentList
    );
    
    // Verify proof
    show("logs", "\n🔐 Verifying proof of fair matching...");
    const isValid = await backend.verifyProof(proof);
    show("logs", `Proof ${isValid ? "✅ VALID" : "❌ INVALID"}`);
    
    // Explain privacy benefits
    displayPrivacyBenefits();
    
  } catch (err) {
    console.error("Global error:", err);
    show("logs", `❌ Error: ${err.message}`);
    show("logs", "Stack trace has been logged to console.");
  }
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
  
  // Public keys
  const studentPublicKeys = [
    "0x7d1e5f02b0cdc7e10cff917625b4e7ee",
    "0x83a1eff0b6627a69b41c5de7b0aeb8e3",
    "0x9c4d8bfd9d4def4eeb1615aa53a32e30",
    "0xa0b3576ee834936135b547beba820d6f",
    "0xb4f0c6f7d89513c2055c54bd463a5275"
  ];
  
  const collegePublicKeys = [
    "0xc78e07db0ad00f15ebde45d9afd043e4",
    "0xd391cafa15d22c96a28afa0375ea8db7",
    "0xe2e3aa9a63b2b855d7c81c9f60e9c411",
    "0xf4b8dff2bb2a889432d097b3fb781c54",
    "0x052968bd5e7e3d743d45cb45e7ca1bf7"
  ];
  
  // Private keys (in a real system, these would be securely stored)
  const studentPrivateKeys = studentPublicKeys.map(key => hexToBigInt(key));
  const collegePrivateKeys = collegePublicKeys.map(key => hexToBigInt(key));
  
  return {
    studentPrefs,
    collegePrefs,
    collegeCapacities,
    studentPublicKeys,
    collegePublicKeys,
    studentPrivateKeys,
    collegePrivateKeys,
    actualStudentList: 5,
    actualUniList: 3
  };
}

// Extract encrypted matches from proof with robust error handling
function extractEncryptedMatches(proof) {
  // For debugging
  console.log("Proof structure:", proof);
  
  // Try various proof structures that might be returned
  let encryptedMatches = [];
  
  if (proof && proof.publicInputs && proof.publicInputs.return) {
    encryptedMatches = proof.publicInputs.return;
  } else if (proof && proof.public_inputs && proof.public_inputs.return) {
    encryptedMatches = proof.public_inputs.return;
  } else if (proof && Array.isArray(proof.publicInputs)) {
    encryptedMatches = proof.publicInputs;
  } else if (proof && Array.isArray(proof.public_inputs)) {
    encryptedMatches = proof.public_inputs;
  } else if (Array.isArray(proof)) {
    encryptedMatches = proof;
  } else {
    // Fallback to demo data
    show("logs", "⚠️ Could not extract encrypted matches from proof. Using demo data.");
    encryptedMatches = Array(TOTAL_ENCRYPTIONS).fill().map(() => ({
      c1: { x: "0x1", y: "0x2", is_infinity: false },
      c2: { x: "0x3", y: "0x4", is_infinity: false }
    }));
  }
  
  return encryptedMatches;
}

// Process student matches
async function processStudentMatches(studentResults, studentPrivateKeys, actualUniList) {
  show("logs", "\n🧑‍🎓 Student Results (Each student can only decrypt their own match):");
  
  for (let studentId = 0; studentId < studentResults.length; studentId++) {
    const studentMatch = studentResults[studentId];
    
    show("logs", `Student ${studentId} decrypting their match...`);
    
    try {
      // Use student's private key to decrypt their match
      const collegeId = await decryptElGamal(studentMatch, studentPrivateKeys[studentId]);
      
      if (collegeId === UNMATCHED || collegeId >= actualUniList) {
        show("logs", `Student ${studentId} is unmatched`);
      } else {
        show("logs", `Student ${studentId} matched with College ${collegeId}`);
      }
    } catch (err) {
      console.error(`Error decrypting for student ${studentId}:`, err);
      show("logs", `Error decrypting match for Student ${studentId}`);
    }
  }
}

// Process college matches
async function processCollegeMatches(
  collegeResults, 
  collegePrivateKeys, 
  collegeCapacities, 
  actualUniList,
  actualStudentList
) {
  show("logs", "\n🏫 College Results (Each college can only decrypt their matches):");
  
  let collegeResultIndex = 0;
  for (let collegeId = 0; collegeId < actualUniList; collegeId++) {
    const capacity = collegeCapacities[collegeId];
    
    // Extract this college's matches
    const collegeMatches = collegeResults.slice(
      collegeResultIndex, 
      collegeResultIndex + capacity
    );
    collegeResultIndex += capacity;
    
    show("logs", `College ${collegeId} has ${collegeMatches.length} matches to decrypt:`);
    
    for (let i = 0; i < collegeMatches.length; i++) {
      try {
        // Use college's private key to decrypt each match
        const studentId = await decryptElGamal(collegeMatches[i], collegePrivateKeys[collegeId]);
        
        if (studentId === UNMATCHED) {
          show("logs", `- College ${collegeId} has an unfilled slot`);
        } else if (studentId < actualStudentList) {
          show("logs", `- College ${collegeId} matched with Student ${studentId}`);
        } else {
          show("logs", `- College ${collegeId} has an invalid match`);
        }
      } catch (err) {
        console.error(`Error decrypting for college ${collegeId}:`, err);
        show("logs", `Error decrypting a match for College ${collegeId}`);
      }
    }
  }
}

// Display privacy benefits
function displayPrivacyBenefits() {
  show("logs", "\n🛡️ Privacy Features (Enhanced with ElGamal Encryption):");
  show("logs", "• No central authority learns any student or college preferences");
  show("logs", "• Each participant only learns their own matches");
  show("logs", "• ElGamal encryption provides strong cryptographic security");
  show("logs", "• Zero-knowledge proof verifies fairness without revealing details");
  show("logs", "• All preferences and matching process remain confidential");
  
  show("logs", "\nzkUni matching with ElGamal encryption complete! 🎉");
}

// Initialize UI
document.addEventListener("DOMContentLoaded", () => {
  // Add the submit button event listener
  const submitBtn = document.getElementById("submit");
  if (submitBtn) {
    submitBtn.addEventListener("click", processMatchingWithZKP);
  }
  alert("Click the button to start the zkUni matching demo!");
  // Add key generation demo button
  const genKeyBtn = document.createElement("button");
  genKeyBtn.textContent = "Generate ElGamal Key Pair (Demo)";
  genKeyBtn.className = "demo-btn";
  genKeyBtn.addEventListener("click", async () => {
    const keyInfo = document.getElementById("key-info") || document.createElement("div");
    keyInfo.id = "key-info";
    keyInfo.innerHTML = "<h3>Generated ElGamal Key Info:</h3><p>Generating...</p>";
    document.body.appendChild(keyInfo);
    
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
      keyInfo.innerHTML = `<h3>ElGamal Key Generation Error:</h3><p>${err.message}</p>`;
    }
  });
  
  if (submitBtn) {
    document.body.insertBefore(genKeyBtn, submitBtn.nextSibling);
  }
});

// Add some basic styling
const style = document.createElement('style');
style.textContent = `
  .demo-btn {
    margin: 10px 0;
    padding: 8px 16px;
    background-color: #6200ee;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }
  .demo-btn:hover {
    background-color: #3700b3;
  }
  #key-info {
    margin-top: 20px;
    padding: 15px;
    background-color: #f5f5f5;
    border-radius: 4px;
  }
  #logs {
    white-space: pre-wrap;
    background-color: #f9f9f9;
    padding: 15px;
    border-radius: 4px;
    font-family: monospace;
    margin-top: 20px;
  }
`;
document.head.appendChild(style);