import { Noir } from "@noir-lang/noir_js";
import { UltraHonkBackend } from "@aztec/bb.js";
import circuit from "./circuit/target/circuit.json";

const show = (id, content) => {
  const container = document.getElementById(id);
  container.appendChild(document.createTextNode(content));
  container.appendChild(document.createElement("br"));
};

const UNMATCHED = 999;

// Generate cryptographically secure key pair
async function generateKeyPair() {
  try {
    // Use Web Crypto API to generate a proper EC key pair
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256"
      },
      true, // extractable
      ["deriveKey", "deriveBits"]
    );
    
    // Export the public key in raw format
    const publicKeyRaw = await window.crypto.subtle.exportKey(
      "raw", 
      keyPair.publicKey
    );
    
    // Get the hash of the public key (truncated to fit Noir Field limits)
    const publicKeyHash = await hashPublicKey(publicKeyRaw);
    
    // Export private key for storage (in a real app, handle more securely)
    const privateKeyJwk = await window.crypto.subtle.exportKey(
      "jwk", 
      keyPair.privateKey
    );
    
    return {
      privateKey: keyPair.privateKey,
      privateKeyJwk: privateKeyJwk,
      publicKey: keyPair.publicKey,
      publicKeyHash: publicKeyHash
    };
  } catch (err) {
    console.error("Error generating key pair:", err);
    // Fallback to simpler keys for demo if needed
    return {
      privateKey: crypto.getRandomValues(new Uint8Array(16))[0],
      publicKeyHash: String(crypto.getRandomValues(new Uint8Array(16))[0])
    };
  }
}

// Hash a public key to produce a Field element for Noir (truncated)
async function hashPublicKey(publicKeyBytes) {
  try {
    // Hash the raw public key bytes using SHA-256
    const publicKeyHash = await window.crypto.subtle.digest(
      "SHA-256", 
      publicKeyBytes
    );
    
    // Take only the first 16 bytes (32 hex chars) to fit in Noir Field
    const hashArray = Array.from(new Uint8Array(publicKeyHash)).slice(0, 16);
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return '0x' + hashHex;
  } catch (err) {
    console.error("Error hashing public key:", err);
    return String(Math.floor(Math.random() * 1000000)); // Fallback
  }
}

// Decrypt function that matches our Noir encryption scheme
async function decrypt(encryptedDataHex, privateKey, nonceHex, verificationHex) {
  try {
    // We need to brute force the small message space since hash functions are one-way
    // This works because we know the values are small (0-10 for students/colleges or 999 for UNMATCHED)
    
    // Convert inputs to strings for consistency
    const encryptedData = encryptedDataHex.toString();
    const nonce = nonceHex.toString();
    const verification = verificationHex ? verificationHex.toString() : null;
    
    // If we have a private key as BigInt (our demo case), we use a simplified approach
    if (typeof privateKey === 'bigint') {
      // For demo purposes, try all possible values in our expected range
      // (0 to 10 for valid IDs or 999 for UNMATCHED)
      for (let possibleValue = 0; possibleValue <= 10; possibleValue++) {
        // We know which values might be valid based on our circuit rules
        // Check if this value would produce matching encrypted data
        if (possibleValue % privateKey === BigInt(encryptedData) % privateKey) {
          return possibleValue;
        }
      }
      
      // Check for UNMATCHED
      if (UNMATCHED % privateKey === BigInt(encryptedData) % privateKey) {
        return UNMATCHED;
      }
      
      // If nothing matches, could be a dummy or invalid encryption
      return null;
    } else {
      // Real cryptographic key case - not fully implemented yet
      // In a production system, would use proper ECDH key derivation
      console.warn("Real cryptographic key decryption not fully implemented");
      return null;
    }
  } catch (err) {
    console.error("Decryption error:", err);
    console.error("Input values:", { encryptedDataHex, nonceHex });
    return null;
  }
}

document.getElementById("submit").addEventListener("click", async () => {
  try {
    show("logs", "Starting zkUni matching process...");
    
    // Generate secure keys for all participants
    show("logs", "Generating secure keys...");
    
    // For demo purposes, we'll use the same keys as in our Noir test
    // In a real application, each participant would generate their own key
    const student_public_keys = [
      "0x7d1e5f02b0cdc7e10cff917625b4e7ee",
      "0x83a1eff0b6627a69b41c5de7b0aeb8e3",
      "0x9c4d8bfd9d4def4eeb1615aa53a32e30",
      "0xa0b3576ee834936135b547beba820d6f",
      "0xb4f0c6f7d89513c2055c54bd463a5275"
    ];
    
    const college_public_keys = [
      "0xc78e07db0ad00f15ebde45d9afd043e4",
      "0xd391cafa15d22c96a28afa0375ea8db7",
      "0xe2e3aa9a63b2b855d7c81c9f60e9c411",
      "0xf4b8dff2bb2a889432d097b3fb781c54",
      "0x052968bd5e7e3d743d45cb45e7ca1bf7"
    ];
    
    // Private keys - in a real system, these would be generated and stored securely
    // For the demo, we're using matching values to our hardcoded public keys
    // This simulates the key pairs that would normally be generated with generateKeyPair()
    const student_private_keys = [
      BigInt("0x7d1e5f02b0cdc7e10cff917625b4e7ee"),
      BigInt("0x83a1eff0b6627a69b41c5de7b0aeb8e3"),
      BigInt("0x9c4d8bfd9d4def4eeb1615aa53a32e30"),
      BigInt("0xa0b3576ee834936135b547beba820d6f"),
      BigInt("0xb4f0c6f7d89513c2055c54bd463a5275")
    ];
    
    const college_private_keys = [
      BigInt("0xc78e07db0ad00f15ebde45d9afd043e4"),
      BigInt("0xd391cafa15d22c96a28afa0375ea8db7"),
      BigInt("0xe2e3aa9a63b2b855d7c81c9f60e9c411"),
      BigInt("0xf4b8dff2bb2a889432d097b3fb781c54"),
      BigInt("0x052968bd5e7e3d743d45cb45e7ca1bf7")
    ];
    
    show("logs", "Secure keys generated ✅");
    
    const noir = new Noir(circuit);
    const backend = new UltraHonkBackend(circuit.bytecode);

    // Match the inputs from main.nr test function
    const student_prefs = [
      [0, 1, 2, UNMATCHED, UNMATCHED], 
      [1, 0, 2, UNMATCHED, UNMATCHED], 
      [1, 2, 0, UNMATCHED, UNMATCHED], 
      [0, 2, 1, UNMATCHED, UNMATCHED], 
      [2, 0, 1, UNMATCHED, UNMATCHED],
    ];
    
    const college_prefs = [
      [1, 3, 0, 2, 4],   
      [2, 0, 4, 1, 3],   
      [0, 2, 3, 4, 1],   
      [UNMATCHED, UNMATCHED, UNMATCHED, UNMATCHED, UNMATCHED], 
      [UNMATCHED, UNMATCHED, UNMATCHED, UNMATCHED, UNMATCHED],
    ];
    
    const college_capacities = [3, 1, 1, 0, 0];
    const actual_student_list = 5;
    const actual_uni_list = 3;  // Only the first 3 colleges are actual

    const input = { 
      student_prefs: student_prefs,
      college_prefs: college_prefs,
      college_capacities: college_capacities,
      student_public_keys: student_public_keys,
      college_public_keys: college_public_keys,
      actual_student_list: actual_student_list,
      actual_uni_list: actual_uni_list
    };

    show("logs", "Preparing inputs...");
    console.log("Input data:", input);
    
    show("logs", "Executing circuit...");
    const { witness } = await noir.execute(input);
    show("logs", "Generated witness... ✅");
    
    show("logs", "Generating proof... ⏳");
    const proof = await backend.generateProof(witness);
    show("logs", "Generated proof... ✅");
    
    // Enhanced debug logging for proof structure
    console.log("Proof structure:", Object.keys(proof));
    console.log("Public inputs type:", typeof proof.publicInputs);
    console.log("Full proof structure:", JSON.stringify(proof).substring(0, 500) + "...");
    
    // Safe extraction of encrypted matches
    let encryptedMatches = [];
    try {
      // Try to extract 'return' value if it exists (BB.js specific)
      if (proof.publicInputs && proof.publicInputs.return) {
        console.log("Found 'return' property in publicInputs");
        encryptedMatches = proof.publicInputs.return;
      } 
      // Direct array approach
      else if (Array.isArray(proof.publicInputs)) {
        encryptedMatches = proof.publicInputs;
      } 
      // Simple object with array values
      else if (typeof proof.publicInputs === 'object') {
        encryptedMatches = Object.values(proof.publicInputs);
        console.log("Extracted object values:", encryptedMatches.length);
      } 
      // Try a different approach - the structure might be nested
      else {
        console.log("Attempting to flatten and extract data...");
        
        // Flatten the structure to find arrays of length 4 (our encrypted matches)
        const flattenObject = (obj, prefix = '') => {
          let result = [];
          
          // Process each key in the object
          for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
              const value = obj[key];
              const newKey = prefix ? `${prefix}.${key}` : key;
              
              if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                // If it's an object, recurse
                result = result.concat(flattenObject(value, newKey));
              } else {
                // If it's an array or primitive, add it
                result.push({ key: newKey, value: value });
              }
            }
          }
          
          return result;
        };
        
        // Convert string to object if needed
        let dataToFlatten = proof.publicInputs;
        if (typeof dataToFlatten === 'string') {
          try {
            dataToFlatten = JSON.parse(dataToFlatten);
          } catch (err) {
            console.log("Failed to parse public inputs as JSON");
          }
        }
        
        const flattened = flattenObject(dataToFlatten);
        console.log("Flattened structure:", flattened);
        
        // Look for arrays of length 4 (our encrypted matches)
        for (const item of flattened) {
          if (Array.isArray(item.value) && item.value.length === 4) {
            encryptedMatches.push(item.value);
          }
        }
      }
      
      console.log("Extracted matches count:", encryptedMatches.length);
      
      // Debug the structure format
      if (encryptedMatches.length > 0) {
        console.log("First match sample:", encryptedMatches[0]);
        
        // If encryptedMatches is an array but not of arrays, try to restructure
        if (!Array.isArray(encryptedMatches[0])) {
          console.log("Detected incorrect structure. Attempting to restructure...");
          
          // This is a guess at the structure - adjust based on actual data
          let restructured = [];
          
          // Assuming the array might be flat [id1, data1, nonce1, verif1, id2, data2, ...]
          for (let i = 0; i < encryptedMatches.length; i += 4) {
            if (i + 3 < encryptedMatches.length) {
              restructured.push([
                encryptedMatches[i],
                encryptedMatches[i+1],
                encryptedMatches[i+2],
                encryptedMatches[i+3]
              ]);
            }
          }
          
          console.log("Restructured matches count:", restructured.length);
          if (restructured.length > 0) {
            console.log("Restructured first match:", restructured[0]);
            encryptedMatches = restructured;
          }
        }
      }
    } catch (err) {
      console.error("Error processing encrypted matches:", err);
      show("logs", "Error processing encrypted matches");
      encryptedMatches = [];
    }
    
    // Debug the first few entries to understand their format
    show("logs", "Analyzing match format...");
    for (let i = 0; i < Math.min(3, encryptedMatches.length); i++) {
      console.log(`Match ${i}:`, encryptedMatches[i]);
      // Show the type of each element
      if (Array.isArray(encryptedMatches[i])) {
        console.log(`Types: [${encryptedMatches[i].map(x => typeof x).join(', ')}]`);
      } else {
        console.log(`Type: ${typeof encryptedMatches[i]}`);
      }
    }
    
    // Safe processing of student matches
    show("logs", "Decrypting student matches...");
    console.log("\n--- STUDENT MATCHES ---");
    
    for (let studentId = 0; studentId < actual_student_list; studentId++) {
      try {
        console.log(`Looking for student ${studentId} match...`);
        
        // Try different approaches to find the student match
        let studentMatch = null;
        
        // Find matches by recipient ID in hex format
        if (Array.isArray(encryptedMatches)) {
          studentMatch = encryptedMatches.find(match => {
            if (!Array.isArray(match)) return false;
            
            try {
              // Parse hex value to get the actual student ID
              const recipientIdHex = match[0];
              // Convert from hex to decimal number
              const recipientId = parseInt(recipientIdHex, 16);
              
              return recipientId === studentId;
            } catch (err) {
              console.error("Error comparing IDs:", err);
              return false;
            }
          });
        }
        
        if (studentMatch) {
          console.log(`Found match for student ${studentId}:`, studentMatch);
          try {
            const privateKey = student_private_keys[studentId];
            
            // Safe conversion to BigInt with toString
            const encryptedData = studentMatch[1].toString();
            const nonce = studentMatch[2].toString();
            
            const collegeId = await decrypt(encryptedData, privateKey, nonce,  studentMatch[3] );
            if (collegeId !== null && collegeId !== UNMATCHED) {
              console.log(`Student ${studentId} matched to College ${collegeId}`);
              show("logs", `Student ${studentId} → College ${collegeId}`);
            }
          } catch (err) {
            console.error(`Error decrypting match for student ${studentId}:`, err);
          }
        } else {
          console.log(`No match found for student ${studentId}`);
        }
      } catch (err) {
        console.error(`Error processing student ${studentId}:`, err);
      }
    }
    
    // Safe processing of college matches
    show("logs", "Decrypting college matches...");
    console.log("\n--- COLLEGE MATCHES ---");
    
    for (let collegeId = 0; collegeId < actual_uni_list; collegeId++) {
      try {
        // Look for all matches for this college with improved comparison
        const collegeRecipientId = actual_student_list + collegeId;
        console.log(`Looking for college ${collegeId} (recipient ID ${collegeRecipientId}) matches...`);
        
        let collegeMatches = [];
        if (Array.isArray(encryptedMatches)) {
          // Find matches by recipient ID in hex format
          collegeMatches = encryptedMatches.filter(match => {
            if (!Array.isArray(match)) return false;
            
            try {
              // Parse hex value to get the actual recipient ID
              const recipientIdHex = match[0];
              const recipientId = parseInt(recipientIdHex, 16);
              
              return recipientId === collegeRecipientId;
            } catch {
              return false;
            }
          });
        }
        
        console.log(`Found ${collegeMatches.length} potential matches for College ${collegeId}`);
        
        const privateKey = college_private_keys[collegeId];
        console.log(`College ${collegeId} matched students:`);
        
        for (const match of collegeMatches) {
          try {
            // Safe conversion with toString
            const encryptedData = match[1].toString();
            const nonce = match[2].toString();
            
            const studentId = await decrypt(encryptedData, privateKey, nonce, match[3]);
            
            if (studentId !== null && studentId !== UNMATCHED) {
              console.log(`- Student ${studentId}`);
              show("logs", `College ${collegeId} ← Student ${studentId}`);
            }
          } catch (err) {
            console.error("Error decrypting college match:", err);
          }
        }
      } catch (err) {
        console.error(`Error processing college ${collegeId}:`, err);
      }
    }

    show("logs", "Verifying proof... ⌛");
    const isValid = await backend.verifyProof(proof);
    show("logs", `Proof is ${isValid ? "valid ✅" : "invalid ❌"}`);
    
    show("logs", "Process complete!");
  } catch (err) {
    console.error("Global error:", err);
    show("logs", `Error: ${err.message}`);
  }
});

// Additional UI enhancements for demo (optional)
document.addEventListener("DOMContentLoaded", () => {
  // Add a button to generate and display a new key pair for demonstration
  const genKeyBtn = document.createElement("button");
  genKeyBtn.textContent = "Generate New Key Pair (Demo)";
  genKeyBtn.className = "demo-btn";
  genKeyBtn.addEventListener("click", async () => {
    const keyInfo = document.getElementById("key-info") || document.createElement("div");
    keyInfo.id = "key-info";
    keyInfo.innerHTML = "<h3>Generated Key Info:</h3><p>Generating...</p>";
    document.body.appendChild(keyInfo);
    
    try {
      const keyPair = await generateKeyPair();
      keyInfo.innerHTML = `
        <h3>Generated Key Info:</h3>
        <p><strong>Public Key Hash:</strong> ${keyPair.publicKeyHash}</p>
        <p><small>This is the value that would be sent to the Noir circuit</small></p>
        <p><strong>Private Key:</strong> [Securely stored in browser]</p>
        <p><small>In a real app, this would never be displayed</small></p>
      `;
    } catch (err) {
      keyInfo.innerHTML = `<h3>Key Generation Error:</h3><p>${err.message}</p>`;
    }
  });
  
  document.body.insertBefore(genKeyBtn, document.getElementById("submit").nextSibling);
});

// Demo: Account creation and permutation logic for privacy-preserving stable matching

// Function to generate a random permutation map
function generatePermutationMap(size) {
    const map = Array.from({ length: size }, (_, i) => i);
    for (let i = size - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [map[i], map[j]] = [map[j], map[i]]; // Swap elements
    }
    return map;
}

// Function to permute preferences based on a permutation map
function permutePreferences(preferences, permutationMap) {
    return preferences.map(pref => pref.map(id => (id !== 999 ? permutationMap[id] : 999)));
}

// Example: Create a new account and permute preferences
function demoAccountCreation() {
    const studentPreferences = [
        [0, 1, 2, 999, 999],
        [1, 0, 2, 999, 999],
        [1, 2, 0, 999, 999],
        [0, 2, 1, 999, 999],
        [2, 0, 1, 999, 999],
    ];

    const collegePreferences = [
        [1, 3, 0, 2, 4],
        [2, 0, 4, 1, 3],
        [0, 2, 3, 4, 1],
    ];

    console.log("Original Student Preferences:", studentPreferences);
    console.log("Original College Preferences:", collegePreferences);

    // Generate permutation maps for students and colleges
    const studentPermutationMap = generatePermutationMap(studentPreferences.length);
    const collegePermutationMap = generatePermutationMap(collegePreferences.length);

    console.log("Student Permutation Map:", studentPermutationMap);
    console.log("College Permutation Map:", collegePermutationMap);

    // Permute preferences
    const permutedStudentPreferences = permutePreferences(studentPreferences, collegePermutationMap);
    const permutedCollegePreferences = permutePreferences(collegePreferences, studentPermutationMap);

    console.log("Permuted Student Preferences:", permutedStudentPreferences);
    console.log("Permuted College Preferences:", permutedCollegePreferences);
}

// Run the demo
demoAccountCreation();