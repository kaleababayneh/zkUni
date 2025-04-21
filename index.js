import { Noir } from "@noir-lang/noir_js";
import { UltraHonkBackend } from "@aztec/bb.js";
import circuit from "./circuit/target/circuit.json";

const show = (id, content) => {
  const container = document.getElementById(id);
  container.appendChild(document.createTextNode(content));
  container.appendChild(document.createElement("br"));
};

// Fixed decrypt function with hex string support
const decrypt = (encryptedDataHex, privateKey, nonceHex) => {
  try {
    // Convert hex strings to BigInts for calculation
    const encryptedData = BigInt(encryptedDataHex);
    const privateKeyBigInt = BigInt(privateKey);
    // Note: For the simple demo decryption, we don't actually use the nonce
    
    // Simple decryption - in a real system this would be more complex
    return Number(encryptedData % privateKeyBigInt);
  } catch (err) {
    console.error("Decryption error:", err);
    return null;
  }
};

const UNMATCHED = 999;

document.getElementById("submit").addEventListener("click", async () => {
  try {
    show("logs", "Starting zkUni matching process...");
    
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
    
    // Using strings for keys to avoid BigInt conversion issues
    const student_public_keys = ["1", "2", "3", "4", "5"];
    const college_public_keys = ["101", "102", "103", "104", "105"];
    
    // Private keys (in real system, these would be securely stored by each participant)
    const student_private_keys = [1n, 2n, 3n, 4n, 5n];
    const college_private_keys = [101n, 102n, 103n, 104n, 105n];

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
        
        // NEW: Improved match finding with proper hex handling
        if (Array.isArray(encryptedMatches)) {
          studentMatch = encryptedMatches.find(match => {
            if (!Array.isArray(match)) return false;
            
            try {
              // Parse hex value to get the actual student ID
              const recipientIdHex = match[0];
              // Convert from hex to decimal number
              const recipientId = parseInt(recipientIdHex, 16);
              
              console.log(`Comparing recipient ID ${recipientId} with student ${studentId}`);
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
            const encryptedData = BigInt(studentMatch[1].toString());
            const nonce = BigInt(studentMatch[2].toString());
            
            const collegeId = decrypt(encryptedData, privateKey, nonce);
            if (collegeId !== null) {
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
          // NEW: Improved college match finding with hex parsing
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
            const encryptedData = BigInt(match[1].toString());
            const nonce = BigInt(match[2].toString());
            
            const studentId = decrypt(encryptedData, privateKey, nonce);
            
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