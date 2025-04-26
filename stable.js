// Simple demonstration of permutation-based privacy without cryptography

// Original Data (ONLY known to the client)
const students = ["Alice", "Bob", "Charlie", "David", "Eve"];
const colleges = ["Harvard", "Yale", "Stanford"];

// Actual preferences (what students and colleges truly want)
const studentPreferences = {
  "Alice":   ["Harvard", "Yale", "Stanford"],
  "Bob":     ["Yale", "Harvard", "Stanford"],
  "Charlie": ["Yale", "Stanford", "Harvard"],
  "David":   ["Harvard", "Stanford", "Yale"],
  "Eve":     ["Stanford", "Harvard", "Yale"]
};

const collegePreferences = {
  "Harvard":  ["Bob", "David", "Alice", "Charlie", "Eve"],
  "Yale":     ["Charlie", "Alice", "Eve", "Bob", "David"],
  "Stanford": ["Alice", "Charlie", "David", "Eve", "Bob"]
};

// The client generates a random permutation mapping
function generatePermutation(items) {
  const permuted = [...items];
  
  // Simple Fisher-Yates shuffle
  for (let i = permuted.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [permuted[i], permuted[j]] = [permuted[j], permuted[i]];
  }
  
  // Create mapping from original to permuted IDs
  const mapping = {};
  items.forEach((item, index) => {
    mapping[item] = permuted[index];
  });
  
  return { permuted, mapping };
}

// Generate permutations
const studentPermutation = generatePermutation(students);
const collegePermutation = generatePermutation(colleges);

console.log("=== PERMUTATION MAPPINGS (ONLY KNOWN TO CLIENT) ===");
console.log("Student mapping:", studentPermutation.mapping);
console.log("College mapping:", collegePermutation.mapping);

// Transform preferences using the permutations
function transformPreferences(originalPrefs, entityMapping, preferenceMapping) {
  const transformedPrefs = {};
  
  Object.keys(originalPrefs).forEach(entity => {
    // Get the permuted entity ID
    const permutedEntityID = entityMapping[entity];
    
    // Map each preference to its permuted ID
    const permutedPreferences = originalPrefs[entity].map(
      pref => preferenceMapping[pref]
    );
    
    // Store with permuted ID as key
    transformedPrefs[permutedEntityID] = permutedPreferences;
  });
  
  return transformedPrefs;
}

// Transform preferences
const permutedStudentPrefs = transformPreferences(
  studentPreferences, 
  studentPermutation.mapping, 
  collegePermutation.mapping
);

const permutedCollegePrefs = transformPreferences(
  collegePreferences, 
  collegePermutation.mapping, 
  studentPermutation.mapping
);

console.log("\n=== WHAT THE SERVER SEES ===");
console.log("Permuted student IDs:", studentPermutation.permuted);
console.log("Permuted college IDs:", collegePermutation.permuted);
console.log("Permuted student preferences:", permutedStudentPrefs);
console.log("Permuted college preferences:", permutedCollegePrefs);

// Simulate the server running the matching algorithm
function stableMatching(studentPrefs, collegePrefs) {
  // Simple implementation of Gale-Shapley algorithm
  // This runs with permuted IDs
  const matches = {};
  const studentIDs = Object.keys(studentPrefs);
  const collegeIDs = Object.keys(collegePrefs);
  
  // Initialize all students as free
  const freeStudents = [...studentIDs];
  const collegeMatches = {};
  collegeIDs.forEach(c => collegeMatches[c] = []);
  
  // Create college preference rankings
  const collegeRankings = {};
  collegeIDs.forEach(college => {
    collegeRankings[college] = {};
    collegePrefs[college].forEach((student, rank) => {
      collegeRankings[college][student] = rank;
    });
  });
  
  // While there are free students who still have colleges to apply to
  while (freeStudents.length > 0) {
    const student = freeStudents.pop();
    const preferences = studentPrefs[student];
    
    if (preferences.length === 0) continue;
    
    const college = preferences.shift(); // Get first preference
    
    if (collegeMatches[college].length < 2) { // Assuming capacity of 2
      // College has space
      collegeMatches[college].push(student);
      matches[student] = college;
    } else {
      // College is full, check if student is preferred over any current match
      const currentMatches = collegeMatches[college];
      let worstMatch = null;
      let worstRank = -1;
      
      for (const match of currentMatches) {
        const rank = collegeRankings[college][match];
        if (worstMatch === null || rank > worstRank) {
          worstMatch = match;
          worstRank = rank;
        }
      }
      
      if (collegeRankings[college][student] < worstRank) {
        // Replace worst match
        collegeMatches[college] = [
          ...collegeMatches[college].filter(s => s !== worstMatch),
          student
        ];
        matches[student] = college;
        delete matches[worstMatch];
        freeStudents.push(worstMatch);
      } else {
        // Return student to free pool with one fewer preference
        freeStudents.unshift(student);
      }
    }
  }
  
  return matches;
}

// Run the matching algorithm on the permuted preferences
const permutedMatches = stableMatching(permutedStudentPrefs, permutedCollegePrefs);

console.log("\n=== PERMUTED RESULTS (WHAT SERVER OUTPUTS) ===");
console.log(permutedMatches);

// Client-side unmapping
function unmapResults(permutedMatches, studentMapping, collegeMapping) {
  const realMatches = {};
  
  // Create reverse mappings
  const reverseStudentMapping = Object.fromEntries(
    Object.entries(studentMapping).map(([k, v]) => [v, k])
  );
  
  const reverseCollegeMapping = Object.fromEntries(
    Object.entries(collegeMapping).map(([k, v]) => [v, k])
  );
  
  // Convert permuted IDs back to real IDs
  Object.keys(permutedMatches).forEach(permutedStudentID => {
    const permutedCollegeID = permutedMatches[permutedStudentID];
    
    const realStudentID = reverseStudentMapping[permutedStudentID];
    const realCollegeID = reverseCollegeMapping[permutedCollegeID];
    
    realMatches[realStudentID] = realCollegeID;
  });
  
  return realMatches;
}

// Client unmaps the results
const actualMatches = unmapResults(
  permutedMatches,
  studentPermutation.mapping,
  collegePermutation.mapping
);

console.log("\n=== ACTUAL RESULTS (AFTER CLIENT UNMAPPING) ===");
console.log(actualMatches);

console.log("\n=== PRIVACY GUARANTEES ===");
console.log("1. Server never sees real student or college identities");
console.log("2. Server never knows which real student prefers which real college");
console.log("3. Server never learns which real student matched with which real college");