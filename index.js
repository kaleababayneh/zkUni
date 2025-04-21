import { Noir } from "@noir-lang/noir_js";
import { UltraHonkBackend } from "@aztec/bb.js";
import circuit from "./circuit/target/circuit.json";

const show = (id, content) => {
  const container = document.getElementById(id);
  container.appendChild(document.createTextNode(content));
  container.appendChild(document.createElement("br"));
};

document.getElementById("submit").addEventListener("click", async () => {
  try {
    const noir = new Noir(circuit);
    const backend = new UltraHonkBackend(circuit.bytecode);

    // insert this input into the circuit
    const student_prefs = [
      [3, 1, 2, 0, 4],
      [4, 2, 1, 0, 3],
      [1, 4, 0, 3, 2],
      [4, 1, 3, 2, 0],
      [3, 0, 1, 2, 4],
    ];
    const college_prefs = [
      [3, 1, 4, 2, 0],
      [1, 0, 3, 2, 4],
      [0, 2, 4, 3, 1],
      [3, 0, 2, 1, 4],
      [1, 4, 0, 2, 3],
    ];

    const actual_student_list = 5;
    const actual_uni_list = 5;

    const input = { 
      student_prefs: student_prefs,
      college_prefs: college_prefs,
      actual_student_list: actual_student_list,
      actual_uni_list: actual_uni_list
    }

    console.log("the input is ",input);
    
    const { witness } = await noir.execute(input);
    show("logs", "Generated witness... ✅");
	
    show("logs", "Generating proof... ⏳");
    const proof = await backend.generateProof(witness);
    show("logs", "Generated proof... ✅");
    show("results", proof.proof);

    show("logs", "Verifying proof... ⌛");
    const isValid = await backend.verifyProof(proof);
    show("logs", `Proof is ${isValid ? "valid" : "invalid"}... ✅`);
  } catch (err) {
    console.error(err);
    show("logs", "Oh 💔");
  }
});
