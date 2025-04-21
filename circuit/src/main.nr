global N_STUDENT_PREFERENCE: u32 = 5;
global N_COLLEGE_QUOTA: u32 = 5;
global MAX_PREFS: u32 = 5;
global UNMATCHED: u32 = 999;

fn stable_matching(
    student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE],
    college_prefs: [[u32; N_STUDENT_PREFERENCE];N_COLLEGE_QUOTA],
    actual_student_list: u32,
    actual_uni_list: u32
) -> [u32; N_STUDENT_PREFERENCE] {

    let mut next_application: [u32; N_STUDENT_PREFERENCE] = [0; N_STUDENT_PREFERENCE];
    let mut free_student: [bool; N_STUDENT_PREFERENCE] = [true; N_STUDENT_PREFERENCE];
    let mut accepted_to: [u32;N_COLLEGE_QUOTA] = [UNMATCHED;N_COLLEGE_QUOTA];
    let mut current_match: [u32; N_STUDENT_PREFERENCE] = [UNMATCHED; N_STUDENT_PREFERENCE];

    let mut women_ranks: [[u32; N_STUDENT_PREFERENCE];N_COLLEGE_QUOTA] = [[0; N_STUDENT_PREFERENCE];N_COLLEGE_QUOTA];


    for w in 0..N_COLLEGE_QUOTA {
      if (w < actual_uni_list) {
        for rank in 0..N_STUDENT_PREFERENCE {
          if (rank < actual_student_list){
            let m = college_prefs[w][rank];
            women_ranks[w][m] = rank;
          }
        }
      }
    }

    let max_iterations = N_STUDENT_PREFERENCE *N_COLLEGE_QUOTA;
    let effective_iterations = actual_student_list * actual_uni_list;
    for outerloop in 0..max_iterations {
      if (outerloop < effective_iterations) {
        let mut done = true;
        for m in 0..N_STUDENT_PREFERENCE {
          if (m < actual_student_list){
            if free_student[m] {
                if next_application[m] < MAX_PREFS {
                    let w =student_prefs[m][next_application[m]];
                    next_application[m] += 1;

                    if w != UNMATCHED {
                        if accepted_to[w] == UNMATCHED {
                            accepted_to[w] = m;
                            current_match[m] = w;
                            free_student[m] = false;
                        } else {
                            let m1 = accepted_to[w];
                            if women_ranks[w][m] < women_ranks[w][m1] {
                                accepted_to[w] = m;
                                current_match[m] = w;
                                current_match[m1] = UNMATCHED;
                                free_student[m] = false;
                                free_student[m1] = true;
                            }
                        }
                        done = false;
                    }
                }
            }
          }
        }
      }
    }

    current_match
}

fn main(student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE], college_prefs: [[u32; N_STUDENT_PREFERENCE];N_COLLEGE_QUOTA], actual_student_list: u32, actual_uni_list:u32) -> pub [u32; N_STUDENT_PREFERENCE] {

    let matching = stable_matching(student_prefs, college_prefs, actual_student_list, actual_uni_list);
    matching
    // // Example: assert that all matched women are valid indices or UNMATCHED
    // for m in 0..N_STUDENT_PREFERENCE {
    //     let w = matching[m];
    //     println(w)
    //     //assert(w <=N_COLLEGE_QUOTA);
    // }
}


#[test]
fn try_test(){
      let student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE] = [
        [2, 0, 1, 999, 999],  
        [0, 1, 2, 999, 999],  
        [1, 2, 0, 999, 999],  
        [2, 1, 0, 999, 999],  
        [1, 0, 2, 999, 999],  
      ];
      let college_prefs: [[u32; N_STUDENT_PREFERENCE];N_COLLEGE_QUOTA] = [
        [1, 3, 0, 2, 4],      
        [4, 2, 1, 0, 3],      
        [3, 0, 2, 1, 4],      
        [999, 999, 999, 999, 999],  
        [999, 999, 999, 999, 999],  
      ];

    let returned = main(student_prefs, college_prefs, 5,3);
    println(returned);
}
