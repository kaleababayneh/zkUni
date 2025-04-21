global N_STUDENT_PREFERENCE: u32 = 5;
global N_COLLEGE_QUOTA: u32 = 5;
global MAX_PREFS: u32 = 5;
global MAX_COLLEGE_CAPACITY: u32 = 3;   // upper bound for any college quota

global UNMATCHED: u32 = 999;

fn stable_matching(
        student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE],
        college_prefs: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA],
        college_capacities: [u32; N_COLLEGE_QUOTA],
        actual_student_list: u32,
        actual_uni_list: u32
) -> [u32; N_STUDENT_PREFERENCE] {

    let mut next_application: [u32; N_STUDENT_PREFERENCE] = [0; N_STUDENT_PREFERENCE];
    let mut free_student: [bool; N_STUDENT_PREFERENCE] = [true; N_STUDENT_PREFERENCE];
    let mut current_match: [u32; N_STUDENT_PREFERENCE] = [UNMATCHED; N_STUDENT_PREFERENCE];

    let mut college_count: [u32; N_COLLEGE_QUOTA] = [0; N_COLLEGE_QUOTA];
    let mut college_matches: [[u32; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA] = [[UNMATCHED; MAX_COLLEGE_CAPACITY]; N_COLLEGE_QUOTA];

    let mut college_ranks: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA] = [[0; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA];
    for w in 0..N_COLLEGE_QUOTA {
        if w < actual_uni_list {
            for r in 0..N_STUDENT_PREFERENCE {
                if r < actual_student_list {
                    let s = college_prefs[w][r];
                    college_ranks[w][s] = r;
                }
            }
        }
    }

    let max_iterations = N_STUDENT_PREFERENCE * MAX_PREFS; 
    let mut should_continue = true;

    for _ in 0..max_iterations {
        let mut progress = false; // track if any proposal happened this pass

        if should_continue {
            for s in 0..N_STUDENT_PREFERENCE {
                if (s < actual_student_list) & free_student[s] {
                    if next_application[s] < MAX_PREFS {
                        let c = student_prefs[s][ next_application[s] ];
                        next_application[s] += 1;

                        if (c != UNMATCHED) & (c < actual_uni_list) {
                            progress = true;

                           
                            if college_count[c] < college_capacities[c] {
                                let idx = college_count[c];
                                college_matches[c][idx] = s;
                                college_count[c] += 1;
                                current_match[s] = c;
                                free_student[s] = false;
                            }
                            
                            else {
                               
                                let mut worst_idx: u32 = 0;
                                let mut worst_rank: u32 = 0;
                                let mut first = true;
                                for i in 0..MAX_COLLEGE_CAPACITY {
                                    if i < college_capacities[c] {
                                        let curr_s = college_matches[c][i];
                                        let rnk = college_ranks[c][curr_s];
                                        if first | rnk > worst_rank {
                                            first = false;
                                            worst_rank = rnk;
                                            worst_idx = i;
                                        }
                                    }
                                }

                                // Prefer new applicant?
                                if college_ranks[c][s] < worst_rank {
                                    let replaced = college_matches[c][worst_idx];
                                    college_matches[c][worst_idx] = s;
                                    current_match[s] = c;
                                    free_student[s] = false;

                                    // replaced student becomes free
                                    current_match[replaced] = UNMATCHED;
                                    free_student[replaced] = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Instead of break, update the continue flag
        should_continue = progress;
    }

    current_match
}

fn main(
        student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE],
        college_prefs: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA],
        college_capacities: [u32; N_COLLEGE_QUOTA],
        actual_student_list: u32,
        actual_uni_list: u32
) -> pub [u32; N_STUDENT_PREFERENCE] {
    stable_matching(student_prefs, college_prefs, college_capacities, actual_student_list, actual_uni_list)
}

#[test]
fn try_test() {

    let student_prefs: [[u32; MAX_PREFS]; N_STUDENT_PREFERENCE] = [
        [0, 1, 2, UNMATCHED, UNMATCHED], 
        [1, 0, 2, UNMATCHED, UNMATCHED], 
        [1, 2, 0, UNMATCHED, UNMATCHED], 
        [0, 2, 1, UNMATCHED, UNMATCHED], 
        [2, 0, 1, UNMATCHED, UNMATCHED], 
    ];

    let college_prefs: [[u32; N_STUDENT_PREFERENCE]; N_COLLEGE_QUOTA] = [
        [1, 3, 0, 2, 4],   
        [2, 0, 4, 1, 3],   
        [0, 2, 3, 4, 1],   
        [UNMATCHED; N_STUDENT_PREFERENCE], 
        [UNMATCHED; N_STUDENT_PREFERENCE], 
    ];

    let college_capacities: [u32; N_COLLEGE_QUOTA] = [3, 1, 1, 0, 0];

    let out = main(student_prefs, college_prefs, college_capacities, 5, 3);
    println(out);  
}
