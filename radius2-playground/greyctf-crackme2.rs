// radius2 -p ./crackme -s flag 1008 -c flag '[ -~]' -X 'Wrong flag :(' -A. flag -M
// props to @alkalinesec for helping to figure out the usage of radius2 via the APIs for this
// binary
use radius2::{Radius,RadiusOption, vc};

fn main() {
    let option = [RadiusOption::SimAll(true),RadiusOption::SelfModify(true),RadiusOption::Lazy(false)];
    let mut radius = Radius::new_with_options(Some("crackme"), &option);
    let mut state = radius.callsym_state("main");
    let flag = state.symbolic_value("flag", 126*8);
    state.constrain_bytes(&flag, "[ -~]");
    radius.set_argv_env(&mut state, &[vc(1), flag.clone()], &[]);

    // alternatively
    // radius.avoid(&[0x404016, 0x4006e5]);
    // radius.breakpoint(0x004011f6);
    // let mut final_state = radius.run(state, 1).unwrap();
    // let flag_val = final_state.evaluate_string(&flag).unwrap();

    // stop at function that prints correct flag message
    let final_state = radius.run_until(state,0x4011f6, &[0x404016]); 
    let flag_val = final_state.unwrap().evaluate_string(&flag).unwrap();
    println!("flag: {}", flag_val);
}
