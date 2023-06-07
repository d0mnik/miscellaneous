use radius2::{Radius,RadiusOption, State, vc};
fn main() {
    fn hook_callback(_state: &mut State) -> bool{
        false
    }
    // simulate libs
    let options = [RadiusOption::SimAll(true)];
    let mut radius = Radius::new_with_options(Some("challenge"), &options);
    let main = radius.get_address("main").unwrap();
    let mut state = radius.call_state(main);
    let password = state.symbolic_value("password", 24*8);
    // constraint is needed for this to run properly
    state.constrain_bytes(&password, "[ -~]"); // matches a single character in the range between  (index 32) and ~ (index 126) (case sensitive)
    radius.set_argv_env(&mut state, &[vc(1),password.clone()], &[]);
    radius.avoid(&[0x12eb]);
    radius.breakpoint(0x14a6);
    radius.hook(0x141b, hook_callback); // hook needed to skip the instruction if not it causes some sort of explosion
    let mut new_state = radius.run(state, 1).unwrap();
    /*
    can do this instead of breakpoint
    let mut new_state = radius.run_until(state,0x14a6,&[0x12eb]).unwrap();
    */
    let pass = new_state.evaluate_string(&password).unwrap();
    println!("password: {}", pass);
}
