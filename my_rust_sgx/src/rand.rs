use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

#[no_mangle]
pub extern "C" fn get_rand() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect()
}