use crate::landlock::restrict_access;
mod landlock;

fn main() {
    restrict_access().unwrap();
}
