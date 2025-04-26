extern crate rctl;

fn main() {
    let filter = rctl::Filter::new();

    for rule in filter.rules().unwrap().into_iter() {
        println!("{:?}", rule);
    }
}
