use base64::prelude::*;

fn main() {
    let s = "7AgCGv/SF6EThqVuoxU4edrKzqrzqD9yd4e11eTkGIQ=";
    let bytes = BASE64_STANDARD.decode(s).unwrap();
    println!("mosec0{}", z32::encode(&bytes));
}
