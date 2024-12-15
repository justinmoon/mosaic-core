use mosaic_core::*;
use rand::rngs::OsRng;

fn main() {
    // Create a local updatable random number source
    let mut csprng = OsRng;

    // Create a new identity. This is your private key
    let private_key = PrivateKey::generate(&mut csprng);

    // Compute your public key from your privatek ey
    let public_key = private_key.public();

    // Create a new Address for a new record
    let address = Address::new(public_key, Kind::MICROBLOG_ROOT, Timestamp::now().unwrap());

    // Create a new record with that address
    let record = Record::new(
        &private_key,
        address,
        RecordFlags::default(),
        0,
        b"",
        b"Hello World!",
    )
    .unwrap();

    println!("{}", record);
}
