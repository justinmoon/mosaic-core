use mosaic_core::*;
use rand::rngs::OsRng;

fn main() {
    // Create a local updatable random number source
    let mut csprng = OsRng;

    // Create a new identity. This is your secret key
    let secret_key = SecretKey::generate(&mut csprng);

    // Compute your public key from your secret key
    let public_key = secret_key.public();

    // Create a new Address for a new record
    let address = Address::new(public_key, Kind::MICROBLOG_ROOT, Timestamp::now().unwrap());

    // Create a new record with that address
    let record = Record::new(
        &secret_key,
        address,
        RecordFlags::default(),
        0,
        b"",
        b"Hello World!",
    )
    .unwrap();

    println!("{}", record);
}
