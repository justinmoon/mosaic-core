use mosaic_core::*;
use rand::rngs::OsRng;

fn main() {
    // Create a local updatable random number source
    let mut csprng = OsRng;

    // Create a new identity. This is your secret key
    let secret_key = SecretKey::generate(&mut csprng);

    // Create a new record
    let record = Record::new(
        &secret_key,
	Kind::MICROBLOG_ROOT,
	None,
	Timestamp::now().unwrap(),
        RecordFlags::default(),
        0,
        b"",
        b"Hello World!",
    )
    .unwrap();

    println!("{}", record);
}
