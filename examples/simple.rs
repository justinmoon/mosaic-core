use mosaic_core::*;
use rand::rngs::OsRng;

fn main() {
    // Create a local updatable random number source
    let mut csprng = OsRng;

    // Create a new identity. This is your secret key
    let secret_key = SecretKey::generate(&mut csprng);

    // Create a new record
    let record = OwnedRecord::new(
        &secret_key,
        &RecordParts {
            kind: Kind::MICROBLOG_ROOT,
            deterministic_nonce: None,
            timestamp: Timestamp::now().unwrap(),
            flags: RecordFlags::PRINTABLE,
            tags_bytes: b"",
            payload: b"Hello World!",
        },
    )
    .unwrap();

    println!("{}", record);
}
