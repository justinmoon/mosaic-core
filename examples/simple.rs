use mosaic_core::*;
use rand::rngs::OsRng;

fn main() {
    // Create a local updatable random number source
    let mut csprng = OsRng;

    // Create a new identity. This is your secret key
    let secret_key = SecretKey::generate(&mut csprng);
    let public_key = secret_key.public();

    // Create a new record
    let record = OwnedRecord::new(&RecordParts {
        signing_data: RecordSigningData::SecretKey(secret_key),
        address_data: RecordAddressData::Random(public_key, Kind::MICROBLOG_ROOT),
        timestamp: Timestamp::now().unwrap(),
        flags: RecordFlags::empty(),
        tag_set: &EMPTY_TAG_SET,
        payload: b"Hello World!",
    })
    .unwrap();

    println!("{}", record);
}
