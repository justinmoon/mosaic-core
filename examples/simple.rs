use mosaic_core::*;

fn main() {
    // Create a new identity. This is your secret key
    let secret_key = SecretKey::generate();
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
