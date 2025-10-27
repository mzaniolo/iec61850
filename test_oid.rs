use rasn::prelude::*;

fn main() {
    let oid = ObjectIdentifier::new_unchecked(vec![2, 1, 0, 1].into());
    let encoded = rasn::ber::encode(&oid).expect("Failed to encode");
    println!("OID [2, 1, 0, 1] encoded as: {:?}", encoded);
    
    // Let's also test what the expected encoding should be
    // First two arcs: 2.1 -> 40*2 + 1 = 81 (0x51)
    // Remaining: 0.1 -> 0x00, 0x01
    // So it should be: [0x06, 0x03, 0x51, 0x00, 0x01]
    println!("Expected: [0x06, 0x03, 0x51, 0x00, 0x01]");
}
