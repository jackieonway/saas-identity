//! UUIDv7 generation and validation for authority-owned identifiers.
use uuid::{Uuid, Variant};
pub(crate) fn new_uuid() -> Uuid {
    Uuid::now_v7()
}
pub(crate) fn is_uuid_v7(value: Uuid) -> bool {
    value.get_version_num() == 7 && value.get_variant() == Variant::RFC4122
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_identifiers_are_v7_and_distinct() {
        let a = new_uuid();
        let b = new_uuid();
        assert!(is_uuid_v7(a) && is_uuid_v7(b));
        assert_ne!(a, b);
        assert!(!is_uuid_v7(Uuid::nil()));
    }
}
