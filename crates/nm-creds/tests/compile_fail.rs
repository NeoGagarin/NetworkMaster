#[test]
fn arena_cannot_be_serialized() {
    trybuild::TestCases::new().compile_fail("tests/ui/no_serialize.rs");
}
