std:
	cargo build

test:
	cargo test

debug_test:
	RUST_LOG=debug cargo test test_function_from_json -- --nocapture

no_std:
	cargo build --no-default-features --features no_std
