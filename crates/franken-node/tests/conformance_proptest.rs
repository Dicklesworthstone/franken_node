use frankenengine_node::conformance::connector_method_validator::{
    ContractReport, MethodDeclaration, validate_contract,
};
use proptest::{collection::vec, prelude::*};

fn method_declaration_strategy() -> impl Strategy<Value = MethodDeclaration> {
    (
        "[A-Za-z0-9_.:-]{0,24}",
        "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(name, version, has_input_schema, has_output_schema)| MethodDeclaration {
                name,
                version,
                has_input_schema,
                has_output_schema,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn method_declaration_json_roundtrip(
        declaration in method_declaration_strategy(),
    ) {
        let encoded = serde_json::to_string(&declaration)
            .expect("method declaration should encode");
        let decoded: MethodDeclaration = serde_json::from_str(&encoded)
            .expect("encoded method declaration should decode");

        prop_assert_eq!(&decoded, &declaration);
        prop_assert_eq!(serde_json::to_string(&decoded).expect("re-encode"), encoded);
    }

    #[test]
    fn contract_report_json_roundtrip(
        connector_id in "[A-Za-z0-9_.:-]{1,32}",
        declarations in vec(method_declaration_strategy(), 0..24),
    ) {
        let report = validate_contract(&connector_id, &declarations);
        let encoded = serde_json::to_string(&report)
            .expect("contract report should encode");
        let decoded: ContractReport = serde_json::from_str(&encoded)
            .expect("encoded contract report should decode");

        prop_assert_eq!(&decoded, &report);
        prop_assert_eq!(serde_json::to_string(&decoded).expect("re-encode"), encoded);
    }
}
