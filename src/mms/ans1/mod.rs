pub mod acse;
pub mod mms;
pub mod presentation;

#[cfg(test)]
mod tests {
    use super::presentation::asn1::*;
    use rasn::prelude::*;

    #[test]
    fn test_basic_types() {
        // Test basic type creation
        let context_id = PresentationContextIdentifier(Integer::from(1));
        assert_eq!(context_id.0, Integer::from(1));

        let selector = PresentationSelector(OctetString::from(vec![0x00, 0x01]));
        assert_eq!(selector.0.as_ref(), &[0x00, 0x01]);

        let mode_selector = ModeSelector::new(Integer::from(1));
        assert_eq!(mode_selector.mode_value, Integer::from(1));
    }

    #[test]
    fn test_cp_type_creation() {
        // Test creating a Connect Presentation PDU (CP)
        let mode_selector = ModeSelector::new(Integer::from(1)); // normal-mode

        let calling_selector =
            CallingPresentationSelector(PresentationSelector(OctetString::from(vec![
                0x00, 0x00, 0x00, 0x01,
            ])));
        let called_selector =
            CalledPresentationSelector(PresentationSelector(OctetString::from(vec![
                0x00, 0x00, 0x00, 0x01,
            ])));

        let normal_mode_params = CPTypeNormalModeParameters::new(
            ProtocolVersion(BitString::new()),
            Some(calling_selector),
            Some(called_selector),
            None, // presentation_context_definition_list
            None, // default_context_name
            None, // presentation_requirements
            None, // user_session_requirements
            None, // user_data
        );

        let cp_type = CPType::new(mode_selector, Some(normal_mode_params));

        // Verify the structure
        assert_eq!(cp_type.mode_selector.mode_value, Integer::from(1));
        assert!(cp_type.normal_mode_parameters.is_some());

        let params = cp_type.normal_mode_parameters.unwrap();
        assert!(params.calling_presentation_selector.is_some());
        assert!(params.called_presentation_selector.is_some());
    }

    #[test]
    fn test_cpa_ppdu_creation() {
        // Test creating a Connect Presentation Accept PDU (CPA)
        let mode_selector = ModeSelector::new(Integer::from(1)); // normal-mode

        let responding_selector =
            RespondingPresentationSelector(PresentationSelector(OctetString::from(vec![
                0x00, 0x00, 0x00, 0x01,
            ])));

        let normal_mode_params = CPAPPDUNormalModeParameters::new(
            ProtocolVersion(BitString::new()),
            Some(responding_selector),
            None, // presentation_context_definition_result_list
            None, // presentation_requirements
            None, // user_session_requirements
            None, // user_data
        );

        let cpa_ppdu = CPAPPDU::new(mode_selector, Some(normal_mode_params));

        // Verify the structure
        assert_eq!(cpa_ppdu.mode_selector.mode_value, Integer::from(1));
        assert!(cpa_ppdu.normal_mode_parameters.is_some());

        let params = cpa_ppdu.normal_mode_parameters.unwrap();
        assert!(params.responding_presentation_selector.is_some());
    }

    #[test]
    fn test_user_data_simply_encoded() {
        // Test creating user data with simply encoded data
        let simply_encoded = SimplyEncodedData(OctetString::from(vec![0x04, 0x05, 0x06]));
        let user_data = UserData::simply_encoded_data(simply_encoded);

        match user_data {
            UserData::simply_encoded_data(sed) => {
                assert_eq!(sed.0.as_ref(), &[0x04, 0x05, 0x06]);
            }
            _ => panic!("Expected simply_encoded_data"),
        }
    }

    #[test]
    fn test_presentation_context_identifiers() {
        // Test valid context identifiers
        let acse_id = PresentationContextIdentifier(Integer::from(1));
        let mms_id = PresentationContextIdentifier(Integer::from(3));
        let other_id = PresentationContextIdentifier(Integer::from(127));

        assert_eq!(acse_id.0, Integer::from(1));
        assert_eq!(mms_id.0, Integer::from(3));
        assert_eq!(other_id.0, Integer::from(127));
    }

    #[test]
    fn test_presentation_selectors() {
        // Test presentation selector creation
        let selector1 = PresentationSelector(OctetString::from(vec![0x00, 0x00, 0x00, 0x01]));
        let selector2 = PresentationSelector(OctetString::from(vec![0x00, 0x00, 0x00, 0x02]));

        assert_ne!(selector1, selector2);
        assert_eq!(selector1.0.as_ref(), &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(selector2.0.as_ref(), &[0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn test_protocol_version() {
        // Test protocol version creation
        let version = ProtocolVersion(BitString::new());
        assert_eq!(version.0.len(), 0);
    }

    #[test]
    fn test_result_codes() {
        // Test context definition result codes
        let accepted = Result(Integer::from(0));
        let user_rejection = Result(Integer::from(1));
        let provider_rejection = Result(Integer::from(2));

        assert_eq!(accepted.0, Integer::from(0));
        assert_eq!(user_rejection.0, Integer::from(1));
        assert_eq!(provider_rejection.0, Integer::from(2));
    }

    #[test]
    fn test_encoding_decoding_roundtrip() {
        // Test that we can encode and decode a CP PDU
        let mode_selector = ModeSelector::new(Integer::from(1));
        let calling_selector =
            CallingPresentationSelector(PresentationSelector(OctetString::from(vec![
                0x00, 0x00, 0x00, 0x01,
            ])));
        let called_selector =
            CalledPresentationSelector(PresentationSelector(OctetString::from(vec![
                0x00, 0x00, 0x00, 0x01,
            ])));

        let normal_mode_params = CPTypeNormalModeParameters::new(
            ProtocolVersion(BitString::new()),
            Some(calling_selector),
            Some(called_selector),
            None,
            None,
            None,
            None,
            None,
        );

        let cp_type = CPType::new(mode_selector, Some(normal_mode_params));

        // Encode
        let encoded = rasn::ber::encode(&cp_type).expect("Failed to encode CP PDU");
        assert!(!encoded.is_empty());

        // Decode
        let decoded: CPType = rasn::ber::decode(&encoded).expect("Failed to decode CP PDU");

        // Verify roundtrip
        assert_eq!(
            cp_type.mode_selector.mode_value,
            decoded.mode_selector.mode_value
        );
        assert!(decoded.normal_mode_parameters.is_some());

        let original_params = cp_type.normal_mode_parameters.unwrap();
        let decoded_params = decoded.normal_mode_parameters.unwrap();

        assert!(original_params.calling_presentation_selector.is_some());
        assert!(decoded_params.calling_presentation_selector.is_some());
        assert!(original_params.called_presentation_selector.is_some());
        assert!(decoded_params.called_presentation_selector.is_some());
    }

    #[test]
    fn test_presentation_object_identifiers() {
        let acse_context_id = rasn::ber::encode(&ObjectIdentifier::new(&[2, 2, 1, 0, 1]))
            .expect("Failed to encode ACSE context ID");
        let mms_context_id = rasn::ber::encode(&ObjectIdentifier::new(&[1, 0, 9506, 2, 1]))
            .expect("Failed to encode MMS context ID");
        let transfer_syntax_name = rasn::ber::encode(&ObjectIdentifier::new(&[2, 1, 1]))
            .expect("Failed to encode transfer syntax name");

        assert_eq!(acse_context_id, vec![0x06, 0x04, 0x52, 0x01, 0x00, 0x01]);
        assert_eq!(
            mms_context_id,
            vec![0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x01]
        );
        assert_eq!(transfer_syntax_name, vec![0x06, 0x02, 0x51, 0x01]);
    }
}
