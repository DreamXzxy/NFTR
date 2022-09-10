module myself::NFTR {
    use aptos_framework::account;
    //use aptos_framework::resource_account;
    use aptos_std::ed25519;
    use aptos_std::table;
    use aptos_std::type_info;
    use std::signer;
    use std::string;
    use std::vector;
    use aptos_token::token;

    #[test_only]
    use aptos_std::debug;

    const MAX_U64: u64 = 18446744073709551615;

    struct Anchor {}

    struct CryptoMinter has store, key {
        counter: u64,
        mints: table::Table<address, bool>,
        public_key: ed25519::ValidatedPublicKey,
        minting_enabled: bool,
        signer_cap: account::SignerCapability,
    }

    const EGIVEN_MESSAGE_NOT_MATCH_EXPECTED_MESSAGE: u64 = 1;
    const EMESSAGE_SIGNATURE_INVALID: u64 = 2;
    const ENOT_AUTHORIZED: u64 = 3;
    const EHAS_ALREADY_CLAIMED_MINT: u64 = 4;
    const EMINTING_NOT_ENABLED: u64 = 5;

    const SEP: vector<u8> = b"::";

    const COLLECTION_NAME: vector<u8> = b"Aptos Zero";
    const TOKEN_NAME: vector<u8> = b"Aptos Zero";

    const TOKEN_URL_PREFIX: vector<u8> = b"https://aptoslabs.com/nft_images/aptos-zero/";

    fun init_module(sender: &signer) {
        // Don't run setup more than once
        if (exists<CryptoMinter>(signer::address_of(sender))) {
            return
        };

        // Set up default public key
        let public_key = std::option::extract(&mut ed25519::new_validated_public_key_from_bytes(x"5a4fc3b498f2d816435bc792b460122db0188d61b4f46cb658c8c7dcef8cf721"));

        // Create the resource account, so we can get ourselves as signer later
        let (resource, signer_cap) = account::create_resource_account(sender, vector::empty());

        // Set up NFT collection
        let collection_name = string::utf8(COLLECTION_NAME);
        let description = string::utf8(b"Every Aptos Zero NFT minted helps us test our long-lived testnet network. Thank you for being a part of the journey!");
        let collection_uri = string::utf8(b"https://aptoslabs.com/nft_offers/aptos-zero");
        let maximum_supply = MAX_U64;
        let mutate_setting = vector<bool>[ false, false, false ];
        token::create_collection(&resource, collection_name, description, collection_uri, maximum_supply, mutate_setting);

        move_to(sender, CryptoMinter { counter: 1, mints: table::new(), public_key, minting_enabled: true, signer_cap });
    }

    fun get_resource_signer(): signer acquires CryptoMinter {
        account::create_signer_with_capability(&borrow_global<CryptoMinter>(@myself).signer_cap)
    }

    public entry fun rotate_key(sign: signer, new_public_key: vector<u8>) acquires CryptoMinter {
        let sender = signer::address_of(&sign);
        assert!(sender == @myself, ENOT_AUTHORIZED);
        let public_key = std::option::extract(&mut ed25519::new_validated_public_key_from_bytes(new_public_key));
        let cm = borrow_global_mut<CryptoMinter>(sender);
        cm.public_key = public_key;
    }

    public entry fun set_minting_enabled(sign: signer, minting_enabled: bool) acquires CryptoMinter {
        let sender = signer::address_of(&sign);
        assert!(sender == @myself, ENOT_AUTHORIZED);
        let cm = borrow_global_mut<CryptoMinter>(sender);
        cm.minting_enabled = minting_enabled;
    }

    const HEX_SYMBOLS: vector<u8> = b"0123456789abcdef";

    public entry fun claim_mint(sign: &signer, message: vector<u8>, signature: vector<u8>) acquires CryptoMinter {
        let cm = borrow_global<CryptoMinter>(@myself);
        assert!(cm.minting_enabled, EMINTING_NOT_ENABLED);
        verify_message(sign, message, signature);
        do_mint(sign);
        set_minted(sign);
    }

    fun do_mint(sign: &signer) acquires CryptoMinter {
        // Mints 1 NFT to the signer
        let sender = signer::address_of(sign);

        let resource = get_resource_signer();

        let cm = borrow_global_mut<CryptoMinter>(@myself);

        let count_str = u64_to_string(cm.counter);

        // Set up the NFT
        let collection_name = string::utf8(COLLECTION_NAME);
        let tokendata_name = string::utf8(TOKEN_NAME);
        string::append_utf8(&mut tokendata_name, b": ");
        string::append(&mut tokendata_name, count_str);
        let nft_maximum: u64 = 1;
        let description = string::utf8(b"Long Live the Testnet!");
        let token_uri: string::String = string::utf8(TOKEN_URL_PREFIX);
        string::append(&mut token_uri, count_str);
        let royalty_payee_address: address = @myself;
        let royalty_points_denominator: u64 = 0;
        let royalty_points_numerator: u64 = 0;
        let token_mutate_config = token::create_token_mutability_config(&vector<bool>[ false, true, false, false, true ]);
        let property_keys: vector<string::String> = vector::singleton(string::utf8(b"mint_number"));
        let property_values: vector<vector<u8>> = vector::singleton(*string::bytes(&u64_to_hex_string(cm.counter)));
        let property_types: vector<string::String> = vector::singleton(string::utf8(b"number"));

        let token_data_id = token::create_tokendata(
            &resource,
            collection_name,
            tokendata_name,
            description,
            nft_maximum,
            token_uri,
            royalty_payee_address,
            royalty_points_denominator,
            royalty_points_numerator,
            token_mutate_config,
            property_keys,
            property_values,
            property_types
        );

        let token_id = token::mint_token(&resource, token_data_id, 1);

        token::initialize_token_store(sign);
        token::opt_in_direct_transfer(sign, true);
        token::transfer(&resource, token_id, sender, 1);
        cm.counter = cm.counter + 1;
    }

    fun set_minted(sign: &signer) acquires CryptoMinter {
        let cm = borrow_global_mut<CryptoMinter>(@myself);
        let signer_addr = signer::address_of(sign);
        assert!(table::contains(&cm.mints, signer_addr) == false, EHAS_ALREADY_CLAIMED_MINT);
        table::add(&mut cm.mints, signer_addr, true);
    }

    fun u64_to_hex_string(value: u64): string::String {
        if (value == 0) {
            return string::utf8(b"0x00")
        };
        let temp: u64 = value;
        let length: u64 = 0;
        while (temp != 0) {
            length = length + 1;
            temp = temp >> 8;
        };
        to_hex_string_fixed_length(value, length)
    }
    fun to_hex_string_fixed_length(value: u64, length: u64): string::String {
        let buffer = vector::empty<u8>();

        let i: u64 = 0;
        while (i < length * 2) {
            vector::push_back(&mut buffer, *vector::borrow(&mut HEX_SYMBOLS, (value & 0xf as u64)));
            value = value >> 4;
            i = i + 1;
        };
        assert!(value == 0, 1);
        vector::append(&mut buffer, b"x0");
        vector::reverse(&mut buffer);
        string::utf8(buffer)
    }

    fun bytes_to_hex_string(bytes: &vector<u8>): string::String {
        let length = vector::length(bytes);
        let buffer = b"0x";

        let i: u64 = 0;
        while (i < length) {
            let byte = *vector::borrow(bytes, i);
            vector::push_back(&mut buffer, *vector::borrow(&mut HEX_SYMBOLS, (byte >> 4 & 0xf as u64)));
            vector::push_back(&mut buffer, *vector::borrow(&mut HEX_SYMBOLS, (byte & 0xf as u64)));
            i = i + 1;
        };
        string::utf8(buffer)
    }

    fun address_to_hex_string(addr: &address): string::String {
        let addr_bytes = std::bcs::to_bytes(addr);
        bytes_to_hex_string(&addr_bytes)
    }

    fun full_type_string<T>(): string::String {
        let info = type_info::type_of<T>();
        let full_name = string::utf8(vector::empty());
        let account_address = address_to_hex_string(&type_info::account_address(&info));
        string::append(&mut full_name, account_address);
        string::append_utf8(&mut full_name, SEP);
        string::append_utf8(&mut full_name, type_info::module_name(&info));
        string::append_utf8(&mut full_name, SEP);
        string::append_utf8(&mut full_name, type_info::struct_name(&info));
        full_name
    }

    fun u64_to_string(value: u64): string::String {
        if (value == 0) {
            return string::utf8(b"0")
        };
        let buffer = vector::empty<u8>();
        while (value != 0) {
            vector::push_back(&mut buffer, ((48 + value % 10) as u8));
            value = value / 10;
        };
        vector::reverse(&mut buffer);
        string::utf8(buffer)
    }

    // Builds the expected message given the signer: ["{our_address}::NFTR::Anchor", signer_address_hex, signer_seq_num_str].join("!")
    fun build_expected_message(sign: &signer): string::String {
        let address = signer::address_of(sign);

        // get the expected anchor
        let type_str = full_type_string<Anchor>();

        // get expected user address
        let address_str = address_to_hex_string(&address);

        // and the sequence number
        let sequence_num = account::get_sequence_number(address);
        let sequence_num_str = u64_to_string(sequence_num);


        let message = string::utf8(vector::empty());
        string::append(&mut message, type_str);
        string::append_utf8(&mut message, b"!");
        string::append(&mut message, address_str);
        string::append_utf8(&mut message, b"!");
        string::append(&mut message, sequence_num_str);
        message
    }

    fun verify_message(sign: &signer, message: vector<u8>, signature: vector<u8>) acquires CryptoMinter {
        let expected_message = build_expected_message(sign);
        assert!(&message == string::bytes(&expected_message), EGIVEN_MESSAGE_NOT_MATCH_EXPECTED_MESSAGE);

        let signature = ed25519::new_signature_from_bytes(signature);
        let cm = borrow_global<CryptoMinter>(@myself);

        assert!(ed25519::signature_verify_strict(&signature, &ed25519::public_key_to_unvalidated(&cm.public_key), message), EMESSAGE_SIGNATURE_INVALID);
    }

    #[test_only]
    fun get_test_message(myself: &signer): string::String {
        let result = address_to_hex_string(&signer::address_of(myself));
        string::append_utf8(&mut result, b"::NFTR::Anchor!0x00000000000000000000000000000000000000000000000000000000000123ff!0");
        result
    }

    #[test(sign = @0x123ff, myself=@myself)]
    public entry fun test_build_expected_message(sign: signer, myself: signer) {
        account::create_account_for_test(signer::address_of(&sign));
        let expected_message = build_expected_message(&sign);
        debug::print(&expected_message);
        assert!(expected_message == get_test_message(&myself), 100001);
    }

    #[test(sign = @0x123ff)]
    public entry fun test_address_to_hex_string(sign: signer) {
        let str = address_to_hex_string(&signer::address_of(&sign));
        debug::print(&str);
        assert!(string::bytes(&str) == &b"0x00000000000000000000000000000000000000000000000000000000000123ff", 100002);
    }

    #[test(myself=@myself)]
    public entry fun test_full_type_string(myself: signer) {
        let str = full_type_string<Anchor>();
        debug::print(&str);
        let result = address_to_hex_string(&signer::address_of(&myself));
        string::append_utf8(&mut result, b"::NFTR::Anchor");
        assert!(str == result, 100003);
    }

    #[test_only]
    public fun setup_and_mint(sign: &signer, aptos: &signer) {
        account::create_account_for_test(signer::address_of(sign));
        account::create_account_for_test(signer::address_of(aptos));
        let (burn_cap, mint_cap) = aptos_framework::aptos_coin::initialize_for_test(aptos);
        aptos_framework::coin::destroy_burn_cap(burn_cap);
        aptos_framework::coin::destroy_mint_cap(mint_cap);
    }

    /* Generated with:
      let act = new AptosAccount(HexString.ensure("0xPRIVATE_KEY").toUint8Array());
      let address = act.address().toString();
      let message = `${address}::NFTR::Anchor!0x00000000000000000000000000000000000000000000000000000000000123ff!0`;
      console.log("message: ", message);
      console.log("signature: ", act.signBuffer(new Buffer(message, "ascii")).hex());
    */

    #[test_only]
    const SIGNATURE: vector<u8> = x"39ae640489d9e313a914bbca04e3a03ee7ebc823def9c2f1bcf02a81f32e80939d146de1699724c736e12ff259b509c9447e37cba96bcdfd947840eca78b180f";

    #[test(sign = @0x123ff, myself = @myself, aptos = @0x1)]
    public entry fun test_verify_message(
        sign: signer, myself: signer, aptos: signer
    ) acquires CryptoMinter {
        setup_and_mint(&sign, &aptos);
        init_module(&myself);

        // 0x092537c0ef46a303dfb183abe2d5fe07b16f69d2c4c2699585ef5b08186d4147::NFTR::Anchor!0x00000000000000000000000000000000000000000000000000000000000123ff!0
        let test_message = *string::bytes(&get_test_message(&myself));
        debug::print(&test_message);
        verify_message(&sign, test_message, SIGNATURE);
    }

    #[test(sign = @0x123ff, myself = @myself, aptos = @0x1)]
    #[expected_failure(abort_code = 2)]
    public entry fun test_verify_message_fails(
        sign: signer, myself: signer, aptos: signer
    ) acquires CryptoMinter {
        setup_and_mint(&sign, &aptos);
        init_module(&myself);

        let signature = x"0000000000000000000000003c239f2349e95ba70af4f6f04468791a734e25803160dfc043721fab36a9a30ddcc5f9e88d5442e43a8d31c764c01237c29ccf05";
        verify_message(&sign, *string::bytes(&get_test_message(&myself)), signature)
    }

    #[test(sign = @0x123ff, myself = @myself)]
    public entry fun test_set_minted(
        sign: signer, myself: signer
    ) acquires CryptoMinter {
        account::create_account_for_test(signer::address_of(&myself));
        init_module(&myself);
        set_minted(&sign);
    }

    #[test(sign = @0x123ff, myself = @myself)]
    #[expected_failure(abort_code = 4)]
    public entry fun test_set_minted_fails(
        sign: signer, myself: signer
    ) acquires CryptoMinter {
        account::create_account_for_test(signer::address_of(&myself));
        init_module(&myself);
        set_minted(&sign);
        set_minted(&sign);
    }

    #[test(sign = @0x123ff, myself = @myself, aptos = @0x1)]
    public entry fun test_e2e(
        sign: signer, myself: signer, aptos: signer
    ) acquires CryptoMinter {
        setup_and_mint(&sign, &aptos);
        account::create_account_for_test(signer::address_of(&myself));
        init_module(&myself);

        claim_mint(&sign, *string::bytes(&get_test_message(&myself)), SIGNATURE);

        // Ensure the NFT exists
        let resource = get_resource_signer();
        let token_name = string::utf8(TOKEN_NAME);
        string::append_utf8(&mut token_name, b": 1");
        let token_id = token::create_token_id_raw(signer::address_of(&resource), string::utf8(COLLECTION_NAME), token_name, 0);
        let new_token = token::withdraw_token(&sign, token_id, 1);
        // Put it back so test doesn't explode
        token::deposit_token(&sign, new_token);
    }

    #[test]
    public entry fun test_u64_to_hex_string2() {
        let eleven = u64_to_hex_string(18);
        debug::print(&eleven);
        assert!(string::bytes(&eleven) == &b"0x12", 100004);
    }

}