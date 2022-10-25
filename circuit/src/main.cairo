%builtins output range_check bitwise

from src.difficulty import calculate_new_target, target_to_nbits_little_endian
from src.endian import reverse_4byte_endianess
from src.sha256.sha256 import finalize_sha256, sha256d_80bytes

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import unsigned_div_rem
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.uint256 import Uint256, uint256_add, uint256_le, uint256_unsigned_div_rem

// PeriodLength is the number of blocks between difficulty adjustments.
const PeriodLength = 2016;

// DEBUG* are temporary flags during development that turns on verbose logging
// and additional assertions that don't affect the integrity of the computation,
// but catch errors earlier.
const DEBUG_LOGGING = 0;
const DEBUG_ASSERTS = 0;

// SHA256State represents the internal state of the SHA256 hash function.
// We keep hashes in this state internally.
struct SHA256State {
    w0: felt, 
    w1: felt,
    w2: felt, 
    w3: felt,
    w4: felt,
    w5: felt,
    w6: felt,
    w7: felt,
}

// Header represents a complete block header. Each felt in the struct, including
// children structs, represents 1 4-byte word.
struct Header {
    version: felt,
    prev_hash: SHA256State,
    merkle_root: SHA256State,
    time: felt,
    nbits: felt,
    nonce: felt,
}

// NewHeader represents the values supplied to the program to add new headers
// to the current state. It does not include the previous hash or nbits because
// we calculate those internally.
struct NewHeader {
    version: felt,
    merkle_root: SHA256State,
    time: felt,
    nonce: felt,
}

// State represents the current state of the system at a point in time.
struct State {
    genesis_hash: Uint256,
    height: felt,
    weight: Uint256,
    target: Uint256,
    period_started_at: felt,
    header: Header,
    hash: SHA256State,
}

// Output represents the program's output. It contains the initial state and the
// resulting state.
struct Output {
    old_state: State,
    new_state: State,
}

// get_new_headers loads the new header values from the program input.
func get_new_headers() -> (headers: NewHeader**, n_headers: felt) {
    alloc_locals;
    local headers: NewHeader**;
    local n_headers: felt;
    %{
        headers = [
            [
                header[0],
                header[1],
                header[2],
                header[3],
                header[4],
                header[5],
                header[6],
                header[7],
                header[8],
                header[9],
                header[10]
            ]
            for header in program_input['new_headers']
        ]
        ids.headers = segments.gen_arg(headers)
        ids.n_headers = len(headers)
    %}
    return (headers=headers, n_headers=n_headers);
}

// append_headers takes an initial state a list of headers, and applies each
// header the current state sequentially.
func append_headers{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, sha256_ptr: felt*}(state: State*, headers: NewHeader**, n_headers: felt) -> State* {
    if (n_headers == 0) {
        return state;
    }

    let state = append_header(state, [headers]);
    return append_headers(state, headers + 1, n_headers - 1);
}

// append_header takes a state and a single header, applies the header to the
// state, validates its correctness, and returns the new state.
func append_header{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, sha256_ptr: felt*}(old_state: State*, new_header: NewHeader*) -> State* {
    alloc_locals;
    let (__fp__, _) = get_fp_and_pc();

    // Create new state for the next height
    local new_state: State;
    assert new_state.height = old_state.height + 1;

    // This will never be the genesis header, so simply copy the genesis hash
    assert new_state.genesis_hash.low = old_state.genesis_hash.low;
    assert new_state.genesis_hash.high = old_state.genesis_hash.high;

    // Copy the input header into the new state
    assert new_state.header.version = new_header.version;
    assert new_state.header.merkle_root.w0 = new_header.merkle_root.w0;
    assert new_state.header.merkle_root.w1 = new_header.merkle_root.w1;
    assert new_state.header.merkle_root.w2 = new_header.merkle_root.w2;
    assert new_state.header.merkle_root.w3 = new_header.merkle_root.w3;
    assert new_state.header.merkle_root.w4 = new_header.merkle_root.w4;
    assert new_state.header.merkle_root.w5 = new_header.merkle_root.w5;
    assert new_state.header.merkle_root.w6 = new_header.merkle_root.w6;
    assert new_state.header.merkle_root.w7 = new_header.merkle_root.w7;
    assert new_state.header.time = new_header.time;
    assert new_state.header.nonce = new_header.nonce;

    // Copy the previous header hash into the new state header
    assert new_state.header.prev_hash.w0 = old_state.hash.w0;
    assert new_state.header.prev_hash.w1 = old_state.hash.w1;
    assert new_state.header.prev_hash.w2 = old_state.hash.w2;
    assert new_state.header.prev_hash.w3 = old_state.hash.w3;
    assert new_state.header.prev_hash.w4 = old_state.hash.w4;
    assert new_state.header.prev_hash.w5 = old_state.hash.w5;
    assert new_state.header.prev_hash.w6 = old_state.hash.w6;
    assert new_state.header.prev_hash.w7 = old_state.hash.w7;

    // Check if we're starting a new period or not.
    let (local q, r) = unsigned_div_rem(new_state.height, PeriodLength);

    // New period; calulate new target/nbits before finishing
    if (r == 0) {
        %{
            if ids.DEBUG_LOGGING == 1:
                print("Changing periods...")
        %}

        let old_header_time_big_endian = reverse_4byte_endianess(old_state.header.time);
        let new_header_time_big_endian = reverse_4byte_endianess(new_header.time);
        let new_target = calculate_new_target(old_state.period_started_at, old_header_time_big_endian, old_state.target);
        let new_nbits = target_to_nbits_little_endian{range_check_ptr=range_check_ptr, bitwise_ptr=bitwise_ptr}(new_target);
       
        assert new_state.period_started_at = new_header_time_big_endian;
        assert new_state.target.low = new_target.low;
        assert new_state.target.high = new_target.high;
        assert new_state.header.nbits = new_nbits;

        set_state_hash(&new_state);
        set_state_weight(old_state.weight, &new_state);
        validate_state(&new_state);
        _debug_check_after_append_header(&new_state);
        
        return &new_state;
    } 

    // Same period; just use the old target
    assert new_state.period_started_at = old_state.period_started_at;
    assert new_state.target.low = old_state.target.low;
    assert new_state.target.high = old_state.target.high;
    assert new_state.header.nbits = old_state.header.nbits;

    set_state_hash(&new_state);
    set_state_weight(old_state.weight, &new_state);
    validate_state(&new_state);
    _debug_check_after_append_header(&new_state);

    return &new_state;
}

// hash_header copies the header values into a felt* and applies the sha256d
func hash_header{range_check_ptr,sha256_ptr: felt*}(h : Header) -> felt* {
    let (header_ptr : felt*) = alloc();
    assert header_ptr[0] = h.version;
    assert header_ptr[1] = h.prev_hash.w0;
    assert header_ptr[2] = h.prev_hash.w1;
    assert header_ptr[3] = h.prev_hash.w2;
    assert header_ptr[4] = h.prev_hash.w3;
    assert header_ptr[5] = h.prev_hash.w4;
    assert header_ptr[6] = h.prev_hash.w5;
    assert header_ptr[7] = h.prev_hash.w6;
    assert header_ptr[8] = h.prev_hash.w7;
    assert header_ptr[9] = h.merkle_root.w0;
    assert header_ptr[10] = h.merkle_root.w1;
    assert header_ptr[11] = h.merkle_root.w2;
    assert header_ptr[12] = h.merkle_root.w3;
    assert header_ptr[13] = h.merkle_root.w4;
    assert header_ptr[14] = h.merkle_root.w5;
    assert header_ptr[15] = h.merkle_root.w6;
    assert header_ptr[16] = h.merkle_root.w7;
    assert header_ptr[17] = h.time;
    assert header_ptr[18] = h.nbits;
    assert header_ptr[19] = h.nonce;

    %{
        if ids.DEBUG_LOGGING == 1:
            print("h.version: " + str(ids.h.version))
            print("h.prev_hash.w0: " + str(ids.h.prev_hash.w0))
            print("h.prev_hash.w1: " + str(ids.h.prev_hash.w1))
            print("h.prev_hash.w2: " + str(ids.h.prev_hash.w2))
            print("h.prev_hash.w3: " + str(ids.h.prev_hash.w3))
            print("h.prev_hash.w4: " + str(ids.h.prev_hash.w4))
            print("h.prev_hash.w5: " + str(ids.h.prev_hash.w5))
            print("h.prev_hash.w6: " + str(ids.h.prev_hash.w6))
            print("h.prev_hash.w7: " + str(ids.h.prev_hash.w7))
            print("h.merkle_root.w0: " + str(ids.h.merkle_root.w0))
            print("h.merkle_root.w1: " + str(ids.h.merkle_root.w1))
            print("h.merkle_root.w2: " + str(ids.h.merkle_root.w2))
            print("h.merkle_root.w3: " + str(ids.h.merkle_root.w3))
            print("h.merkle_root.w4: " + str(ids.h.merkle_root.w4))
            print("h.merkle_root.w5: " + str(ids.h.merkle_root.w5))
            print("h.merkle_root.w6: " + str(ids.h.merkle_root.w6))
            print("h.merkle_root.w7: " + str(ids.h.merkle_root.w7))
            print("h.time: " + str(ids.h.time))
            print("h.nbits: " + str(ids.h.nbits))
            print("h.nonce: " + str(ids.h.nonce))
    %}

    return sha256d_80bytes{sha256_ptr=sha256_ptr}(header_ptr);
}

// set_state_hash hashes the the state header and sets it.
func set_state_hash{range_check_ptr, sha256_ptr: felt*}(s : State*) {
    let hash_bytes = hash_header{sha256_ptr=sha256_ptr}(s.header);
    assert s.hash.w0 = hash_bytes[0];
    assert s.hash.w1 = hash_bytes[1];
    assert s.hash.w2 = hash_bytes[2];
    assert s.hash.w3 = hash_bytes[3];
    assert s.hash.w4 = hash_bytes[4];
    assert s.hash.w5 = hash_bytes[5];
    assert s.hash.w6 = hash_bytes[6];
    assert s.hash.w7 = hash_bytes[7];
    return ();
}

// set_state_weight calcaultes the weight created by the new state and adds it
// to the existing weight.
func set_state_weight{range_check_ptr}(old_weight : Uint256, new_state : State*) {
    let max = Uint256(low=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, high=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
    let (new_additional_weight, _) = uint256_unsigned_div_rem(max, new_state.target);
    let (new_total_weight, carry) = uint256_add(old_weight, new_additional_weight);

    assert carry = 0;
    assert new_state.weight.low = new_total_weight.low;
    assert new_state.weight.high = new_total_weight.high;
    return ();
}

// validate_state performs the checks to ensure the new header is valid. This
// includes ensuring the hash is small enough for the current target.
func validate_state{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(state: State*) {
    assert state.header.version = 16777216;

    // Validate the PoW
    let hash_uint256 = pack_hash(state.hash);
    let (res) = uint256_le(hash_uint256, state.target);
    assert res = 1;

    return ();
}

// pack_hash creates a Uint256 from a SHA256 state.
func pack_hash{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(s : SHA256State) -> Uint256 {
    alloc_locals;

    // The last word will always be 0 in a valid header hash. We can assert it's
    // 0 and then ignore it.
    assert s.w7 = 0;

    local w0 = reverse_4byte_endianess(s.w0);
    local w1 = reverse_4byte_endianess(s.w1);
    local w2 = reverse_4byte_endianess(s.w2);
    local w3 = reverse_4byte_endianess(s.w3);
    local w4 = reverse_4byte_endianess(s.w4);
    local w5 = reverse_4byte_endianess(s.w5);
    local w6 = reverse_4byte_endianess(s.w6);

    local low = w0 + 2 ** 32 * w1 + 2 ** 64 * w2 + 2 ** 96 * w3;
    local high = w4 + 2 ** 32 * w5 + 2 ** 64 * w6;
    let hash = Uint256(low=low, high=high);

    return hash;
}

// write_output sends the input and output states to the output buffer.
func write_output{output_ptr: felt*}(old_state : State*, new_state : State*) {
    let output = cast(output_ptr, Output*);
    let output_ptr = output_ptr + Output.SIZE;
    assert output.old_state = [old_state];
    assert output.new_state = [new_state];
    return ();
}

// _debug_check_after_append_header performs assertions to check program
// correctness during header generation. It should not be called in production,
// and is just to catch regressions while developing.
func _debug_check_after_append_header{bitwise_ptr: BitwiseBuiltin*}(state : State*) {
    %{
        #print("Applied block " + str(ids.state.height))
    %}

    if (DEBUG_ASSERTS != 1) {
        return ();
    }

    if (state.height == 1){
        assert state.hash.w0 = 1214311192;
        assert state.hash.w1 = 3206223392;
        assert state.hash.w2 = 3816723600;
        assert state.hash.w3 = 4236919413;
        assert state.hash.w4 = 339832791;
        assert state.hash.w5 = 1364831110;
        assert state.hash.w6 = 1754176131;
        assert state.hash.w7 = 0;
        return ();
    }

    if (state.height == 2){
        assert state.hash.w0 = 3185416652;
        assert state.hash.w1 = 4255358369;
        assert state.hash.w2 = 2970144282;
        assert state.hash.w3 = 1567622029;
        assert state.hash.w4 = 177634220;
        assert state.hash.w5 = 3062590307;
        assert state.hash.w6 = 106914410;
        assert state.hash.w7 = 0;
        return ();
    }

    if (state.height == 136){
		assert state.hash.w0 = 2042266655;
		assert state.hash.w1 = 4061047328;
		assert state.hash.w2 = 1951425496;
		assert state.hash.w3 = 3045976810;
		assert state.hash.w4 = 4233166640;
		assert state.hash.w5 = 1436215262;
		assert state.hash.w6 = 962037944;
		assert state.hash.w7 = 0;
		return ();
    }

    if (state.height == 654){
        assert state.hash.w0 = 879055790;
		assert state.hash.w1 = 57172736;
		assert state.hash.w2 = 3735764904;
		assert state.hash.w3 = 3731121276;
		assert state.hash.w4 = 2131083962;
		assert state.hash.w5 = 1802154925;
		assert state.hash.w6 = 457471993;
		assert state.hash.w7 = 0;
		return ();
    }

    if (state.height == 32256){
        assert state.header.nbits = 1792540701;
        return ();
    }

    return ();
}

func main{output_ptr: felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() {
    alloc_locals;
    let (__fp__, _) = get_fp_and_pc();

    // Create memory for sha256 operations. All sha256 input and output blocks
    // are stored here without constraints, and later we'll apply constraints to
    // ensure they're all calculated correctly.
    let (local sha256_ptr_start: felt*) = alloc();
    let sha256_ptr = sha256_ptr_start;

    // Load the initial state from program input
    local initial_state: State;
    %{
        ids.initial_state.height = program_input['height']

        ids.initial_state.period_started_at = program_input['period_started_at']

        ids.initial_state.weight.low = program_input['weight']['low']
        ids.initial_state.weight.high = program_input['weight']['high']

        ids.initial_state.target.low = program_input['target']['low']
        ids.initial_state.target.high = program_input['target']['high']

        if ids.initial_state.height != 0:
            ids.initial_state.genesis_hash.low = program_input['genesis_hash']['low']
            ids.initial_state.genesis_hash.high = program_input['genesis_hash']['high']

        header = program_input['header']
        ids.initial_state.header.version = header[0]
        ids.initial_state.header.prev_hash.w0 = header[1]
        ids.initial_state.header.prev_hash.w1 = header[2]
        ids.initial_state.header.prev_hash.w2 = header[3]
        ids.initial_state.header.prev_hash.w3 = header[4]
        ids.initial_state.header.prev_hash.w4 = header[5]
        ids.initial_state.header.prev_hash.w5 = header[6]
        ids.initial_state.header.prev_hash.w6 = header[7]
        ids.initial_state.header.prev_hash.w7 = header[8]
        ids.initial_state.header.merkle_root.w0 = header[9]
        ids.initial_state.header.merkle_root.w1 = header[10]
        ids.initial_state.header.merkle_root.w2 = header[11]
        ids.initial_state.header.merkle_root.w3 = header[12]
        ids.initial_state.header.merkle_root.w4 = header[13]
        ids.initial_state.header.merkle_root.w5 = header[14]
        ids.initial_state.header.merkle_root.w6 = header[15]
        ids.initial_state.header.merkle_root.w7 = header[16]
        ids.initial_state.header.time = header[17]
        ids.initial_state.header.nbits = header[18]
        ids.initial_state.header.nonce = header[19]
    %}

    // Hash the input state
    set_state_hash{sha256_ptr=sha256_ptr}(&initial_state);

    // If this is the genesis header, set our genesis_hash
    let packed_hash = pack_hash(initial_state.hash);
    if (initial_state.height == 0) {
        assert initial_state.genesis_hash.low = packed_hash.low;
        assert initial_state.genesis_hash.high = packed_hash.high;
    }

    // Load new headers from input and append them sequentially
    let state = initial_state;
    let (headers, n_headers) = get_new_headers();
    let new_state = append_headers{sha256_ptr=sha256_ptr}(&state, headers, n_headers);

    // Add sha256 constraints
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr);

    // Write the input and output states
    write_output(&initial_state, new_state);

    return ();
}

