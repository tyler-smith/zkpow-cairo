from src.sha256.packed_sha256 import (
    BLOCK_SIZE,
    compute_message_schedule,
    sha2_compress,
    get_round_constants,
)
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_fp_and_pc, get_label_location
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import unsigned_div_rem

const SHA256_INPUT_CHUNK_SIZE_FELTS = 16;
const SHA256_STATE_SIZE_FELTS = 8;
const SHA256_INSTANCE_SIZE = SHA256_INPUT_CHUNK_SIZE_FELTS + 2 * SHA256_STATE_SIZE_FELTS;


// sha256d_80bytes calculates the double-SHA256 algorithm over exactly 80 bytes
// of input, broken up into 20 4-word felts.
func sha256d_80bytes{range_check_ptr, sha256_ptr: felt*}(header: felt*) -> felt* {
    let digest = sha256_80bytes{sha256_ptr=sha256_ptr}(header);
    let digest = sha256_32bytes{sha256_ptr=sha256_ptr}(digest);
    return digest;
}

// sha256d_80bytes calculates the SHA256 algorithm over exactly 80 bytes of
// input, broken up into 20 4-word felts.
func sha256_80bytes{range_check_ptr, sha256_ptr: felt*}(message: felt*) -> felt* {
    alloc_locals;

    // Copy the message and add the correct padding for an 80 message
    let (local padded_message: felt*) = alloc();
    assert padded_message[0] = message[0];
    assert padded_message[1] = message[1];
    assert padded_message[2] = message[2];
    assert padded_message[3] = message[3];
    assert padded_message[4] = message[4];
    assert padded_message[5] = message[5];
    assert padded_message[6] = message[6];
    assert padded_message[7] = message[7];
    assert padded_message[8] = message[8];
    assert padded_message[9] = message[9];
    assert padded_message[10] = message[10];
    assert padded_message[11] = message[11];
    assert padded_message[12] = message[12];
    assert padded_message[13] = message[13];
    assert padded_message[14] = message[14];
    assert padded_message[15] = message[15];
    assert padded_message[16] = message[16];
    assert padded_message[17] = message[17];
    assert padded_message[18] = message[18];
    assert padded_message[19] = message[19];
    assert padded_message[20] = 0x80000000;
    assert padded_message[21] = 0;
    assert padded_message[22] = 0;
    assert padded_message[23] = 0;
    assert padded_message[24] = 0;
    assert padded_message[25] = 0;
    assert padded_message[26] = 0;
    assert padded_message[27] = 0;
    assert padded_message[28] = 0;
    assert padded_message[29] = 0;
    assert padded_message[30] = 0;
    assert padded_message[31] = 640;

    // 80 bytes requires 2 rounds. Calculate the first, then feeds its output
    // into the second along with the second half the message.
    let (iv: felt*) = get_iv();
    let output = _sha256_raw_chunk(padded_message, iv);

    let padded_message = padded_message + SHA256_INPUT_CHUNK_SIZE_FELTS;
    let output = _sha256_raw_chunk(padded_message, output);

    return output;
}

// sha256d_80bytes calculates the SHA256 algorithm over exactly 32 bytes of
// input, broken up into 8 4-word felts.
func sha256_32bytes{range_check_ptr, sha256_ptr: felt*}(message: felt*) -> felt* {
    alloc_locals;

    // Copy the message and add the correct padding for a 32 message
    let (local padded_message: felt*) = alloc();
    assert padded_message[0] = message[0];
    assert padded_message[1] = message[1];
    assert padded_message[2] = message[2];
    assert padded_message[3] = message[3];
    assert padded_message[4] = message[4];
    assert padded_message[5] = message[5];
    assert padded_message[6] = message[6];
    assert padded_message[7] = message[7];
    assert padded_message[8] = 0x80000000;
    assert padded_message[9] = 0;
    assert padded_message[10] = 0;
    assert padded_message[11] = 0;
    assert padded_message[12] = 0;
    assert padded_message[13] = 0;
    assert padded_message[14] = 0;
    assert padded_message[15] = 256;

    // We only need to perform a single round
    let (iv: felt*) = get_iv();
    return _sha256_raw_chunk(padded_message, iv);
}

// _sha256_raw_chunk processes a single round by copying one block of message
// into the sha256_ptr, then the input state, then the output state. Later we
// can add constraints on these to ensure they're the real digests.
func _sha256_raw_chunk{range_check_ptr, sha256_ptr: felt*}(input: felt*, state: felt*) -> felt* {
    let sha256_start = sha256_ptr;

    // Add the message chunk to the sha256_ptr
    message_loop:
    assert sha256_ptr[0] = input[0];
    assert sha256_ptr[1] = input[1];
    assert sha256_ptr[2] = input[2];
    assert sha256_ptr[3] = input[3];
    assert sha256_ptr[4] = input[4];
    assert sha256_ptr[5] = input[5];
    assert sha256_ptr[6] = input[6];
    assert sha256_ptr[7] = input[7];
    assert sha256_ptr[8] = input[8];
    assert sha256_ptr[9] = input[9];
    assert sha256_ptr[10] = input[10];
    assert sha256_ptr[11] = input[11];
    assert sha256_ptr[12] = input[12];
    assert sha256_ptr[13] = input[13];
    assert sha256_ptr[14] = input[14];
    assert sha256_ptr[15] = input[15];
    let sha256_ptr = sha256_ptr + SHA256_INPUT_CHUNK_SIZE_FELTS;

    // Add the input state to the sha256_ptr
    let input_state_start = sha256_ptr;
    assert sha256_ptr[0] = state[0];
    assert sha256_ptr[1] = state[1];
    assert sha256_ptr[2] = state[2];
    assert sha256_ptr[3] = state[3];
    assert sha256_ptr[4] = state[4];
    assert sha256_ptr[5] = state[5];
    assert sha256_ptr[6] = state[6];
    assert sha256_ptr[7] = state[7];
    let sha256_ptr = sha256_ptr + SHA256_STATE_SIZE_FELTS;

    // Calculate and add the output state to the sha256_ptr
    let output = sha256_ptr;
    %{
        from starkware.cairo.common.cairo_sha256.sha256_utils import (
            compute_message_schedule, sha2_compress_function)

        msg_size = int(ids.SHA256_INPUT_CHUNK_SIZE_FELTS)
        state_size = int(ids.SHA256_STATE_SIZE_FELTS)

        msg = memory.get_range(ids.sha256_start, msg_size)
        input_state = memory.get_range(ids.input_state_start, state_size)

        w = compute_message_schedule(msg)
        output_state = sha2_compress_function(input_state, w)
        segments.write_arg(ids.output, output_state)
    %}
    let sha256_ptr = sha256_ptr + SHA256_STATE_SIZE_FELTS;

    return output;
}

// get_iv returns the 8-word SHA256 initialization vector as an array of felts.
func get_iv() -> (iv: felt*) {
    let (iv_addr) = get_label_location(iv_start);
    return (cast(iv_addr, felt*),);

    iv_start:
    dw 0x6A09E667;
    dw 0xBB67AE85;
    dw 0x3C6EF372;
    dw 0xA54FF53A;
    dw 0x510E527F;
    dw 0x9B05688C;
    dw 0x1F83D9AB;
    dw 0x5BE0CD19;
}

// finalize_sha256 verifies that the results of sha256() are valid.
func finalize_sha256{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    sha256_ptr_start: felt*, sha256_ptr_end: felt*
) {
    alloc_locals;
    let (__fp__, _) = get_fp_and_pc();
    let (round_constants) = get_round_constants();

    // Compute the number of total sha256 instances given
    let (local instance_count, r) = unsigned_div_rem(sha256_ptr_end - sha256_ptr_start, SHA256_INSTANCE_SIZE);
    
    // Ensure there are no incomplete instances
    assert r = 0;

    // Compute the amount of packed blocks needed to handle all the instances
    let (local q, r) = unsigned_div_rem(instance_count, BLOCK_SIZE);

    // If there's no remainder then we can go ahead and finalize
    if (r == 0) {
        _finalize_sha256_inner(sha256_ptr_start, q, round_constants);
        return ();
    }

    // There was a remainder, so add padding inputs before finalizing
    %{
        # Add dummy pairs of input and output.
        from starkware.cairo.common.cairo_sha256.sha256_utils import (
            IV, compute_message_schedule, sha2_compress_function)

        _block_size = int(ids.BLOCK_SIZE)
        assert 0 <= _block_size < 20
        
        _sha256_input_chunk_size_felts = int(ids.SHA256_INPUT_CHUNK_SIZE_FELTS)
        assert 0 <= _sha256_input_chunk_size_felts < 100
        
        _instance_remainder = int(ids.r)
        assert 0 < _instance_remainder

        # Get the number of padding instances to add
        padding_count = _block_size - _instance_remainder

        # Calculate a padding instance
        padding_message = [0] * _sha256_input_chunk_size_felts
        w = compute_message_schedule(padding_message)
        padding_output = sha2_compress_function(IV, w)

        # Write the padding instance to sha256_ptr for each needed pad element
        padding = (padding_message + IV + padding_output) * padding_count
        segments.write_arg(ids.sha256_ptr_end, padding)
    %}

    // Add the actual constraints
    _finalize_sha256_inner(sha256_ptr_start, q+1, round_constants);
    return ();
}

// _finalize_sha256_inner adds the actual constraints on the sha256_ptr, using
// the packed SHA256 algorithm over batches of instances.
func _finalize_sha256_inner{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    sha256_ptr: felt*, n: felt, round_constants: felt*
) {
    if (n == 0) {
        return ();
    }

    alloc_locals;

    local MAX_VALUE = 2 ** 32 - 1;

    let sha256_start = sha256_ptr;

    let (local message_start: felt*) = alloc();
    let (local input_state_start: felt*) = alloc();

    // Handle message.
    tempvar message = message_start;
    tempvar sha256_ptr = sha256_ptr;
    tempvar range_check_ptr = range_check_ptr;
    tempvar m = SHA256_INPUT_CHUNK_SIZE_FELTS;

    message_loop:
    tempvar x0 = sha256_ptr[0 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 0] = x0;
    assert [range_check_ptr + 1] = MAX_VALUE - x0;
    tempvar x1 = sha256_ptr[1 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 2] = x1;
    assert [range_check_ptr + 3] = MAX_VALUE - x1;
    tempvar x2 = sha256_ptr[2 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 4] = x2;
    assert [range_check_ptr + 5] = MAX_VALUE - x2;
    tempvar x3 = sha256_ptr[3 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 6] = x3;
    assert [range_check_ptr + 7] = MAX_VALUE - x3;
    tempvar x4 = sha256_ptr[4 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 8] = x4;
    assert [range_check_ptr + 9] = MAX_VALUE - x4;
    tempvar x5 = sha256_ptr[5 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 10] = x5;
    assert [range_check_ptr + 11] = MAX_VALUE - x5;
    tempvar x6 = sha256_ptr[6 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 12] = x6;
    assert [range_check_ptr + 13] = MAX_VALUE - x6;
    assert message[0] = x0 + 2 ** 35 * x1 + 2 ** (35 * 2) * x2 + 2 ** (35 * 3) * x3 +
        2 ** (35 * 4) * x4 + 2 ** (35 * 5) * x5 + 2 ** (35 * 6) * x6;

    tempvar message = message + 1;
    tempvar sha256_ptr = sha256_ptr + 1;
    tempvar range_check_ptr = range_check_ptr + 14;
    tempvar m = m - 1;
    jmp message_loop if m != 0;

    // Handle input state.
    tempvar input_state = input_state_start;
    tempvar sha256_ptr = sha256_ptr;
    tempvar range_check_ptr = range_check_ptr;
    tempvar m = SHA256_STATE_SIZE_FELTS;

    input_state_loop:
    tempvar x0 = sha256_ptr[0 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 0] = x0;
    assert [range_check_ptr + 1] = MAX_VALUE - x0;
    tempvar x1 = sha256_ptr[1 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 2] = x1;
    assert [range_check_ptr + 3] = MAX_VALUE - x1;
    tempvar x2 = sha256_ptr[2 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 4] = x2;
    assert [range_check_ptr + 5] = MAX_VALUE - x2;
    tempvar x3 = sha256_ptr[3 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 6] = x3;
    assert [range_check_ptr + 7] = MAX_VALUE - x3;
    tempvar x4 = sha256_ptr[4 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 8] = x4;
    assert [range_check_ptr + 9] = MAX_VALUE - x4;
    tempvar x5 = sha256_ptr[5 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 10] = x5;
    assert [range_check_ptr + 11] = MAX_VALUE - x5;
    tempvar x6 = sha256_ptr[6 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 12] = x6;
    assert [range_check_ptr + 13] = MAX_VALUE - x6;
    assert input_state[0] = x0 + 2 ** 35 * x1 + 2 ** (35 * 2) * x2 + 2 ** (35 * 3) * x3 +
        2 ** (35 * 4) * x4 + 2 ** (35 * 5) * x5 + 2 ** (35 * 6) * x6;

    tempvar input_state = input_state + 1;
    tempvar sha256_ptr = sha256_ptr + 1;
    tempvar range_check_ptr = range_check_ptr + 14;
    tempvar m = m - 1;
    jmp input_state_loop if m != 0;

    // Run sha256 on the 7 instances.
    local sha256_ptr: felt* = sha256_ptr;
    local range_check_ptr = range_check_ptr;
    compute_message_schedule(message_start);
    let (outputs) = sha2_compress(input_state_start, message_start, round_constants);
    local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;

    // Handle outputs.
    tempvar outputs = outputs;
    tempvar sha256_ptr = sha256_ptr;
    tempvar range_check_ptr = range_check_ptr;
    tempvar m = SHA256_STATE_SIZE_FELTS;

    output_loop:
    tempvar x0 = sha256_ptr[0 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr] = x0;
    assert [range_check_ptr + 1] = MAX_VALUE - x0;
    tempvar x1 = sha256_ptr[1 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 2] = x1;
    assert [range_check_ptr + 3] = MAX_VALUE - x1;
    tempvar x2 = sha256_ptr[2 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 4] = x2;
    assert [range_check_ptr + 5] = MAX_VALUE - x2;
    tempvar x3 = sha256_ptr[3 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 6] = x3;
    assert [range_check_ptr + 7] = MAX_VALUE - x3;
    tempvar x4 = sha256_ptr[4 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 8] = x4;
    assert [range_check_ptr + 9] = MAX_VALUE - x4;
    tempvar x5 = sha256_ptr[5 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 10] = x5;
    assert [range_check_ptr + 11] = MAX_VALUE - x5;
    tempvar x6 = sha256_ptr[6 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 12] = x6;
    assert [range_check_ptr + 13] = MAX_VALUE - x6;
    assert outputs[0] = x0 + 2 ** 35 * x1 + 2 ** (35 * 2) * x2 + 2 ** (35 * 3) * x3 +
        2 ** (35 * 4) * x4 + 2 ** (35 * 5) * x5 + 2 ** (35 * 6) * x6;

    tempvar outputs = outputs + 1;
    tempvar sha256_ptr = sha256_ptr + 1;
    tempvar range_check_ptr = range_check_ptr + 14;
    tempvar m = m - 1;
    jmp output_loop if m != 0;

    // Done with this block, now handle the next one
    return _finalize_sha256_inner(
        sha256_start + SHA256_INSTANCE_SIZE * BLOCK_SIZE,
        n - 1,
        round_constants,
    );
}
