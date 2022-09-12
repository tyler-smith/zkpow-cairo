from src.endian import reverse_4byte_endianess

from starkware.cairo.common.bitwise import bitwise_and, bitwise_or
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import unsigned_div_rem, assert_le_felt, assert_lt_felt
from starkware.cairo.common.uint256 import Uint256, uint256_and, uint256_lt, uint256_mul, uint256_or, uint256_shr, uint256_unsigned_div_rem

// nbits_to_target calculates the full Uint256 target value represented by the
// compact base-256 nbits value.
func nbits_to_target{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(nbits : felt) -> Uint256 {
    alloc_locals;

    // nbits of 0 means target is 0
    if (nbits == 0) {
        let z = Uint256(low=0, high=0);
        return z;
    }

    // Bit-shift 24 to the right to get the exponent. Adjust it by 3 to account
    // for the mantissa.
    let (local exponent, _) = unsigned_div_rem(nbits, 2**24);
    assert_le_felt(exponent, 0x1d);
    let exponent_adj = exponent - 3;

    // Get the multiplier from the exponent
    let m_big = Uint256(low=256, high=0);
    let m_multiplier = uint256_pow(m_big, exponent_adj);

    // Get the mantissa from the nbits
    let (x_and_y) = bitwise_and(nbits, 0x007fffff);
    let mantissa = Uint256(low=x_and_y, high=0);

    // Finally, multiply the mantissa by the multiplier
    let (res, _) = uint256_mul(mantissa, m_multiplier);

    return res;
}

// target_to_nbits calculates the base-256 nbits representations of the given
// Uint256 target value.
func target_to_nbits{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(target : Uint256) -> felt {
    alloc_locals; 

    // A target of 0 has an nbits of 0; return early
    if (target.low == 0 and target.high == 0) {
        return 0;
    }

    // Get the number of bytes in the target
    let bit_count = uint256_bit_count(target);
    let (local byte_count, _) = unsigned_div_rem(bit_count + 7, 8);

    // Shift the target over into just the significand that we care about
    let shift_size = 8 * (byte_count - 3);
    let shift_size_big = Uint256(low=shift_size, high=0);
    let (res) = uint256_shr(target, shift_size_big);

    // Ensure it's at most 64 bits
    let mask_64bits = Uint256(low=0xffffffffffffffff, high=0);
    let (res) = uint256_and(res, mask_64bits);
    let low_64bits = res.low;

    // Handle negative
    let (x_and_y) = bitwise_and(low_64bits, 0x00800000);
    if (x_and_y != 0) {
        let (low_64bits_shifted, _) = unsigned_div_rem(low_64bits, 256);
        let or_mask = (byte_count + 1) * 16777216;
        let (x_or_y) = bitwise_or(low_64bits_shifted, or_mask);

        return x_or_y;
    } 

    // Add the exponent
    let or_mask = byte_count * 16777216;
    let (x_or_y) = bitwise_or(low_64bits, or_mask);

    return x_or_y;
}

// target_to_nbits calculates the base-256 nbits representations of the given
// Uint256 target value, and then converts into little endian for use in Bitcoin
// hashing.
func target_to_nbits_little_endian{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(target : Uint256) -> felt {
    let nbits_big_endian = target_to_nbits(target);
    let nbits_little_endian = reverse_4byte_endianess(nbits_big_endian);
    return nbits_little_endian;
}

// calculate_new_target returns the target for the next period from the last
// state of the current period.
func calculate_new_target{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(period_start: felt, period_end: felt, old_target: Uint256) -> Uint256 {
    let actual_span = period_end - period_start;
    let adjusted_span = clamp_timespan(actual_span);
    let adjusted_span_big = Uint256(low=adjusted_span, high=0);

    let (new_target_num, _) = uint256_mul(old_target, adjusted_span_big);
    let expected_span = Uint256(low=1209600, high=0);
    let (new_target_candidate, _) = uint256_unsigned_div_rem(new_target_num, expected_span);

    let max_target =Uint256(low=0, high=0xffff00000000000000000000);
    let (res) = uint256_lt(max_target, new_target_candidate);
    if (res == 1) {
        return max_target;
    }

    return new_target_candidate;
}

// clamp_timespan ensures the timespan doesn't exceed protocol thresholds.
func clamp_timespan{range_check_ptr}(timespan : felt) -> felt {
    alloc_locals;

    local is_too_large : felt;
    local is_too_small : felt;
    %{
        ids.is_too_large = 1 if ids.timespan > 4838400 else 0
        ids.is_too_small = 1 if ids.timespan < 302400 else 0
    %}

    if (is_too_large == 1) {
        assert_le_felt(4838400, timespan);
        return 4838400;
    }

    if (is_too_small == 1) {
        assert_lt_felt(timespan, 302400);
        return 302400;
    }
    
    return timespan;
}

// uint256_bit_count returns the number of bits in the given integer Uint256 n.
func uint256_bit_count{range_check_ptr}(n : Uint256) -> felt {
    if (n.high == 0) {
        return felt_bit_count(n.low);
    }
    let high_count = felt_bit_count(n.high);
    let count = high_count + 128;
    return count;
}

// felt_bit_count returns the number of bits in the given felt integer n.
func felt_bit_count{range_check_ptr}(n : felt) -> felt {
    return _felt_bit_count_inner(0, n);
}

// _felt_bit_count_inner implements the inner-loop logic for felt_bit_count.
func _felt_bit_count_inner{range_check_ptr}(count : felt, n : felt) -> felt {
    if (n != 0) {
        let (half_n, _) = unsigned_div_rem(n, 2);
        return _felt_bit_count_inner(count + 1, half_n);
    }
    return count;
}

// uint256_pow implements the exponentiation function for Uint256 bases.
func uint256_pow{range_check_ptr}(base : Uint256, exp : felt) -> Uint256 {
    return _uint256_pow_inner(base, base, exp);
}

// _uint256_pow_inner implements the inner-loop logic of uint256_pow.
func _uint256_pow_inner{range_check_ptr}(carry : Uint256, base : Uint256, exp : felt) -> Uint256 {
    if (exp == 1) {
        return carry;
    }

    let (res, _) = uint256_mul(carry, base);
    return _uint256_pow_inner(res, base, exp-1);
}
