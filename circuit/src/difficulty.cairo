from src.endian import reverse_4byte_endianess

from starkware.cairo.common.bitwise import bitwise_and, bitwise_or
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import unsigned_div_rem, assert_le_felt, assert_lt_felt
from starkware.cairo.common.uint256 import Uint256, uint256_add, uint256_and, uint256_check, uint256_le, uint256_lt, uint256_mul, uint256_or, uint256_shr, uint256_sub, uint256_unsigned_div_rem

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

// calculate_work_from_target determines the amount of work proven by a header
// with the given difficulty target.
func calculate_work_from_target{range_check_ptr}(target: Uint256) -> Uint256 {
    alloc_locals;

    let one = Uint256(low=1, high=0);

    // Targets < 1 are undefined
    let (target_gt_one) = uint256_le(target, one);
    assert target_gt_one = 0;

    // Use target+1 as the divisor, per the spec
    let (divisor, add_carry) = uint256_add(target, one);
    assert add_carry = 0;


    // Calulate the quotient and remainder from (max+1)/(target+1). These will
    // both fit in Uint256 because the numerator is 257 bits and divisor must
    // be >= 2
    let max = max_target();
    local quotient: Uint256;
    local remainder: Uint256;
    %{
        num = (ids.max.high << 128) + ids.max.low + 1
        den = (ids.divisor.high << 128) + ids.divisor.low
        quotient, remainder = divmod(num, den)

        ids.quotient.low = quotient & ((1 << 128) - 1)
        ids.quotient.high = quotient >> 128
        ids.remainder.low = remainder & ((1 << 128) - 1)
        ids.remainder.high = remainder >> 128
    %}
    uint256_check(quotient);
    uint256_check(remainder);

    // The natural validity check is:
    //
    //   divisor * quotient + remainder == numerator
    //
    // but to avoid dealing with overflowing Uint256s we instead check:
    //
    //   divisor * (quotient-1) + remainder = numerator - divisor
    //
    // Because divisor = target + 1, and numerator = 1<<256, we can calulate
    // (numerator - divisor) with 2^256 - 1 - target and completely avoid any
    // integers with >256 bits.

    let (numerator_minus_divisor) = uint256_sub(max, target);
    let (quotient_minus_one) = uint256_sub(quotient, one);

    let (res_mul, carry) = uint256_mul(quotient_minus_one, divisor);
    assert carry = Uint256(0, 0);
    let (check_val, add_carry) = uint256_add(res_mul, remainder);
    assert check_val = numerator_minus_divisor;
    assert add_carry = 0;

    let (is_valid) = uint256_lt(remainder, divisor);
    assert is_valid = 1;

    return quotient;
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

// max_target returns the maximum possible target value (minimum difficulty)
func max_target() -> Uint256 {
    let max = Uint256(low=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, high=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
    return max;
}
