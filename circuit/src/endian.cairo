from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_le, unsigned_div_rem

func reverse_4byte_endianess{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(n : felt) -> felt {
    // We must not be greater than 4 bytes
    assert_le(n, 0xFFFFFFFF);

    // Use right-shifts and AND-masks to get each of the 4 bytes
    let (n2, _) = unsigned_div_rem(n, 2**08);
    let (n3, _) = unsigned_div_rem(n, 2**16);
    let (n4, _) = unsigned_div_rem(n, 2**24);
    assert bitwise_ptr[0].x = n;
    assert bitwise_ptr[1].x = n2;
    assert bitwise_ptr[2].x = n3;
    assert bitwise_ptr[3].x = n4;
    assert bitwise_ptr[0].y = 0xFF;
    assert bitwise_ptr[1].y = 0xFF;
    assert bitwise_ptr[2].y = 0xFF;
    assert bitwise_ptr[3].y = 0xFF;

    // Set the new n with the bytes reversed
    let n = bitwise_ptr[0].x_and_y * 2**24 +
            bitwise_ptr[1].x_and_y * 2**16 +
            bitwise_ptr[2].x_and_y * 2**08 +
            bitwise_ptr[3].x_and_y;

    // Advance the bitwise_ptr for each use above
    let bitwise_ptr = bitwise_ptr + 4*BitwiseBuiltin.SIZE;

    return n;
}
