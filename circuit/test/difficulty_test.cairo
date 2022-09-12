%builtins range_check bitwise

from src.difficulty import nbits_to_target, target_to_nbits, target_to_nbits_little_endian

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256, assert_uint256_eq, uint256_mul


func main{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() {
    alloc_locals;
    
    let target1 = Uint256(low=0, high=0x1bc3300000000000);
    let calculated_target1 = nbits_to_target(0x181BC330);
    assert_uint256_eq(target1, calculated_target1);
    
    let target2 = Uint256(low=0, high=0xffff00000000000000000000);
    let calculated_target2 = nbits_to_target(0x1d00ffff);
    assert_uint256_eq(target2, calculated_target2);

    let nbits1 = target_to_nbits(target1);
    assert nbits1 = 0x181BC330;
    
    let nbits2 = target_to_nbits(target2);  
    assert nbits2 = 0x1d00ffff;

    return ();
}