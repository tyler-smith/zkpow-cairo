%builtins range_check bitwise

from src.endian import reverse_4byte_endianess

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin


func main{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() {
    alloc_locals;
    
    let a = reverse_4byte_endianess(0xAABBCCDD);
    assert a = 0xDDCCBBAA;

    let a = reverse_4byte_endianess(a);
    assert a = 0xAABBCCDD;

    return ();
}