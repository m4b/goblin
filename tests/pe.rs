use goblin::elf::Sym;
use goblin::pe::PE;

#[repr(C)]
#[repr(align(64))] // Align to cache lines
pub struct AlignedData<T: ?Sized>(T);

#[test]
fn test_can_map_exception_rva() {
    static DATA: &[u8] =
        include_bytes!("bins/pe/exception_rva_mapping/amdcleanuputility.exe.upx_packed");
    PE::parse(DATA).unwrap();
}
