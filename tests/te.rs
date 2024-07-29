#[cfg(test)]
mod te_tests {
    use goblin::pe;
    use goblin::pe::header::machine_to_str;
    use goblin::pe::section_table::*;

    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#windows-subsystem
    const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u8 = 11;

    #[test]
    fn parse_unloaded_te() {
        let image = include_bytes!("bins/te/test_image.te");
        let te = pe::TE::parse(image).expect("Failed to parse TE");

        assert_eq!(machine_to_str(te.header.machine), "X86_64");
        assert_eq!(te.header.number_of_sections, 5);
        assert_eq!(te.header.subsystem, IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER);

        // Pre-determined field values to be correct for this specific binary
        assert_eq!(te.header.stripped_size, 0x1c8);
        assert_eq!(te.header.entry_point, 0x10a8);
        assert_eq!(te.header.base_of_code, 0x0e60);
        assert_eq!(te.header.image_base, 0x0);
        assert_eq!(te.header.reloc_dir.virtual_address, 0x6e58);
        assert_eq!(te.header.reloc_dir.size, 0x0);
        assert_eq!(te.header.debug_dir.virtual_address, 0x3a64);
        assert_eq!(te.header.debug_dir.size, 0x54);

        // Verify section information is correct - with pre-determined values
        // known to be correct. For brevity sake, check first and last entries.
        assert_eq!(String::from_utf8_lossy(&te.sections[0].name), ".text\0\0\0");
        assert_eq!(te.sections[0].virtual_address, 0xe60);
        assert_eq!(te.sections[0].virtual_size, 0x17db);
        assert_eq!(te.sections[0].pointer_to_linenumbers, 0);
        assert_eq!(te.sections[0].pointer_to_raw_data, 0xe60);
        assert_eq!(te.sections[0].pointer_to_relocations, 0);
        assert_eq!(
            te.sections[0].characteristics,
            IMAGE_SCN_MEM_EXECUTE
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_NOT_PAGED
                | IMAGE_SCN_CNT_CODE
        );

        assert_eq!(String::from_utf8_lossy(&te.sections[4].name), ".xdata\0\0");
        assert_eq!(te.sections[4].virtual_address, 0x5e60);
        assert_eq!(te.sections[4].virtual_size, 0x98);
        assert_eq!(
            te.sections[4].characteristics,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_CNT_INITIALIZED_DATA
        );
        assert_eq!(te.sections[4].pointer_to_linenumbers, 0);
        assert_eq!(te.sections[4].pointer_to_raw_data, 0x5e60);
        assert_eq!(te.sections[4].pointer_to_relocations, 0);

        // Verify the debug directory is correct
        assert_eq!(te.debug_data.image_debug_directory.size_of_data, 0xab);
        assert_eq!(
            te.debug_data.image_debug_directory.address_of_raw_data,
            0x3b54
        );
        assert_eq!(
            te.debug_data.image_debug_directory.pointer_to_raw_data,
            0x3b54
        );
        let debug_info = te.debug_data.codeview_pdb70_debug_info.unwrap();
        assert_eq!(
            debug_info.signature,
            [
                0x70, 0xfb, 0xb5, 0x4b, 0xcf, 0x68, 0x15, 0x42, 0xa1, 0x2b, 0xa5, 0xc5, 0x51, 0x95,
                0x0a, 0x4a
            ]
        );
        assert_eq!(String::from_utf8_lossy(debug_info.filename), String::from("c:\\src\\mu_tiano_platforms\\Build\\QemuQ35Pkg\\DEBUG_VS2022\\X64\\QemuQ35Pkg\\RustTerseImageTestDxe\\RustTerseImageTestDxe\\DEBUG\\RustTerseImageTestDxe.pdb\0"));

        // Misc matches
        assert_eq!(te.header.base_of_code, te.sections[0].virtual_address);
    }

    /// Verify that parsing of a loaded TE image works.
    #[test]
    fn parse_loaded_te() {
        let image = include_bytes!("bins/te/test_image.te");
        let te = pe::TE::parse(image).expect("Failed to parse TE");

        let loaded_image = include_bytes!("bins/te/test_image_loaded.bin");
        let te_loaded = pe::TE::parse(loaded_image).expect("Failed to parse TE");

        assert_eq!(te.header, te_loaded.header);
        assert_eq!(te.sections, te_loaded.sections);
        assert_eq!(te.debug_data, te_loaded.debug_data);
    }

    /// Verify that parsing of a relocated TE image works. Raw data should be different due to
    /// the relocations being applied, but that is outside the scope of goblin.
    #[test]
    fn parse_relocated_te() {
        let loaded_image = include_bytes!("bins/te/test_image_loaded.bin");
        let te_loaded = pe::TE::parse(loaded_image).expect("Failed to parse TE");

        let relocated_image = include_bytes!("bins/te/test_image_relocated.bin");
        let te_relocated = pe::TE::parse(relocated_image).expect("Failed to parse TE");

        // Only the image base should be different in the section headers.
        assert_ne!(te_loaded.header.image_base, te_relocated.header.image_base);
        assert_eq!(te_loaded.sections, te_relocated.sections);
        assert_eq!(te_loaded.debug_data, te_relocated.debug_data);
    }
}
