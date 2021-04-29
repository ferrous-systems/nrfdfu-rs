use std::iter;

use object::{
    elf::{FileHeader32, PT_LOAD},
    read::elf::{FileHeader, ProgramHeader},
    Bytes, Endianness, FileKind,
};

use crate::{init_packet::build_init_packet, Result};

pub struct DfuPackage {
    pub init_packet: Vec<u8>,
    pub image: Vec<u8>,
}

impl DfuPackage {
    pub fn from_elf(elf: &[u8]) -> Result<Self> {
        struct Chunk<'a> {
            flash_addr: u32,
            data: &'a [u8],
        }

        let file_kind = object::FileKind::parse(elf)
            .map_err(|e| format!("failed to parse firmware as ELF file: {}", e))?;
        if !matches!(file_kind, FileKind::Elf32) {
            return Err(format!(
                "firmware file has unsupported format {:?} (only 32-bit ELF files are supported)",
                file_kind
            )
            .into());
        }

        // Collect the to-be-flashed chunks.
        let mut chunks = Vec::new();

        let header = FileHeader32::<Endianness>::parse(Bytes(elf))?;
        let endian = header.endian()?;
        for program in header.program_headers(endian, Bytes(elf))? {
            let data = program
                .data(endian, Bytes(elf))
                .map_err(|()| format!("failed to load segment data (corrupt ELF?)"))?;
            let p_type = program.p_type(endian);

            if !data.is_empty() && p_type == PT_LOAD {
                chunks.push(Chunk {
                    flash_addr: program.p_paddr(endian),
                    data: data.0,
                });
            }
        }

        chunks.sort_by_key(|chunk| chunk.flash_addr);

        if chunks.is_empty() {
            return Err(format!("no loadable program segments found").into());
        }

        let mut image = Vec::new();
        let mut addr = chunks[0].flash_addr;
        eprintln!("firmware starts at {:#x}", addr);
        for chunk in &chunks {
            if chunk.flash_addr < addr {
                return Err(format!(
                    "overlapping program segments at 0x{:08x} (corrupt ELF?)",
                    chunk.flash_addr
                )
                .into());
            }

            // Fill gaps between chunks with erased 0xFF bytes.
            let gap = chunk.flash_addr - addr;
            image.extend(iter::once(0xFF).take(gap as usize));
            if gap > 0 {
                eprintln!("0x{:08x}-0x{:08x} (gap)", addr, chunk.flash_addr - 1);
            }

            image.extend(chunk.data);

            eprintln!(
                "0x{:08x}-0x{:08x}",
                chunk.flash_addr,
                chunk.flash_addr as usize + chunk.data.len()
            );
            addr += chunk.data.len() as u32;
        }

        Ok(Self {
            init_packet: build_init_packet(&image),
            image,
        })
    }
}
