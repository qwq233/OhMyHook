use super::*;

impl Image {
    pub(super) fn scan_symbol_relocations(
        &self,
        memory: &Memory<'_>,
        requested: &[SymbolQuery<'_>],
        scans: &mut [RelocationScan],
    ) -> Result<()> {
        if scans.len() != requested.len() {
            return Err(Error::InvalidElf("symbol result count mismatch"));
        }
        let strtab = self
            .dynamic
            .strtab
            .ok_or(Error::InvalidElf("missing DT_STRTAB"))?;
        let strsz = self
            .dynamic
            .strsz
            .ok_or(Error::InvalidElf("missing DT_STRSZ"))?;
        let symtab = self
            .dynamic
            .symtab
            .ok_or(Error::InvalidElf("missing DT_SYMTAB"))?;
        let syment = self
            .dynamic
            .syment
            .ok_or(Error::InvalidElf("missing DT_SYMENT"))?;
        let expected_syment = self.header.class.sym_size() as u64;
        if syment != expected_syment {
            return Err(Error::InvalidElf("unexpected DT_SYMENT"));
        }
        let symbol_count = self.dynamic_symbol_count(memory, symtab, syment)?;
        let strtab_address = absolute_address(strtab)?;
        let strtab_size = usize::try_from(strsz).map_err(|_| Error::ArithmeticOverflow)?;
        if strtab_size > MAX_TABLE_SIZE {
            return Err(Error::InvalidElf("dynamic string table is too large"));
        }
        if !range_in_ranges(strtab_address, strtab_size, &self.load_ranges) {
            return Err(Error::InvalidElf("DT_STRTAB exceeds PT_LOAD"));
        }
        let needs_versions = requested
            .iter()
            .any(|query| query.version() != SymbolVersion::Any);
        let needs_exact_versions = requested
            .iter()
            .any(|query| matches!(query.version(), SymbolVersion::Exact(_)));
        let versions = needs_versions
            .then(|| self.parse_version_metadata(memory, strtab, strsz, needs_exact_versions))
            .transpose()?;
        let mut queries = requested
            .iter()
            .enumerate()
            .map(|(output, query)| ResolvedSymbolQuery {
                output,
                name: query.name().to_bytes(),
                version: query.version(),
                strtab,
                strsz,
                symtab,
                symbol_count,
                versions: versions.as_ref(),
            })
            .collect::<Vec<_>>();
        queries.sort_unstable_by(|left, right| {
            left.name
                .cmp(right.name)
                .then(left.output.cmp(&right.output))
        });
        // The symbol and string tables belong to the Image, not to an
        // individual REL/RELA/APS2 table.  Build the validated byte views once
        // and lend them to every relocation decoder below.
        let mut symbol_tables =
            SymbolTables::new(memory, &queries, self.header.class, &self.load_ranges);
        let hash_filter = SymbolHashPrefilter::new(self, memory);
        symbol_tables.single_exact_index =
            self.single_exact_symbol_index(memory, &queries, &symbol_tables, &hash_filter)?;
        for table in self.relocation_tables()? {
            self.scan_relocation_table_with_tables(
                memory,
                &queries,
                &symbol_tables,
                &hash_filter,
                table,
                scans,
            )?;
        }
        Ok(())
    }

    pub(super) fn find_exact_relocation(
        &self,
        memory: &Memory<'_>,
        query: &SymbolQuery<'_>,
    ) -> Result<Option<FoundRelocation>> {
        if query.version() != SymbolVersion::Any {
            return Ok(None);
        }
        let strtab = self
            .dynamic
            .strtab
            .ok_or(Error::InvalidElf("missing DT_STRTAB"))?;
        let strsz = self
            .dynamic
            .strsz
            .ok_or(Error::InvalidElf("missing DT_STRSZ"))?;
        let symtab = self
            .dynamic
            .symtab
            .ok_or(Error::InvalidElf("missing DT_SYMTAB"))?;
        let syment = self
            .dynamic
            .syment
            .ok_or(Error::InvalidElf("missing DT_SYMENT"))?;
        if syment != self.header.class.sym_size() as u64 {
            return Err(Error::InvalidElf("unexpected DT_SYMENT"));
        }
        let symbol_count = self.dynamic_symbol_count(memory, symtab, syment)?;
        let strtab_address = absolute_address(strtab)?;
        let strtab_size = usize::try_from(strsz).map_err(|_| Error::ArithmeticOverflow)?;
        if strtab_size > MAX_TABLE_SIZE {
            return Err(Error::InvalidElf("dynamic string table is too large"));
        }
        if !range_in_ranges(strtab_address, strtab_size, &self.load_ranges) {
            return Err(Error::InvalidElf("DT_STRTAB exceeds PT_LOAD"));
        }
        let resolved = ResolvedSymbolQuery {
            output: 0,
            name: query.name().to_bytes(),
            version: query.version(),
            strtab,
            strsz,
            symtab,
            symbol_count,
            versions: None,
        };
        let queries = std::slice::from_ref(&resolved);
        let mut symbol_tables =
            SymbolTables::new(memory, queries, self.header.class, &self.load_ranges);
        let hash_filter = SymbolHashPrefilter::new(self, memory);
        let exact_index =
            self.single_exact_symbol_index(memory, queries, &symbol_tables, &hash_filter)?;
        symbol_tables.single_exact_index = exact_index;
        if exact_index.is_none() {
            return Ok(None);
        }
        let mut scan = RelocationScan::default();
        for table in self.relocation_tables()? {
            self.scan_relocation_table_with_tables(
                memory,
                queries,
                &symbol_tables,
                &hash_filter,
                table,
                std::slice::from_mut(&mut scan),
            )?;
        }
        let rejected = scan.rejected.into_values().next().is_some();
        let mut matches = scan.matches.into_values();
        let Some(relocation) = matches.next() else {
            return Ok(None);
        };
        if rejected || matches.next().is_some() {
            return Ok(None);
        }
        Ok(Some(relocation))
    }

    /// Raw single-symbol scan for the common Elf64 RELA + SysV hash case.
    ///
    /// Returns `None` for every non-fast input so the generic scanner remains
    /// the sole semantic authority for packed tables, versions, PAC, and IFUNC.
    ///
    pub(super) fn find_exact_relocation_raw(
        &self,
        memory: &Memory<'_>,
        query: &SymbolQuery<'_>,
    ) -> Result<Option<FoundRelocation>> {
        if self.header.class != ElfClass::Elf64
            || query.version() != SymbolVersion::Any
            || self.dynamic.aarch64_pac_plt
        {
            return Ok(None);
        }
        if self.dynamic.hash.is_none() {
            return Ok(None);
        }
        let Some(strtab) = self.dynamic.strtab else {
            return Ok(None);
        };
        let Some(strsz) = self.dynamic.strsz else {
            return Ok(None);
        };
        let Some(symtab) = self.dynamic.symtab else {
            return Ok(None);
        };
        let Some(syment) = self.dynamic.syment else {
            return Ok(None);
        };
        if syment != self.header.class.sym_size() as u64 {
            return Ok(None);
        }

        let symbol_count = self.dynamic_symbol_count(memory, symtab, syment)?;
        let strtab_address = absolute_address(strtab)?;
        let strtab_size = usize::try_from(strsz).map_err(|_| Error::ArithmeticOverflow)?;
        if strtab_size > MAX_TABLE_SIZE
            || !range_in_ranges(strtab_address, strtab_size, &self.load_ranges)
        {
            return Ok(None);
        }
        let resolved = ResolvedSymbolQuery {
            output: 0,
            name: query.name().to_bytes(),
            version: query.version(),
            strtab,
            strsz,
            symtab,
            symbol_count,
            versions: None,
        };
        let queries = std::slice::from_ref(&resolved);
        let symbol_tables =
            SymbolTables::new(memory, queries, self.header.class, &self.load_ranges);
        // The exact-index scan uses only GNU chains; DT_HASH was validated above.
        let hash_filter = SymbolHashPrefilter {
            sysv: None,
            gnu: self
                .dynamic
                .gnu_hash
                .and_then(|address| SymbolHashPrefilter::gnu(self, memory, address, syment)),
        };
        let Some(symbol_index) =
            self.single_exact_symbol_index(memory, queries, &symbol_tables, &hash_filter)?
        else {
            return Ok(None);
        };

        let symbol_address = absolute_address(symtab)?
            .checked_add(
                usize::try_from(symbol_index)
                    .map_err(|_| Error::InvalidElf("invalid symbol index"))?
                    * syment as usize,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let symbol = memory.read_array::<24>(symbol_address)?;
        let shndx = u16::from_le_bytes([symbol[6], symbol[7]]);
        let info = symbol[4];
        let value = u64::from_le_bytes([
            symbol[8], symbol[9], symbol[10], symbol[11], symbol[12], symbol[13], symbol[14],
            symbol[15],
        ]);
        if info & 0x0f == STT_GNU_IFUNC {
            return Ok(None);
        }
        let definition = match shndx {
            SHN_UNDEF => None,
            SHN_ABS => Some(usize::try_from(value).map_err(|_| Error::ArithmeticOverflow)?),
            _ => Some(runtime_address(self.id.load_bias, value)?),
        };

        let mut found = None;
        for table in self.relocation_tables()? {
            let RelocationTable::Plain {
                address,
                size,
                entry_size: 24,
                format: RelFormat::Rela,
                relative_prefix,
            } = table
            else {
                return Ok(None);
            };
            if size % 24 != 0 {
                return Ok(None);
            }
            let table_size = usize::try_from(size).map_err(|_| Error::ArithmeticOverflow)?;
            let relocation_count = table_size / 24;
            if table_size > MAX_TABLE_SIZE || relocation_count > MAX_RELOCATIONS {
                return Ok(None);
            }
            let table_address = absolute_address(address)?;
            if !range_in_ranges(table_address, table_size, &self.load_ranges) {
                return Err(Error::InvalidElf("relocation table exceeds PT_LOAD"));
            }
            let bytes =
                memory
                    .read_slice(table_address, table_size)
                    .ok_or(Error::UnmappedRead {
                        address: table_address,
                        length: table_size,
                    })?;
            for entry in bytes.as_chunks::<24>().0.iter().skip(relative_prefix) {
                let entry_symbol = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
                if entry_symbol != symbol_index {
                    continue;
                }
                let relocation_type =
                    u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
                let Some(kind) = arch::relocation_kind(self.header.machine, relocation_type)?
                else {
                    return Ok(None);
                };
                let relocation_offset = u64::from_le_bytes([
                    entry[0], entry[1], entry[2], entry[3], entry[4], entry[5], entry[6], entry[7],
                ]);
                let address = runtime_address(self.id.load_bias, relocation_offset)?;
                let pointer_size = self.header.class.pointer_size();
                if address % pointer_size != 0
                    || !range_in_ranges(address, pointer_size, &self.load_ranges)
                    || !memory.is_readable(address, pointer_size)
                {
                    return Err(Error::InvalidElf("invalid relocation slot"));
                }
                let addend = i64::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19], entry[20], entry[21], entry[22],
                    entry[23],
                ]);
                if self.header.machine == arch::EM_X86_64
                    && matches!(kind, RelocationKind::GlobalData | RelocationKind::JumpSlot)
                    && addend != 0
                {
                    return Ok(None);
                }
                if found.is_some() {
                    return Ok(None);
                }
                found = Some((address, kind, addend));
            }
        }
        let Some((address, kind, addend)) = found else {
            return Ok(None);
        };

        let jump_slot_state = if kind == RelocationKind::JumpSlot && cfg!(target_os = "linux") {
            let current = usize::try_from(memory.read_u64(address)?)
                .map_err(|_| Error::ArithmeticOverflow)?;
            if address_in_ranges(current, &self.load_ranges)
                && (shndx == SHN_UNDEF || definition != Some(current))
            {
                JumpSlotState::Lazy(current)
            } else {
                JumpSlotState::Resolved
            }
        } else {
            JumpSlotState::Resolved
        };
        Ok(Some(FoundRelocation {
            address,
            image: self.id,
            kind,
            addend,
            jump_slot_state,
            aarch64_pac_plt: false,
            function_symbol: info & 0x0f == 2,
            _validated_mapping: (),
        }))
    }

    fn single_exact_symbol_index(
        &self,
        memory: &Memory<'_>,
        queries: &[ResolvedSymbolQuery<'_>],
        tables: &SymbolTables<'_>,
        hash_filter: &SymbolHashPrefilter<'_>,
    ) -> Result<Option<u32>> {
        if queries.len() != 1 {
            return Ok(None);
        }
        let query = &queries[0];
        let Some(symbol_count) = query.symbol_count else {
            return Ok(None);
        };
        let mut found = None;
        if let Some(gnu) = &hash_filter.gnu {
            let hashes = tables.hashes[0];
            if gnu.chain.is_some() && gnu.symbol_offset != 0 {
                let bucket = (hashes.gnu % gnu.bucket_count) as usize;
                let mut candidate = gnu
                    .buckets
                    .as_chunks::<4>()
                    .0
                    .get(bucket)
                    .map(|word| u32::from_le_bytes(*word))
                    .filter(|first| *first != 0)
                    .unwrap_or(0);
                while candidate != 0 && candidate < gnu.symbol_count {
                    if let Some((range, _)) =
                        self.matching_query_range(memory, queries, candidate, tables)?
                        && range.len() == 1
                        && found.replace(candidate).is_some()
                    {
                        return Ok(None);
                    }
                    let chain_index = usize::try_from(
                        candidate
                            .checked_sub(gnu.symbol_offset)
                            .ok_or(Error::InvalidElf("invalid GNU hash symbol index"))?,
                    )
                    .map_err(|_| Error::ArithmeticOverflow)?;
                    let chain = table_u32(
                        gnu.chain
                            .ok_or(Error::InvalidElf("missing GNU hash chain"))?,
                        chain_index,
                    )
                    .ok_or(Error::InvalidElf("truncated GNU hash chain"))?;
                    if chain & 1 != 0 {
                        break;
                    }
                    candidate = candidate.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                }
                for symbol_index in 0..gnu.symbol_offset {
                    if let Some((range, _)) =
                        self.matching_query_range(memory, queries, symbol_index, tables)?
                        && range.len() == 1
                        && found.replace(symbol_index).is_some()
                    {
                        return Ok(None);
                    }
                }
                return Ok(found);
            }
        }
        // SysV chains can omit imports anywhere in dynsym; a chain hit does
        // not prove uniqueness without checking the remaining symbols.
        if let (Some((_, symbols)), Some((_, strings))) = (tables.symtab, tables.strtab) {
            // The complete table views already prove every entry readable.
            for (index, symbol) in symbols
                .chunks_exact(self.header.class.sym_size())
                .enumerate()
            {
                let name_offset =
                    u32::from_le_bytes([symbol[0], symbol[1], symbol[2], symbol[3]]) as usize;
                if name_offset >= strings.len() {
                    return Err(Error::InvalidElf("symbol name exceeds DT_STRSZ"));
                }
                let name = &strings[name_offset..];
                if name.get(query.name.len()) == Some(&0)
                    && name.starts_with(query.name)
                    && found
                        .replace(u32::try_from(index).map_err(|_| Error::ArithmeticOverflow)?)
                        .is_some()
                {
                    return Ok(None);
                }
            }
            return Ok(found);
        }
        for symbol_index in 0..symbol_count {
            if let Some((range, _)) =
                self.matching_query_range(memory, queries, symbol_index, tables)?
                && range.len() == 1
                && found.replace(symbol_index).is_some()
            {
                return Ok(None);
            }
        }
        Ok(found)
    }

    fn exact_symbol_match(
        &self,
        memory: &Memory<'_>,
        queries: &[ResolvedSymbolQuery<'_>],
        symbol_index: u32,
        tables: &SymbolTables<'_>,
    ) -> Result<SymbolMatch> {
        let Some(query) = queries.first() else {
            return Err(Error::InvalidElf("missing single relocation query"));
        };
        let (symbol_address, _, _) =
            self.symbol_name_location_with_tables(memory, query, symbol_index, tables)?;
        self.symbol_match_known_name(memory, query, symbol_index, symbol_address, tables)
    }

    fn scan_relocation_table_with_tables(
        &self,
        memory: &Memory<'_>,
        queries: &[ResolvedSymbolQuery<'_>],
        symbol_tables: &SymbolTables<'_>,
        hash_filter: &SymbolHashPrefilter<'_>,
        table: RelocationTable,
        scans: &mut [RelocationScan],
    ) -> Result<()> {
        let (address, size, entry_size, format, relative_prefix) = match table {
            RelocationTable::Plain {
                address,
                size,
                entry_size,
                format,
                relative_prefix,
            } => (address, size, entry_size, format, relative_prefix),
            RelocationTable::Packed {
                address,
                size,
                format,
            } => {
                return self.scan_packed_table_with_tables(
                    memory,
                    queries,
                    symbol_tables,
                    hash_filter,
                    RelocationTable::Packed {
                        address,
                        size,
                        format,
                    },
                    scans,
                );
            }
        };
        let expected = self.header.class.rel_size(format) as u64;
        if entry_size != expected || size % entry_size != 0 {
            return Err(Error::InvalidElf("invalid relocation entry size"));
        }
        let table_size = usize::try_from(size).map_err(|_| Error::ArithmeticOverflow)?;
        if table_size > MAX_TABLE_SIZE {
            return Err(Error::InvalidElf("relocation table is too large"));
        }
        let count = usize::try_from(size / entry_size).map_err(|_| Error::ArithmeticOverflow)?;
        if count > MAX_RELOCATIONS {
            return Err(Error::InvalidElf("too many relocations"));
        }
        let skip = if symbol_tables.single_exact_index.is_some() {
            relative_prefix
        } else {
            0
        };
        let address = absolute_address(address)?;
        if !range_in_ranges(address, table_size, &self.load_ranges) {
            return Err(Error::InvalidElf("relocation table exceeds PT_LOAD"));
        }
        let table_bytes = if table_size == 0 || !memory.is_readable(address, table_size) {
            None
        } else {
            // SAFETY: `is_readable` proves that this complete non-empty table
            // is inside one live readable mapping for `Memory`.
            Some(unsafe {
                std::slice::from_raw_parts(std::ptr::with_exposed_provenance(address), table_size)
            })
        };
        if self.header.class == ElfClass::Elf64
            && format == RelFormat::Rela
            && let Some(exact_index) = symbol_tables.single_exact_index
            && let Some(bytes) = table_bytes
        {
            let symbol_match =
                self.exact_symbol_match(memory, queries, exact_index, symbol_tables)?;
            let Some(scan) = scans.get_mut(queries[0].output) else {
                return Err(Error::InvalidElf("symbol result count mismatch"));
            };
            for entry in bytes.as_chunks::<24>().0.iter().skip(skip) {
                let symbol_index = u32::from_le_bytes(
                    entry[12..16]
                        .try_into()
                        .unwrap_or_else(|_| crate::sys::fail_stop()),
                );
                if symbol_index != exact_index {
                    continue;
                }
                let relocation_type = u32::from_le_bytes(
                    entry[8..12]
                        .try_into()
                        .unwrap_or_else(|_| crate::sys::fail_stop()),
                );
                let relocation_offset = u64::from_le_bytes(
                    entry[0..8]
                        .try_into()
                        .unwrap_or_else(|_| crate::sys::fail_stop()),
                );
                let addend = i64::from_le_bytes(
                    entry[16..24]
                        .try_into()
                        .unwrap_or_else(|_| crate::sys::fail_stop()),
                );
                let Some(kind) = arch::relocation_kind(self.header.machine, relocation_type)?
                else {
                    continue;
                };
                if symbol_index == 0 {
                    continue;
                }
                self.consider_relocation_decoded(
                    memory,
                    relocation_offset,
                    kind,
                    Some(addend),
                    scan,
                    symbol_match,
                )?;
            }
            return Ok(());
        }
        for index in skip..count {
            let offset = index
                .checked_mul(expected as usize)
                .ok_or(Error::ArithmeticOverflow)?;
            let entry = checked_add(address, offset)?;
            let bytes = table_bytes.map(|bytes| &bytes[offset..offset + expected as usize]);
            let (relocation_offset, info, addend) = match (self.header.class, bytes) {
                (ElfClass::Elf32, Some(bytes)) => (
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                    u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64,
                    match format {
                        RelFormat::Rel => None,
                        RelFormat::Rela => Some(i64::from(i32::from_le_bytes([
                            bytes[8], bytes[9], bytes[10], bytes[11],
                        ]))),
                    },
                ),
                (ElfClass::Elf64, Some(bytes)) => (
                    u64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]),
                    u64::from_le_bytes([
                        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                        bytes[15],
                    ]),
                    match format {
                        RelFormat::Rel => None,
                        RelFormat::Rela => Some(i64::from_le_bytes([
                            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21],
                            bytes[22], bytes[23],
                        ])),
                    },
                ),
                (ElfClass::Elf32, None) => (
                    memory.read_u32(entry)? as u64,
                    memory.read_u32(entry + 4)? as u64,
                    match format {
                        RelFormat::Rel => None,
                        RelFormat::Rela => Some(i64::from(memory.read_i32(entry + 8)?)),
                    },
                ),
                (ElfClass::Elf64, None) => (
                    memory.read_u64(entry)?,
                    memory.read_u64(entry + 8)?,
                    match format {
                        RelFormat::Rel => None,
                        RelFormat::Rela => Some(memory.read_i64(entry + 16)?),
                    },
                ),
            };
            self.consider_relocations_with_tables(
                memory,
                queries,
                symbol_tables,
                hash_filter,
                (relocation_offset, info, addend),
                scans,
            )?;
        }
        Ok(())
    }

    fn scan_packed_table_with_tables(
        &self,
        memory: &Memory<'_>,
        queries: &[ResolvedSymbolQuery<'_>],
        symbol_tables: &SymbolTables<'_>,
        hash_filter: &SymbolHashPrefilter<'_>,
        table: RelocationTable,
        scans: &mut [RelocationScan],
    ) -> Result<()> {
        let RelocationTable::Packed {
            address,
            size,
            format,
        } = table
        else {
            return Err(Error::InvalidElf("plain table passed to packed decoder"));
        };
        let address = absolute_address(address)?;
        let size = usize::try_from(size).map_err(|_| Error::ArithmeticOverflow)?;
        if size > MAX_TABLE_SIZE {
            return Err(Error::InvalidElf("packed relocation table is too large"));
        }
        if !range_in_ranges(address, size, &self.load_ranges) {
            return Err(Error::InvalidElf("packed relocations exceed PT_LOAD"));
        }
        let mut reader = PackedReader::new(memory, address, size)?;
        let relocation_count = nonnegative_usize(reader.read_sleb128()?)?;
        if relocation_count > MAX_RELOCATIONS {
            return Err(Error::InvalidElf("too many packed relocations"));
        }
        let mut relocation_offset = reader.read_sleb128()?;
        if relocation_offset < 0 {
            return Err(Error::InvalidElf("negative packed relocation offset"));
        }
        let mut relocation_addend = 0_i64;
        let mut emitted = 0_usize;

        while emitted < relocation_count {
            let group_size = nonnegative_usize(reader.read_sleb128()?)?;
            if group_size == 0 || group_size > relocation_count - emitted {
                return Err(Error::InvalidElf("invalid packed relocation group size"));
            }
            let flags = reader.read_sleb128()?;
            if flags < 0 || flags & !KNOWN_GROUP_FLAGS != 0 {
                return Err(Error::InvalidElf("invalid packed relocation group flags"));
            }
            if format == RelFormat::Rel && flags & RELOCATION_GROUP_HAS_ADDEND != 0 {
                return Err(Error::InvalidElf("REL packed group contains addends"));
            }

            let grouped_offset = if flags & RELOCATION_GROUPED_BY_OFFSET_DELTA != 0 {
                Some(reader.read_sleb128()?)
            } else {
                None
            };
            let grouped_info = if flags & RELOCATION_GROUPED_BY_INFO != 0 {
                Some(nonnegative_u64(reader.read_sleb128()?)?)
            } else {
                None
            };
            let grouped_addend = if flags & RELOCATION_GROUP_HAS_ADDEND != 0
                && flags & RELOCATION_GROUPED_BY_ADDEND != 0
            {
                Some(reader.read_sleb128()?)
            } else {
                None
            };
            if format == RelFormat::Rela && flags & RELOCATION_GROUP_HAS_ADDEND == 0 {
                relocation_addend = 0;
            }
            if let Some(delta) = grouped_addend {
                relocation_addend = relocation_addend
                    .checked_add(delta)
                    .ok_or(Error::ArithmeticOverflow)?;
            }

            for _ in 0..group_size {
                let delta = match grouped_offset {
                    Some(delta) => delta,
                    None => reader.read_sleb128()?,
                };
                relocation_offset = relocation_offset
                    .checked_add(delta)
                    .ok_or(Error::ArithmeticOverflow)?;
                if relocation_offset < 0 {
                    return Err(Error::InvalidElf("negative packed relocation offset"));
                }
                let info = match grouped_info {
                    Some(info) => info,
                    None => nonnegative_u64(reader.read_sleb128()?)?,
                };

                if format == RelFormat::Rela
                    && flags & RELOCATION_GROUP_HAS_ADDEND != 0
                    && grouped_addend.is_none()
                {
                    let delta = reader.read_sleb128()?;
                    relocation_addend = relocation_addend
                        .checked_add(delta)
                        .ok_or(Error::ArithmeticOverflow)?;
                }

                self.consider_relocations_with_tables(
                    memory,
                    queries,
                    symbol_tables,
                    hash_filter,
                    (
                        relocation_offset as u64,
                        info,
                        (format == RelFormat::Rela).then_some(relocation_addend),
                    ),
                    scans,
                )?;
                emitted += 1;
            }
        }

        if !reader.trailing_is_padding()? {
            return Err(Error::InvalidElf("trailing packed relocation data"));
        }
        Ok(())
    }

    fn consider_relocations_with_tables(
        &self,
        memory: &Memory<'_>,
        queries: &[ResolvedSymbolQuery<'_>],
        symbol_tables: &SymbolTables<'_>,
        hash_filter: &SymbolHashPrefilter<'_>,
        relocation: (u64, u64, Option<i64>),
        scans: &mut [RelocationScan],
    ) -> Result<()> {
        let (relocation_offset, info, addend) = relocation;
        let (symbol_index, relocation_type) = self.header.class.decode_info(info)?;
        let Some(kind) = arch::relocation_kind(self.header.machine, relocation_type)? else {
            return Ok(());
        };
        if symbol_index == 0 {
            return Ok(());
        }
        if let Some(exact_index) = symbol_tables.single_exact_index
            && symbol_index != exact_index
        {
            return Ok(());
        }
        if !queries
            .iter()
            .zip(symbol_tables.hashes.iter().copied())
            .any(|(_, hashes)| hash_filter.may_match(symbol_index, hashes))
        {
            return Ok(());
        }
        let Some((range, symbol_address)) =
            self.matching_query_range(memory, queries, symbol_index, symbol_tables)?
        else {
            return Ok(());
        };
        for query in &queries[range] {
            let scan = scans
                .get_mut(query.output)
                .ok_or(Error::InvalidElf("symbol result count mismatch"))?;
            let symbol_match = self.symbol_match_known_name(
                memory,
                query,
                symbol_index,
                symbol_address,
                symbol_tables,
            )?;
            self.consider_relocation_decoded(
                memory,
                relocation_offset,
                kind,
                addend,
                scan,
                symbol_match,
            )?;
        }
        Ok(())
    }

    fn consider_relocation_decoded(
        &self,
        memory: &Memory<'_>,
        relocation_offset: u64,
        kind: RelocationKind,
        addend: Option<i64>,
        scan: &mut RelocationScan,
        symbol_match: SymbolMatch,
    ) -> Result<()> {
        let SymbolMatch::Match {
            undefined,
            definition,
            ifunc,
            function,
        } = symbol_match
        else {
            return Ok(());
        };
        let address = runtime_address(self.id.load_bias, relocation_offset)?;
        let pointer_size = self.header.class.pointer_size();
        if address % pointer_size != 0
            || !range_in_ranges(address, pointer_size, &self.load_ranges)
            || !memory.is_readable(address, pointer_size)
        {
            return Err(Error::InvalidElf("unaligned or unmapped relocation slot"));
        }
        let addend = match (kind, addend) {
            (RelocationKind::Absolute, None) => {
                scan.unsupported_implicit_addend = true;
                record_rejected_relocation(
                    scan,
                    RejectedRelocation {
                        address,
                        image: self.id,
                        kind,
                        addend: None,
                        reason: RelocationRejection::ImplicitAddend,
                    },
                )?;
                return Ok(());
            }
            (RelocationKind::GlobalData | RelocationKind::JumpSlot, Some(addend))
                if self.header.machine == arch::EM_X86_64 && addend != 0 =>
            {
                // The x86-64 ABI stores `S + A` in these slots, but a PltHookRequest
                // replacement is an exact entry pointer. A non-zero addend
                // cannot be applied without guessing whether the caller wants
                // `replacement` or `replacement + A`, so reject the slot.
                record_rejected_relocation(
                    scan,
                    RejectedRelocation {
                        address,
                        image: self.id,
                        kind,
                        addend: Some(addend),
                        reason: RelocationRejection::UnsupportedAddend,
                    },
                )?;
                return Ok(());
            }
            (_, Some(addend)) => addend,
            (_, None) => 0,
        };
        let aarch64_pac_plt = self.header.machine == arch::EM_AARCH64
            && self.dynamic.aarch64_pac_plt
            && kind == RelocationKind::JumpSlot;
        let current_jump_slot =
            if kind == RelocationKind::JumpSlot && (aarch64_pac_plt || cfg!(target_os = "linux")) {
                let stored = match self.header.class {
                    ElfClass::Elf32 => memory.read_u32(address)? as u64,
                    ElfClass::Elf64 => memory.read_u64(address)?,
                };
                let stored = usize::try_from(stored).map_err(|_| Error::ArithmeticOverflow)?;
                if aarch64_pac_plt {
                    match crate::sys::verify_pac_plt(stored, address) {
                        Some(current) => Some(current),
                        None => {
                            record_rejected_relocation(
                                scan,
                                RejectedRelocation {
                                    address,
                                    image: self.id,
                                    kind,
                                    addend: Some(addend),
                                    reason: RelocationRejection::PacPltVerificationFailed,
                                },
                            )?;
                            return Ok(());
                        }
                    }
                } else {
                    Some(stored)
                }
            } else {
                None
            };
        let jump_slot_state = if kind == RelocationKind::JumpSlot && cfg!(target_os = "linux") {
            let current =
                current_jump_slot.ok_or(Error::InvalidElf("missing jump-slot state value"))?;
            match current {
                current
                    if !undefined
                        && ifunc
                        && (definition == Some(current)
                            || address_in_ranges(current, &self.load_ranges)) =>
                {
                    JumpSlotState::AmbiguousIfunc
                }
                current
                    if address_in_ranges(current, &self.load_ranges)
                        && (undefined || definition != Some(current)) =>
                {
                    JumpSlotState::Lazy(current)
                }
                _ => JumpSlotState::Resolved,
            }
        } else {
            JumpSlotState::Resolved
        };
        let relocation = FoundRelocation {
            address,
            image: self.id,
            kind,
            addend,
            jump_slot_state,
            aarch64_pac_plt,
            function_symbol: function,
            _validated_mapping: (),
        };
        if scan.rejected.contains_key(&address) {
            return Err(Error::InvalidElf("conflicting relocations for one slot"));
        }
        scan.matches.insert(address, relocation)
    }

    fn relocation_tables(&self) -> Result<Vec<RelocationTable>> {
        let mut tables = Vec::new();
        push_plain_table(
            &mut tables,
            self.dynamic.rel,
            self.dynamic.relsz,
            self.dynamic.relent,
            self.header.class.rel_size(RelFormat::Rel) as u64,
            RelFormat::Rel,
            self.dynamic.relcount,
        )?;
        push_plain_table(
            &mut tables,
            self.dynamic.rela,
            self.dynamic.relasz,
            self.dynamic.relaent,
            self.header.class.rel_size(RelFormat::Rela) as u64,
            RelFormat::Rela,
            self.dynamic.relacount,
        )?;

        match (
            self.dynamic.jmprel,
            self.dynamic.pltrelsz,
            self.dynamic.pltrel,
        ) {
            (None, None, None) => {}
            (Some(address), Some(size), Some(value)) => {
                let format = match value {
                    value if value == DT_REL as u64 => RelFormat::Rel,
                    value if value == DT_RELA as u64 => RelFormat::Rela,
                    _ => {
                        return Err(Error::InvalidElf(
                            "incomplete or invalid PLT relocation tags",
                        ));
                    }
                };
                tables.push(RelocationTable::Plain {
                    address,
                    size,
                    entry_size: self.header.class.rel_size(format) as u64,
                    format,
                    relative_prefix: 0,
                })
            }
            _ => {
                return Err(Error::InvalidElf(
                    "incomplete or invalid PLT relocation tags",
                ));
            }
        }

        push_packed_table(
            &mut tables,
            self.dynamic.android_rel,
            self.dynamic.android_relsz,
            RelFormat::Rel,
        )?;
        push_packed_table(
            &mut tables,
            self.dynamic.android_rela,
            self.dynamic.android_relasz,
            RelFormat::Rela,
        )?;
        Ok(tables)
    }
}

pub(super) enum RelocationTable {
    Plain {
        address: u64,
        size: u64,
        entry_size: u64,
        format: RelFormat,
        relative_prefix: usize,
    },
    Packed {
        address: u64,
        size: u64,
        format: RelFormat,
    },
}

fn record_rejected_relocation(
    scan: &mut RelocationScan,
    relocation: RejectedRelocation,
) -> Result<()> {
    if scan.matches.contains_key(&relocation.address) {
        return Err(Error::InvalidElf("conflicting relocations for one slot"));
    }
    scan.rejected.insert(relocation.address, relocation)
}

fn push_plain_table(
    tables: &mut Vec<RelocationTable>,
    address: Option<u64>,
    size: Option<u64>,
    entry_size: Option<u64>,
    default_entry_size: u64,
    format: RelFormat,
    relative_count: Option<u64>,
) -> Result<()> {
    match (address, size) {
        (None, None) => Ok(()),
        (Some(address), Some(size)) => {
            let entry_size = entry_size.unwrap_or(default_entry_size);
            let count = size
                .checked_div(entry_size)
                .ok_or(Error::InvalidElf("invalid relocation entry size"))?;
            let relative_count = relative_count.unwrap_or(0);
            if relative_count > count {
                return Err(Error::InvalidElf(
                    "relative relocation count exceeds relocation table",
                ));
            }
            let relative_prefix = usize::try_from(relative_count)
                .map_err(|_| Error::InvalidElf("relative relocation count is too large"))?;
            tables.push(RelocationTable::Plain {
                address,
                size,
                entry_size,
                format,
                relative_prefix,
            });
            Ok(())
        }
        _ => Err(Error::InvalidElf("incomplete relocation table tags")),
    }
}

fn push_packed_table(
    tables: &mut Vec<RelocationTable>,
    address: Option<u64>,
    size: Option<u64>,
    format: RelFormat,
) -> Result<()> {
    match (address, size) {
        (None, None) => Ok(()),
        (Some(address), Some(size)) => {
            tables.push(RelocationTable::Packed {
                address,
                size,
                format,
            });
            Ok(())
        }
        _ => Err(Error::InvalidElf("incomplete packed relocation tags")),
    }
}

pub(super) struct PackedReader<'a, 'm> {
    memory: &'a Memory<'m>,
    bytes: Option<&'a [u8]>,
    address: usize,
    size: usize,
    position: usize,
}

impl<'a, 'm> PackedReader<'a, 'm> {
    pub(super) fn new(memory: &'a Memory<'m>, address: usize, size: usize) -> Result<Self> {
        if size < 4 {
            return Err(Error::InvalidElf("truncated packed relocation header"));
        }
        if &memory.read_array::<4>(address)? != b"APS2" {
            return Err(Error::InvalidElf("bad packed relocation magic"));
        }
        let bytes = memory.is_readable(address, size).then(|| {
            // SAFETY: the complete table is inside one live readable mapping
            // for the Memory lifetime.
            unsafe { std::slice::from_raw_parts(std::ptr::with_exposed_provenance(address), size) }
        });
        Ok(Self {
            memory,
            bytes,
            address,
            size,
            position: 4,
        })
    }

    pub(super) fn read_sleb128(&mut self) -> Result<i64> {
        let mut value = 0_i128;
        let mut shift = 0_u32;
        for _ in 0..10 {
            if self.position >= self.size {
                return Err(Error::InvalidElf("truncated SLEB128"));
            }
            let byte = match self.bytes {
                Some(bytes) => bytes[self.position],
                None => self
                    .memory
                    .read_u8(checked_add(self.address, self.position)?)?,
            };
            self.position += 1;
            value |= i128::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if byte & 0x40 != 0 {
                    value |= (-1_i128) << shift;
                }
                return i64::try_from(value).map_err(|_| Error::InvalidElf("SLEB128 overflow"));
            }
        }
        Err(Error::InvalidElf("SLEB128 overflow"))
    }

    /// Reports whether nothing but zero padding follows the encoded stream.
    ///
    /// `lld` appends zero bytes so a packed relocation section never shrinks
    /// between layout iterations, and bionic's own consumer stops at the
    /// relocation count without reading them. A non-zero remainder still means
    /// the table disagrees with its own count and is rejected.
    fn trailing_is_padding(&self) -> Result<bool> {
        for position in self.position..self.size {
            let byte = match self.bytes {
                Some(bytes) => bytes[position],
                None => self.memory.read_u8(checked_add(self.address, position)?)?,
            };
            if byte != 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn nonnegative_usize(value: i64) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::InvalidElf("negative or oversized integer"))
}

fn nonnegative_u64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::InvalidElf("negative integer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Image {
        pub(crate) fn scan_relocation_table(
            &self,
            memory: &Memory<'_>,
            queries: &[ResolvedSymbolQuery<'_>],
            table: RelocationTable,
            scans: &mut [RelocationScan],
        ) -> Result<()> {
            let symbol_tables =
                SymbolTables::new(memory, queries, self.header.class, &self.load_ranges);
            let hash_filter = SymbolHashPrefilter::new(self, memory);
            self.scan_relocation_table_with_tables(
                memory,
                queries,
                &symbol_tables,
                &hash_filter,
                table,
                scans,
            )
        }

        pub(crate) fn scan_packed_table(
            &self,
            memory: &Memory<'_>,
            queries: &[ResolvedSymbolQuery<'_>],
            address: u64,
            size: u64,
            format: RelFormat,
            scans: &mut [RelocationScan],
        ) -> Result<()> {
            let symbol_tables =
                SymbolTables::new(memory, queries, self.header.class, &self.load_ranges);
            let hash_filter = SymbolHashPrefilter::new(self, memory);
            self.scan_packed_table_with_tables(
                memory,
                queries,
                &symbol_tables,
                &hash_filter,
                RelocationTable::Packed {
                    address,
                    size,
                    format,
                },
                scans,
            )
        }

        pub(crate) fn consider_relocations(
            &self,
            memory: &Memory<'_>,
            queries: &[ResolvedSymbolQuery<'_>],
            relocation_offset: u64,
            info: u64,
            addend: Option<i64>,
            scans: &mut [RelocationScan],
        ) -> Result<()> {
            let symbol_tables =
                SymbolTables::new(memory, queries, self.header.class, &self.load_ranges);
            let hash_filter = SymbolHashPrefilter::new(self, memory);
            self.consider_relocations_with_tables(
                memory,
                queries,
                &symbol_tables,
                &hash_filter,
                (relocation_offset, info, addend),
                scans,
            )
        }

        pub(crate) fn consider_relocation(
            &self,
            memory: &Memory<'_>,
            query: &ResolvedSymbolQuery<'_>,
            relocation_offset: u64,
            info: u64,
            addend: Option<i64>,
            scan: &mut RelocationScan,
        ) -> Result<()> {
            let (symbol_index, relocation_type) = self.header.class.decode_info(info)?;
            let Some(kind) = arch::relocation_kind(self.header.machine, relocation_type)? else {
                return Ok(());
            };
            if symbol_index == 0 {
                return Ok(());
            }
            let symbol_tables = SymbolTables::new(
                memory,
                std::slice::from_ref(query),
                self.header.class,
                &self.load_ranges,
            );
            let (symbol_address, name_address, available) =
                self.symbol_name_location(memory, query, symbol_index)?;
            if !memory.matches_c_string(name_address, available, query.name)? {
                return Ok(());
            }
            let symbol_match = self.symbol_match_known_name(
                memory,
                query,
                symbol_index,
                symbol_address,
                &symbol_tables,
            )?;
            self.consider_relocation_decoded(
                memory,
                relocation_offset,
                kind,
                addend,
                scan,
                symbol_match,
            )
        }
    }
}
