use super::*;

impl Image {
    pub(super) fn symbol_name_location_with_tables(
        &self,
        memory: &Memory<'_>,
        query: &ResolvedSymbolQuery<'_>,
        symbol_index: u32,
        tables: &SymbolTables<'_>,
    ) -> Result<(usize, usize, usize)> {
        if query
            .symbol_count
            .is_some_and(|count| symbol_index >= count)
        {
            return Err(Error::InvalidElf(
                "relocation symbol index exceeds dynamic symbol table",
            ));
        }
        let syment = self.header.class.sym_size() as u64;
        let symbol_offset = u64::from(symbol_index)
            .checked_mul(syment)
            .ok_or(Error::ArithmeticOverflow)?;
        if symbol_offset
            .checked_add(syment)
            .is_none_or(|end| end > MAX_TABLE_SIZE as u64)
        {
            return Err(Error::InvalidElf("dynamic symbol table is too large"));
        }
        let symbol_address = checked_add_u64(absolute_address(query.symtab)?, symbol_offset)?;
        let symbol = tables.symbol(symbol_address, syment as usize);
        if symbol.is_none()
            && (!range_in_ranges(symbol_address, syment as usize, &self.load_ranges)
                || !memory.is_fully_readable(symbol_address, syment as usize))
        {
            return Err(Error::InvalidElf("symbol entry exceeds PT_LOAD"));
        }
        let name_offset = match symbol {
            Some(symbol) => u32::from_le_bytes([symbol[0], symbol[1], symbol[2], symbol[3]]) as u64,
            None => memory.read_u32(symbol_address)? as u64,
        };
        if name_offset >= query.strsz {
            return Err(Error::InvalidElf("symbol name exceeds DT_STRSZ"));
        }
        let name_address = checked_add_u64(absolute_address(query.strtab)?, name_offset)?;
        let available =
            usize::try_from(query.strsz - name_offset).map_err(|_| Error::ArithmeticOverflow)?;
        Ok((symbol_address, name_address, available))
    }

    pub(super) fn dynamic_symbol_count(
        &self,
        memory: &Memory<'_>,
        symtab: u64,
        syment: u64,
    ) -> Result<Option<u32>> {
        if syment == 0 {
            return Err(Error::InvalidElf("unexpected DT_SYMENT"));
        }
        // Only exact sizes permit a whole-table scan; padding before DT_STRTAB
        // and an empty GNU hash do not describe the symbol table's extent.
        let mut count = None;
        let mut tagged_error = None;
        if let Some(hash) = self.dynamic.hash {
            count = Some(self.sysv_symbol_count(memory, hash)?);
        }
        if let Some(hash) = self.dynamic.gnu_hash
            && let Some(n) = self.gnu_symbol_count(memory, hash, syment)?
        {
            if count.is_some_and(|count| count != n) {
                return Err(Error::InvalidElf("inconsistent dynamic symbol table sizes"));
            }
            count = Some(n);
        }
        if let Some(size) = self.dynamic.symtabsz {
            if size == 0 || !size.is_multiple_of(syment) {
                tagged_error = Some(Error::InvalidElf("invalid DT_SYMTABSZ"));
            } else {
                match u32::try_from(size / syment) {
                    Ok(n) => {
                        if count.is_some_and(|count| count != n) {
                            return Err(Error::InvalidElf(
                                "inconsistent dynamic symbol table sizes",
                            ));
                        }
                        count = Some(n);
                    }
                    Err(_) => {
                        tagged_error = Some(Error::InvalidElf("dynamic symbol table is too large"));
                    }
                }
            }
        }
        if count.is_none()
            && let Some(error) = tagged_error
        {
            return Err(error);
        }
        if count == Some(0) {
            return Err(Error::InvalidElf("empty dynamic symbol table"));
        }
        // Unknown extents use relocation-driven reads, starting with the
        // mandatory null entry; each referenced entry is validated separately.
        let table_size = u64::from(count.unwrap_or(1))
            .checked_mul(syment)
            .and_then(|size| usize::try_from(size).ok())
            .filter(|size| *size <= MAX_TABLE_SIZE)
            .ok_or(Error::InvalidElf("dynamic symbol table is too large"))?;
        let address = absolute_address(symtab)?;
        if !range_in_ranges(address, table_size, &self.load_ranges)
            || !memory.is_fully_readable(address, table_size)
        {
            return Err(Error::InvalidElf("DT_SYMTAB exceeds readable PT_LOAD"));
        }
        Ok(count)
    }

    fn sysv_symbol_count(&self, memory: &Memory<'_>, hash: u64) -> Result<u32> {
        const HEADER_SIZE: usize = 8;
        let invalid = || Error::InvalidElf("invalid DT_HASH");
        let address = usize::try_from(hash).map_err(|_| invalid())?;
        if !range_in_ranges(address, HEADER_SIZE, &self.load_ranges)
            || !memory.is_fully_readable(address, HEADER_SIZE)
        {
            return Err(invalid());
        }
        let bucket_count = memory.read_u32(address)?;
        let symbol_count = memory.read_u32(checked_add(address, 4)?)?;
        if bucket_count == 0 {
            return Err(invalid());
        }
        let table_size = u64::from(bucket_count)
            .checked_add(u64::from(symbol_count))
            .and_then(|words| words.checked_add(2))
            .and_then(|words| words.checked_mul(4))
            .and_then(|size| usize::try_from(size).ok())
            .filter(|size| *size <= MAX_TABLE_SIZE)
            .ok_or_else(invalid)?;
        if !range_in_ranges(address, table_size, &self.load_ranges)
            || !memory.is_fully_readable(address, table_size)
        {
            return Err(invalid());
        }
        Ok(symbol_count)
    }

    pub(super) fn gnu_symbol_count(
        &self,
        memory: &Memory<'_>,
        hash: u64,
        syment: u64,
    ) -> Result<Option<u32>> {
        const HEADER_SIZE: usize = 16;
        let invalid = || Error::InvalidElf("invalid DT_GNU_HASH");
        let address = usize::try_from(hash).map_err(|_| invalid())?;
        if !range_in_ranges(address, HEADER_SIZE, &self.load_ranges)
            || !memory.is_fully_readable(address, HEADER_SIZE)
        {
            return Err(invalid());
        }
        let bucket_count = memory.read_u32(address)?;
        let symbol_offset = memory.read_u32(checked_add(address, 4)?)?;
        let bloom_count = memory.read_u32(checked_add(address, 8)?)?;
        if bucket_count == 0 || bloom_count == 0 {
            return Err(invalid());
        }
        let bloom_size = u64::from(bloom_count)
            .checked_mul(self.header.class.pointer_size() as u64)
            .ok_or_else(invalid)?;
        let buckets_offset = u64::try_from(HEADER_SIZE)
            .ok()
            .and_then(|header| header.checked_add(bloom_size))
            .ok_or_else(invalid)?;
        let prefix_size = u64::from(bucket_count)
            .checked_mul(4)
            .and_then(|buckets| buckets_offset.checked_add(buckets))
            .and_then(|size| usize::try_from(size).ok())
            .filter(|size| *size <= MAX_TABLE_SIZE)
            .ok_or_else(invalid)?;
        if !range_in_ranges(address, prefix_size, &self.load_ranges)
            || !memory.is_fully_readable(address, prefix_size)
        {
            return Err(invalid());
        }
        let bucket_address = checked_add(
            address,
            usize::try_from(buckets_offset).map_err(|_| invalid())?,
        )?;
        let bucket_bytes = memory
            .read_slice(
                bucket_address,
                usize::try_from(u64::from(bucket_count).checked_mul(4).ok_or_else(invalid)?)
                    .map_err(|_| invalid())?,
            )
            .ok_or_else(invalid)?;
        let mut maximum_bucket = 0;
        for bucket in bucket_bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
        {
            if bucket != 0 && bucket < symbol_offset {
                return Err(invalid());
            }
            maximum_bucket = maximum_bucket.max(bucket);
        }
        let maximum_symbols = (MAX_TABLE_SIZE as u64) / syment;
        if u64::from(symbol_offset) > maximum_symbols
            || u64::from(maximum_bucket) + 1 > maximum_symbols
        {
            return Err(invalid());
        }
        if maximum_bucket == 0 {
            return Ok(None);
        }
        let chain_base = checked_add(address, prefix_size)?;
        let mut chain_index = u64::from(maximum_bucket - symbol_offset);
        let mut symbol_index = maximum_bucket;
        loop {
            let chain_size = chain_index
                .checked_add(1)
                .and_then(|words| words.checked_mul(4))
                .and_then(|size| usize::try_from(size).ok())
                .filter(|size| {
                    prefix_size
                        .checked_add(*size)
                        .is_some_and(|end| end <= MAX_TABLE_SIZE)
                })
                .ok_or_else(invalid)?;
            if !range_in_ranges(chain_base, chain_size, &self.load_ranges)
                || !memory.is_fully_readable(chain_base, chain_size)
            {
                return Err(invalid());
            }
            let chain = memory.read_u32(checked_add(
                chain_base,
                usize::try_from(chain_index.checked_mul(4).ok_or_else(invalid)?)
                    .map_err(|_| invalid())?,
            )?)?;
            let count = u64::from(symbol_index) + 1;
            if count > maximum_symbols {
                return Err(invalid());
            }
            if chain & 1 != 0 {
                return u32::try_from(count).map(Some).map_err(|_| invalid());
            }
            chain_index = chain_index.checked_add(1).ok_or_else(invalid)?;
            symbol_index = symbol_index.checked_add(1).ok_or_else(invalid)?;
        }
    }

    pub(super) fn matching_query_range(
        &self,
        memory: &Memory<'_>,
        queries: &[ResolvedSymbolQuery<'_>],
        symbol_index: u32,
        tables: &SymbolTables<'_>,
    ) -> Result<Option<(std::ops::Range<usize>, usize)>> {
        let Some(query) = queries.first() else {
            return Ok(None);
        };
        let (symbol_address, name_address, available) =
            self.symbol_name_location_with_tables(memory, query, symbol_index, tables)?;
        if queries.len() == 1 {
            let matches = match tables
                .strtab
                .and_then(|_| tables.matches_c_string(name_address, available, query.name))
            {
                Some(matches) => matches,
                None => {
                    memory.compare_c_string(name_address, available, query.name)? == Ordering::Equal
                }
            };
            return Ok(matches.then_some((0..1, symbol_address)));
        }
        let mut low = 0;
        let mut high = queries.len();
        while low < high {
            let middle = low + (high - low) / 2;
            let ordering =
                match tables.compare_c_string(name_address, available, queries[middle].name) {
                    Some(ordering) => ordering,
                    None => {
                        memory.compare_c_string(name_address, available, queries[middle].name)?
                    }
                };
            match ordering {
                Ordering::Less => high = middle,
                Ordering::Greater => low = middle + 1,
                Ordering::Equal => {
                    let name = queries[middle].name;
                    let start = queries.partition_point(|query| query.name < name);
                    let end = queries.partition_point(|query| query.name <= name);
                    return Ok(Some((start..end, symbol_address)));
                }
            }
        }
        Ok(None)
    }

    pub(super) fn symbol_match_known_name(
        &self,
        memory: &Memory<'_>,
        query: &ResolvedSymbolQuery<'_>,
        symbol_index: u32,
        symbol_address: usize,
        tables: &SymbolTables<'_>,
    ) -> Result<SymbolMatch> {
        let symbol = tables.symbol(symbol_address, self.header.class.sym_size());
        let shndx_offset = self.header.class.sym_shndx_offset();
        let shndx = match symbol {
            Some(symbol) => u16::from_le_bytes([symbol[shndx_offset], symbol[shndx_offset + 1]]),
            None => memory.read_u16(checked_add(symbol_address, shndx_offset)?)?,
        };
        if !self.symbol_version_matches(memory, query, symbol_index, shndx, tables)? {
            return Ok(SymbolMatch::Mismatch);
        }
        let info_offset = self.header.class.sym_info_offset();
        let info = match symbol {
            Some(symbol) => symbol[info_offset],
            None => memory.read_u8(checked_add(symbol_address, info_offset)?)?,
        };
        let value = match (self.header.class, symbol) {
            (ElfClass::Elf32, Some(symbol)) => u64::from(u32::from_le_bytes([
                symbol[4], symbol[5], symbol[6], symbol[7],
            ])),
            (ElfClass::Elf64, Some(symbol)) => u64::from_le_bytes([
                symbol[8], symbol[9], symbol[10], symbol[11], symbol[12], symbol[13], symbol[14],
                symbol[15],
            ]),
            (ElfClass::Elf32, None) => u64::from(memory.read_u32(checked_add(symbol_address, 4)?)?),
            (ElfClass::Elf64, None) => memory.read_u64(checked_add(symbol_address, 8)?)?,
        };
        let definition = match shndx {
            SHN_UNDEF => None,
            SHN_ABS => Some(absolute_address(value)?),
            _ => Some(runtime_address(self.id.load_bias, value)?),
        };
        Ok(SymbolMatch::Match {
            undefined: shndx == SHN_UNDEF,
            definition,
            ifunc: info & 0x0f == STT_GNU_IFUNC,
            function: matches!(info & 0x0f, 2 | STT_GNU_IFUNC),
        })
    }

    pub(super) fn parse_version_metadata(
        &self,
        memory: &Memory<'_>,
        strtab: u64,
        strsz: u64,
        needs_exact: bool,
    ) -> Result<VersionMetadata> {
        if self.dynamic.duplicate_versym || (needs_exact && self.dynamic.duplicate_version_tag) {
            return Err(Error::InvalidElf("duplicate GNU version dynamic tag"));
        }

        let Some(raw_versym) = self.dynamic.versym else {
            if needs_exact
                && (self.dynamic.verdef.is_some()
                    || self.dynamic.verdefnum.is_some()
                    || self.dynamic.verneed.is_some()
                    || self.dynamic.verneednum.is_some())
            {
                return Err(Error::InvalidElf("GNU version tables without DT_VERSYM"));
            }
            return Ok(VersionMetadata::default());
        };
        let versym = absolute_address(resolve_dynamic_pointer(
            memory,
            self.id.load_bias,
            &self.load_ranges,
            raw_versym,
        )?)?;
        if !range_in_ranges(versym, 2, &self.load_ranges) {
            return Err(Error::InvalidElf("DT_VERSYM exceeds PT_LOAD"));
        }

        let mut metadata = VersionMetadata {
            versym: Some(versym),
            ..VersionMetadata::default()
        };
        if !needs_exact {
            return Ok(metadata);
        }
        let mut validated_strings = BTreeMap::<u64, u64>::new();

        match (self.dynamic.verdef, self.dynamic.verdefnum) {
            (None, None) => {}
            (Some(raw), Some(count)) => {
                let count = checked_version_count(count)?;
                let address = absolute_address(resolve_dynamic_pointer(
                    memory,
                    self.id.load_bias,
                    &self.load_ranges,
                    raw,
                )?)?;
                metadata.definitions = self.parse_verdef(
                    memory,
                    address,
                    count,
                    strtab,
                    strsz,
                    &mut validated_strings,
                )?;
            }
            _ => return Err(Error::InvalidElf("incomplete VERDEF dynamic tags")),
        }
        match (self.dynamic.verneed, self.dynamic.verneednum) {
            (None, None) => {}
            (Some(raw), Some(count)) => {
                let count = checked_version_count(count)?;
                let address = absolute_address(resolve_dynamic_pointer(
                    memory,
                    self.id.load_bias,
                    &self.load_ranges,
                    raw,
                )?)?;
                metadata.requirements = self.parse_verneed(
                    memory,
                    address,
                    count,
                    strtab,
                    strsz,
                    &mut validated_strings,
                )?;
            }
            _ => return Err(Error::InvalidElf("incomplete VERNEED dynamic tags")),
        }
        Ok(metadata)
    }

    fn parse_verdef(
        &self,
        memory: &Memory<'_>,
        start: usize,
        count: usize,
        strtab: u64,
        strsz: u64,
        validated_strings: &mut BTreeMap<u64, u64>,
    ) -> Result<BTreeMap<u16, u32>> {
        let mut definitions = BTreeMap::new();
        let mut record = start;
        let mut total_aux = 0_usize;
        for record_index in 0..count {
            ensure_version_range(
                record,
                20,
                &self.load_ranges,
                "VERDEF header exceeds PT_LOAD",
            )?;
            if memory.read_u16(record)? != VER_DEF_CURRENT {
                return Err(Error::InvalidElf("unsupported VERDEF version"));
            }
            let index = memory.read_u16(checked_add(record, 4)?)? & VER_NDX_MASK;
            if index == 0 {
                return Err(Error::InvalidElf("invalid VERDEF index"));
            }
            let aux_count = usize::from(memory.read_u16(checked_add(record, 6)?)?);
            if aux_count == 0 {
                return Err(Error::InvalidElf("VERDEF has no auxiliary entry"));
            }
            total_aux = total_aux
                .checked_add(aux_count)
                .ok_or(Error::ArithmeticOverflow)?;
            if total_aux > MAX_VERSION_ENTRIES {
                return Err(Error::InvalidElf("too many VERDEF auxiliary entries"));
            }
            let aux_offset = memory.read_u32(checked_add(record, 12)?)?;
            let header_end = checked_add(record, 20)?;
            let mut aux =
                checked_forward_offset(record, aux_offset, "invalid VERDEF auxiliary offset")?;
            if aux < header_end {
                return Err(Error::InvalidElf("overlapping VERDEF auxiliary chain"));
            }
            let mut identity = None;
            let mut consumed_end = header_end;
            for aux_index in 0..aux_count {
                ensure_version_range(
                    aux,
                    8,
                    &self.load_ranges,
                    "VERDEF auxiliary entry exceeds PT_LOAD",
                )?;
                let name = memory.read_u32(aux)?;
                validate_dynamic_string(memory, strtab, strsz, name, validated_strings)?;
                identity.get_or_insert(name);
                consumed_end = consumed_end.max(checked_add(aux, 8)?);
                let next = memory.read_u32(checked_add(aux, 4)?)?;
                if aux_index + 1 == aux_count {
                    if next != 0 {
                        return Err(Error::InvalidElf("unterminated VERDEF auxiliary chain"));
                    }
                } else {
                    let next_aux =
                        checked_forward_offset(aux, next, "invalid VERDEF auxiliary chain")?;
                    if next_aux < checked_add(aux, 8)? {
                        return Err(Error::InvalidElf("overlapping VERDEF auxiliary chain"));
                    }
                    aux = next_aux;
                }
            }
            if index > VER_NDX_GLOBAL && definitions.insert(index, identity.unwrap_or(0)).is_some()
            {
                return Err(Error::InvalidElf("duplicate VERDEF index"));
            }

            let next = memory.read_u32(checked_add(record, 16)?)?;
            if record_index + 1 == count {
                if next != 0 {
                    return Err(Error::InvalidElf("unterminated VERDEF chain"));
                }
            } else {
                let next_record = checked_forward_offset(record, next, "invalid VERDEF chain")?;
                if next_record < consumed_end
                    || next_record
                        .checked_sub(start)
                        .is_none_or(|span| span > MAX_TABLE_SIZE)
                {
                    return Err(Error::InvalidElf("overlapping or oversized VERDEF chain"));
                }
                record = next_record;
            }
        }
        Ok(definitions)
    }

    fn parse_verneed(
        &self,
        memory: &Memory<'_>,
        start: usize,
        count: usize,
        strtab: u64,
        strsz: u64,
        validated_strings: &mut BTreeMap<u64, u64>,
    ) -> Result<BTreeMap<u16, u32>> {
        let mut requirements = BTreeMap::new();
        let mut record = start;
        let mut total_aux = 0_usize;
        for record_index in 0..count {
            ensure_version_range(
                record,
                16,
                &self.load_ranges,
                "VERNEED header exceeds PT_LOAD",
            )?;
            if memory.read_u16(record)? != VER_NEED_CURRENT {
                return Err(Error::InvalidElf("unsupported VERNEED version"));
            }
            let aux_count = usize::from(memory.read_u16(checked_add(record, 2)?)?);
            if aux_count == 0 {
                return Err(Error::InvalidElf("VERNEED has no auxiliary entry"));
            }
            total_aux = total_aux
                .checked_add(aux_count)
                .ok_or(Error::ArithmeticOverflow)?;
            if total_aux > MAX_VERSION_ENTRIES {
                return Err(Error::InvalidElf("too many VERNEED auxiliary entries"));
            }
            let file = memory.read_u32(checked_add(record, 4)?)?;
            validate_dynamic_string(memory, strtab, strsz, file, validated_strings)?;
            let aux_offset = memory.read_u32(checked_add(record, 8)?)?;
            let header_end = checked_add(record, 16)?;
            let mut aux =
                checked_forward_offset(record, aux_offset, "invalid VERNEED auxiliary offset")?;
            if aux < header_end {
                return Err(Error::InvalidElf("overlapping VERNEED auxiliary chain"));
            }
            let mut consumed_end = header_end;
            for aux_index in 0..aux_count {
                ensure_version_range(
                    aux,
                    16,
                    &self.load_ranges,
                    "VERNEED auxiliary entry exceeds PT_LOAD",
                )?;
                let index = memory.read_u16(checked_add(aux, 6)?)? & VER_NDX_MASK;
                if index <= VER_NDX_GLOBAL {
                    return Err(Error::InvalidElf("invalid VERNEED index"));
                }
                let name = memory.read_u32(checked_add(aux, 8)?)?;
                validate_dynamic_string(memory, strtab, strsz, name, validated_strings)?;
                if requirements.insert(index, name).is_some() {
                    return Err(Error::InvalidElf("duplicate VERNEED index"));
                }
                consumed_end = consumed_end.max(checked_add(aux, 16)?);
                let next = memory.read_u32(checked_add(aux, 12)?)?;
                if aux_index + 1 == aux_count {
                    if next != 0 {
                        return Err(Error::InvalidElf("unterminated VERNEED auxiliary chain"));
                    }
                } else {
                    let next_aux =
                        checked_forward_offset(aux, next, "invalid VERNEED auxiliary chain")?;
                    if next_aux < checked_add(aux, 16)? {
                        return Err(Error::InvalidElf("overlapping VERNEED auxiliary chain"));
                    }
                    aux = next_aux;
                }
            }

            let next = memory.read_u32(checked_add(record, 12)?)?;
            if record_index + 1 == count {
                if next != 0 {
                    return Err(Error::InvalidElf("unterminated VERNEED chain"));
                }
            } else {
                let next_record = checked_forward_offset(record, next, "invalid VERNEED chain")?;
                if next_record < consumed_end
                    || next_record
                        .checked_sub(start)
                        .is_none_or(|span| span > MAX_TABLE_SIZE)
                {
                    return Err(Error::InvalidElf("overlapping or oversized VERNEED chain"));
                }
                record = next_record;
            }
        }
        Ok(requirements)
    }

    fn symbol_version_matches(
        &self,
        memory: &Memory<'_>,
        query: &ResolvedSymbolQuery<'_>,
        symbol_index: u32,
        shndx: u16,
        tables: &SymbolTables<'_>,
    ) -> Result<bool> {
        if query.version == SymbolVersion::Any {
            return Ok(true);
        }
        let versions = query
            .versions
            .ok_or(Error::InvalidElf("missing prepared GNU version metadata"))?;
        let Some(versym) = versions.versym else {
            return Ok(query.version == SymbolVersion::Unversioned);
        };
        let offset = usize::try_from(symbol_index)
            .map_err(|_| Error::ArithmeticOverflow)?
            .checked_mul(2)
            .ok_or(Error::ArithmeticOverflow)?;
        let address = checked_add(versym, offset)?;
        ensure_version_range(
            address,
            2,
            &self.load_ranges,
            "VERSYM entry exceeds PT_LOAD",
        )?;
        let index = memory.read_u16(address)? & VER_NDX_MASK;
        match query.version {
            SymbolVersion::Any => Ok(true),
            SymbolVersion::Unversioned => Ok(index <= VER_NDX_GLOBAL),
            SymbolVersion::Exact(version) => {
                if index <= VER_NDX_GLOBAL {
                    return Ok(false);
                }
                let name = if shndx == SHN_UNDEF {
                    versions.requirements.get(&index)
                } else {
                    versions.definitions.get(&index)
                }
                .copied()
                .ok_or(Error::InvalidElf("unresolved GNU symbol version index"))?;
                let address = checked_add_u64(absolute_address(query.strtab)?, u64::from(name))?;
                let available = usize::try_from(query.strsz - u64::from(name))
                    .map_err(|_| Error::ArithmeticOverflow)?;
                match tables.matches_c_string(address, available, version.to_bytes()) {
                    Some(matches) => Ok(matches),
                    None => memory.matches_c_string(address, available, version.to_bytes()),
                }
            }
        }
    }
}

fn checked_version_count(value: u64) -> Result<usize> {
    let count = usize::try_from(value).map_err(|_| Error::ArithmeticOverflow)?;
    if count == 0 || count > MAX_VERSION_ENTRIES {
        return Err(Error::InvalidElf("invalid GNU version record count"));
    }
    Ok(count)
}

fn ensure_version_range(
    address: usize,
    length: usize,
    ranges: &[(usize, usize)],
    message: &'static str,
) -> Result<()> {
    if range_in_ranges(address, length, ranges) {
        Ok(())
    } else {
        Err(Error::InvalidElf(message))
    }
}

fn checked_forward_offset(address: usize, offset: u32, message: &'static str) -> Result<usize> {
    if offset == 0 || !offset.is_multiple_of(4) {
        return Err(Error::InvalidElf(message));
    }
    let next = checked_add(
        address,
        usize::try_from(offset).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    if next <= address {
        return Err(Error::InvalidElf(message));
    }
    Ok(next)
}

pub(super) fn validate_dynamic_string(
    memory: &Memory<'_>,
    strtab: u64,
    strsz: u64,
    offset: u32,
    validated: &mut BTreeMap<u64, u64>,
) -> Result<()> {
    let offset = u64::from(offset);
    if offset >= strsz {
        return Err(Error::InvalidElf("GNU version name exceeds DT_STRSZ"));
    }
    if validated
        .range(..=offset)
        .next_back()
        .is_some_and(|(_, &end)| offset <= end)
    {
        return Ok(());
    }
    let next = validated
        .range(offset + 1..)
        .next()
        .map(|(&start, &end)| (start, end));
    let scan_end = next.map_or(strsz, |(start, _)| start);
    let address = checked_add_u64(absolute_address(strtab)?, offset)?;
    let available = usize::try_from(scan_end - offset).map_err(|_| Error::ArithmeticOverflow)?;
    for index in 0..available {
        let byte = memory.read_u8(checked_add(address, index)?)?;
        if byte == 0 {
            let end = offset
                .checked_add(u64::try_from(index).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            validated.insert(offset, end);
            return Ok(());
        }
    }
    if let Some((start, end)) = next {
        validated.remove(&start);
        validated.insert(offset, end);
        return Ok(());
    }
    Err(Error::InvalidElf("unterminated GNU version name"))
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Image {
        pub(crate) fn symbol_name_location(
            &self,
            memory: &Memory<'_>,
            query: &ResolvedSymbolQuery<'_>,
            symbol_index: u32,
        ) -> Result<(usize, usize, usize)> {
            let tables = SymbolTables::new(
                memory,
                std::slice::from_ref(query),
                self.header.class,
                &self.load_ranges,
            );
            self.symbol_name_location_with_tables(memory, query, symbol_index, &tables)
        }

        pub(crate) fn symbol_match(
            &self,
            memory: &Memory<'_>,
            query: &ResolvedSymbolQuery<'_>,
            symbol_index: u32,
        ) -> Result<SymbolMatch> {
            let tables = SymbolTables::new(
                memory,
                std::slice::from_ref(query),
                self.header.class,
                &self.load_ranges,
            );
            let (symbol_address, name_address, available) =
                self.symbol_name_location_with_tables(memory, query, symbol_index, &tables)?;
            let matches = match tables.matches_c_string(name_address, available, query.name) {
                Some(matches) => matches,
                None => memory.matches_c_string(name_address, available, query.name)?,
            };
            if !matches {
                return Ok(SymbolMatch::Mismatch);
            }
            self.symbol_match_known_name(memory, query, symbol_index, symbol_address, &tables)
        }
    }
}
