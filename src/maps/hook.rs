use super::{DeviceId, MapInfo, MapPerms};

impl MapPerms {
    pub(crate) const fn to_prot(self) -> i32 {
        let mut prot = 0;
        if self.contains(Self::READ) {
            prot |= libc::PROT_READ;
        }
        if self.contains(Self::WRITE) {
            prot |= libc::PROT_WRITE;
        }
        if self.contains(Self::EXEC) {
            prot |= libc::PROT_EXEC;
        }
        prot
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MappingIdentity {
    start: usize,
    end: usize,
    perms: MapPerms,
    is_private: bool,
    offset: u64,
    device: DeviceId,
    inode: u64,
}

impl MappingIdentity {
    pub(crate) fn from_map(map: &MapInfo) -> Self {
        Self {
            start: map.start,
            end: map.end,
            perms: map.perms,
            is_private: map.is_private,
            offset: map.offset,
            device: map.device,
            inode: map.inode,
        }
    }

    pub(crate) fn matches(self, map: &MapInfo) -> bool {
        self.start == map.start
            && self.end == map.end
            && self.perms == map.perms
            && self.is_private == map.is_private
            && self.offset == map.offset
            && self.device == map.device
            && self.inode == map.inode
    }

    pub(crate) fn matches_at(self, map: &MapInfo, address: usize) -> bool {
        if self.matches(map) {
            return map.contains(address);
        }
        let Some(offset) = address
            .checked_sub(self.start)
            .and_then(|delta| u64::try_from(delta).ok())
            .and_then(|delta| self.offset.checked_add(delta))
        else {
            return false;
        };
        self.perms == map.perms
            && self.is_private == map.is_private
            && self.device == map.device
            && self.inode == map.inode
            && map.file_offset_at(address) == Some(offset)
    }
}

impl MapInfo {
    pub(crate) fn contains_range(&self, address: usize, len: usize) -> bool {
        address >= self.start && address.checked_add(len).is_some_and(|end| end <= self.end)
    }

    pub(crate) fn file_offset_at(&self, address: usize) -> Option<u64> {
        if !self.contains(address) {
            return None;
        }
        let delta = address.checked_sub(self.start)?;
        self.offset.checked_add(u64::try_from(delta).ok()?)
    }
}

pub(crate) fn find_map_containing(
    maps: &[MapInfo],
    address: usize,
    length: usize,
) -> Option<&MapInfo> {
    let index = maps.partition_point(|map| map.start <= address);
    index
        .checked_sub(1)
        .and_then(|index| maps.get(index))
        .filter(|map| map.contains_range(address, length))
}
