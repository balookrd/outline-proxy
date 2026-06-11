#[derive(Debug)]
pub(super) struct FragmentChunk {
    pub(super) offset: usize,
    pub(super) data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChunkInsertOutcome {
    Inserted(usize),
    DuplicateExact,
    Overlap,
}

impl FragmentChunk {
    pub(super) fn end(&self) -> usize {
        self.offset + self.data.len()
    }

    pub(super) fn len(&self) -> usize {
        self.data.len()
    }
}

pub(super) fn insert_chunk(
    chunks: &mut Vec<FragmentChunk>,
    offset: usize,
    data: &[u8],
) -> ChunkInsertOutcome {
    let Some(end) = offset.checked_add(data.len()) else {
        return ChunkInsertOutcome::Overlap;
    };

    let mut index = 0usize;
    while index < chunks.len() {
        let existing = &chunks[index];
        if end <= existing.offset {
            break;
        }
        if offset >= existing.end() {
            index += 1;
            continue;
        }
        if offset == existing.offset && end == existing.end() && data == existing.data.as_slice() {
            return ChunkInsertOutcome::DuplicateExact;
        }
        return ChunkInsertOutcome::Overlap;
    }

    chunks.insert(index, FragmentChunk { offset, data: data.to_vec() });
    ChunkInsertOutcome::Inserted(data.len())
}

pub(super) fn chunks_are_complete(chunks: &[FragmentChunk], total_len: usize) -> bool {
    let mut cursor = 0usize;
    for chunk in chunks {
        if chunk.offset != cursor {
            return false;
        }
        cursor += chunk.data.len();
    }
    cursor == total_len
}
