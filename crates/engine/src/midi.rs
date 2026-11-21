//! Minimal Standard MIDI File writer (format 0, no dependencies).
//! Cantus firmus -> channel 0, counterpoint -> channel 1.

use crate::composer::TICKS_PER_NOTE;
use crate::species::first::Composition;
use crate::species::second::Composition2;
use crate::theory::Note;

/// Half-note duration in ticks (second-species CP voice).
const TICKS_PER_HALF: u32 = TICKS_PER_NOTE / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteEvent {
    pub tick: u32,
    pub duration: u32,
    pub midi: u8,
    pub voice: u8, // 0 = CF, 1 = CP
}

impl Composition {
    /// Flatten to timed MIDI events (both voices).
    pub fn events(&self) -> Vec<NoteEvent> {
        let mut evs = Vec::with_capacity(self.cf.len() * 2);
        for (i, n) in self.cf.iter().enumerate() {
            evs.push(NoteEvent {
                tick: i as u32 * TICKS_PER_NOTE,
                duration: TICKS_PER_NOTE,
                midi: n.midi(),
                voice: 0,
            });
        }
        for (i, n) in self.cp.iter().enumerate() {
            evs.push(NoteEvent {
                tick: i as u32 * TICKS_PER_NOTE,
                duration: TICKS_PER_NOTE,
                midi: n.midi(),
                voice: 1,
            });
        }
        evs
    }
}

fn be16(v: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn be32(v: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn varlen(mut v: u32, out: &mut Vec<u8>) {
    let mut buf = [0u8; 5];
    let mut i = buf.len() - 1;
    buf[i] = (v & 0x7F) as u8;
    v >>= 7;
    while v > 0 {
        i -= 1;
        buf[i] = ((v & 0x7F) as u8) | 0x80;
        v >>= 7;
    }
    out.extend_from_slice(&buf[i..]);
}

/// Parsed SMF data: voices plus any track-name meta text.
#[derive(Debug, Clone, Default)]
pub struct SmfData {
    pub cf: Vec<u8>,    // MIDI pitches, whole notes in order
    pub cp: Vec<u8>,
    pub track_name: Option<String>,
}

impl SmfData {
    /// Convert to engine notes, handling both species. First-species files
    /// convert directly. Second-species files need the flat half-note CP
    /// list rebuilt: `read_smf` returns the *sounded* list (2*len-2
    /// entries, the repeated boundary upbeats omitted), while the decoder
    /// replay expects the full 2*len list with the repeats restored —
    /// `[a0, a0, a1, b1, ..., a_last, a_last]`. Returns None if a pitch is
    /// not a diatonic note or the voice lengths fit neither species.
    pub fn to_notes(&self) -> Option<(Vec<Note>, Vec<Note>)> {
        let cf: Vec<Note> = self.cf.iter().map(|&m| Note::from_midi(m)).collect::<Option<_>>()?;
        let cp: Vec<Note> = if self.cp.len() == cf.len() {
            self.cp.iter().map(|&m| Note::from_midi(m)).collect::<Option<_>>()?
        } else if cf.len() >= 4 && self.cp.len() == 2 * cf.len() - 2 {
            let sounded: Vec<Note> =
                self.cp.iter().map(|&m| Note::from_midi(m)).collect::<Option<_>>()?;
            // flat = [s0, s0, s1..s_last, s_last]: restore both boundary
            // whole-note repeats the sounded list omits.
            let mut flat = Vec::with_capacity(2 * cf.len());
            flat.push(sounded[0]);
            flat.push(sounded[0]);
            flat.extend_from_slice(&sounded[1..]);
            flat.push(*sounded.last().unwrap());
            flat
        } else {
            return None;
        };
        Some((cf, cp))
    }
}

fn read_varlen(b: &[u8], i: &mut usize) -> Option<u32> {
    let mut v: u32 = 0;
    for _ in 0..5 {
        let byte = *b.get(*i)? as u32;
        *i += 1;
        v = (v << 7) | (byte & 0x7F);
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    Some(v)
}

/// Parse a format-0 SMF produced by `write_smf`. Returns note pitches per
/// voice (channel 0 -> cf, channel 1 -> cp) and the track-name meta, if any.
pub fn read_smf(bytes: &[u8]) -> Result<SmfData, String> {
    if bytes.len() < 14 || &bytes[0..4] != b"MThd" {
        return Err("not a MIDI file (bad MThd)".into());
    }
    let hdr_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let ntracks = u16::from_be_bytes(bytes[10..12].try_into().unwrap());
    if ntracks != 1 {
        return Err("expected format 0 (single track)".into());
    }
    let mut i = 8 + hdr_len;
    if bytes.get(i..i + 4) != Some(b"MTrk") {
        return Err("missing MTrk".into());
    }
    let track_len = u32::from_be_bytes(bytes[i + 4..i + 8].try_into().unwrap()) as usize;
    let track = &bytes[i + 8..i + 8 + track_len];
    i = 0;

    let mut data = SmfData::default();
    let mut tick: u32 = 0;
    let mut notes: Vec<(u32, u8, u8)> = Vec::new(); // (tick, pitch, channel)

    while i < track.len() {
        let delta = read_varlen(track, &mut i).ok_or("truncated delta")?;
        tick += delta;
        let status = *track.get(i).ok_or("truncated status")?;
        if status == 0xFF {
            let meta_type = *track.get(i + 1).ok_or("truncated meta")?;
            let len = *track.get(i + 2).ok_or("truncated meta len")? as usize;
            let payload = &track[i + 3..i + 3 + len.min(track.len().saturating_sub(i + 3))];
            if meta_type == 0x03 {
                data.track_name = Some(String::from_utf8_lossy(payload).into_owned());
            }
            i += 3 + len;
            continue;
        }
        match status & 0xF0 {
            0x90 => {
                let pitch = *track.get(i + 1).ok_or("truncated note")?;
                let vel = *track.get(i + 2).ok_or("truncated vel")?;
                if vel > 0 {
                    notes.push((tick, pitch, status & 0x0F));
                }
                i += 3;
            }
            0x80 => {
                i += 3;
            }
            0xC0 | 0xD0 => {
                i += 2;
            }
            s => return Err(format!("unhandled MIDI status {s:#x}")),
        }
    }

    notes.sort();
    for (_, pitch, ch) in notes {
        if ch == 0 {
            data.cf.push(pitch);
        } else {
            data.cp.push(pitch);
        }
    }
    Ok(data)
}

impl Composition2 {
    /// Flatten to timed MIDI events. Interior positions emit two half notes;
    /// boundary positions (0, len-1) emit a single whole-note event.
    pub fn events(&self) -> Vec<NoteEvent> {
        let len = self.cf.len();
        let mut evs = Vec::with_capacity(self.cf.len() + 2 * len);
        for (i, n) in self.cf.iter().enumerate() {
            evs.push(NoteEvent {
                tick: i as u32 * TICKS_PER_NOTE,
                duration: TICKS_PER_NOTE,
                midi: n.midi(),
                voice: 0,
            });
        }
        for i in 0..len {
            let base = i as u32 * TICKS_PER_NOTE;
            let a = self.cp[2 * i];
            if i == 0 || i == len - 1 {
                // Whole note: the repeated pair (a, a) is one sounding note.
                evs.push(NoteEvent {
                    tick: base,
                    duration: TICKS_PER_NOTE,
                    midi: a.midi(),
                    voice: 1,
                });
            } else {
                let b = self.cp[2 * i + 1];
                evs.push(NoteEvent {
                    tick: base,
                    duration: TICKS_PER_HALF,
                    midi: a.midi(),
                    voice: 1,
                });
                evs.push(NoteEvent {
                    tick: base + TICKS_PER_HALF,
                    duration: TICKS_PER_HALF,
                    midi: b.midi(),
                    voice: 1,
                });
            }
        }
        evs
    }
}

/// Write a format-0 SMF: tempo 120bpm, CF on ch0, CP on ch1, whole notes.
/// `track_name` is embedded as a track-name meta event (used for the seed).
pub fn write_smf_named(comp: &Composition, track_name: Option<&str>) -> Vec<u8> {
    encode_smf(comp.events(), track_name)
}

/// Second-species variant: CP voice carries half notes (whole notes at the
/// boundaries). Same encoder; `read_smf` parses both transparently.
pub fn write_smf2_named(comp: &Composition2, track_name: Option<&str>) -> Vec<u8> {
    encode_smf(comp.events(), track_name)
}

/// Write without a track-name meta.
pub fn write_smf2(comp: &Composition2) -> Vec<u8> {
    write_smf2_named(comp, None)
}

fn encode_smf(events: Vec<NoteEvent>, track_name: Option<&str>) -> Vec<u8> {
    let mut track: Vec<u8> = Vec::new();

    // Track name meta (optional; carries the generation seed).
    if let Some(name) = track_name {
        let nb = name.as_bytes();
        track.extend_from_slice(&[0x00, 0xFF, 0x03, nb.len() as u8]);
        track.extend_from_slice(nb);
    }
    // Tempo meta: 500000 us per quarter.
    track.extend_from_slice(&[0x00, 0xFF, 0x51, 0x03, 0x07, 0xA1, 0x20]);
    // Program changes: ch0 = 0 (piano), ch1 = 40 (violin).
    track.extend_from_slice(&[0x00, 0xC0, 0x00]);
    track.extend_from_slice(&[0x00, 0xC1, 0x28]);

    // Build a time-ordered event list; note-offs before note-ons at same tick.
    let mut evs: Vec<(u32, u8, u8, bool)> = Vec::new(); // (tick, midi, voice, is_on)
    for e in events {
        evs.push((e.tick, e.midi, e.voice, true));
        evs.push((e.tick + e.duration, e.midi, e.voice, false));
    }
    evs.sort_by_key(|&(t, m, v, on)| (t, !on, v, m));

    let mut last = 0u32;
    for (tick, midi, voice, on) in evs {
        varlen(tick.saturating_sub(last), &mut track);
        last = tick;
        let status = if on {
            0x90 | voice
        } else {
            0x80 | voice
        };
        track.push(status);
        track.push(midi);
        track.push(if on { 0x50 } else { 0x40 });
    }
    // End of track.
    track.extend_from_slice(&[0x00, 0xFF, 0x2F, 0x00]);

    let mut out = Vec::new();
    out.extend_from_slice(b"MThd");
    be32(6, &mut out);
    be16(0, &mut out); // format 0
    be16(1, &mut out); // one track
    be16(480, &mut out); // ticks per quarter
    out.extend_from_slice(b"MTrk");
    be32(track.len() as u32, &mut out);
    out.extend_from_slice(&track);
    out
}

/// Write without a track-name meta.
pub fn write_smf(comp: &Composition) -> Vec<u8> {
    write_smf_named(comp, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::species::first::compose;

    #[test]
    fn smf_structure() {
        let comp = compose(1, 8);
        let bytes = write_smf(&comp);
        assert_eq!(&bytes[0..4], b"MThd");
        assert_eq!(&bytes[14..18], b"MTrk");
        // every note-on has a matching note-off
        let ons = bytes.windows(2).filter(|w| w[0] == 0x90).count()
            + bytes.windows(2).filter(|w| w[0] == 0x91).count();
        let offs = bytes.windows(2).filter(|w| w[0] == 0x80).count()
            + bytes.windows(2).filter(|w| w[0] == 0x81).count();
        assert_eq!(ons, comp.cf.len() + comp.cp.len());
        assert_eq!(offs, ons);
    }

    #[test]
    fn smf_roundtrip() {
        let comp = compose(7, 12);
        let bytes = write_smf_named(&comp, Some("seed:7"));
        let data = read_smf(&bytes).unwrap();
        let cf: Vec<u8> = comp.cf.iter().map(|n| n.midi()).collect();
        let cp: Vec<u8> = comp.cp.iter().map(|n| n.midi()).collect();
        assert_eq!(data.cf, cf);
        assert_eq!(data.cp, cp);
        assert_eq!(data.track_name.as_deref(), Some("seed:7"));
    }

    #[test]
    fn smf2_structure() {
        let comp = crate::species::second::compose2(1, 8);
        let bytes = write_smf2(&comp);
        assert_eq!(&bytes[0..4], b"MThd");
        assert_eq!(&bytes[14..18], b"MTrk");
        // CF whole notes + CP half notes (boundaries are single whole notes).
        let expected = comp.cf.len() + 2 * comp.cf.len() - 2;
        let ons = bytes.windows(2).filter(|w| w[0] == 0x90).count()
            + bytes.windows(2).filter(|w| w[0] == 0x91).count();
        let offs = bytes.windows(2).filter(|w| w[0] == 0x80).count()
            + bytes.windows(2).filter(|w| w[0] == 0x81).count();
        assert_eq!(ons, expected);
        assert_eq!(offs, ons);
    }

    #[test]
    fn smf2_roundtrip() {
        let comp = crate::species::second::compose2(7, 12);
        let bytes = write_smf2_named(&comp, Some("seed:7"));
        let data = read_smf(&bytes).unwrap();
        let cf: Vec<u8> = comp.cf.iter().map(|n| n.midi()).collect();
        assert_eq!(data.cf, cf);
        // The sounded CP list: flat half notes minus the repeated boundary
        // upbeats (indices 1 and 2*len - 1 are one sounding whole note).
        let len = comp.cf.len();
        let sounded: Vec<u8> = comp
            .cp
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1 && *i != 2 * len - 1)
            .map(|(_, n)| n.midi())
            .collect();
        assert_eq!(data.cp, sounded);
        assert_eq!(data.track_name.as_deref(), Some("seed:7"));
    }

    #[test]
    fn smf2_to_notes_rebuilds_flat_cp() {
        // Extraction replays the full 2*len half-note list; to_notes must
        // restore the boundary repeats read_smf omits.
        let comp = crate::species::second::compose2(3, 10);
        let data = read_smf(&write_smf2(&comp)).unwrap();
        let (cf, cp) = data.to_notes().unwrap();
        assert_eq!(cf, comp.cf);
        assert_eq!(cp, comp.cp);
        // First-species files convert directly.
        let comp1 = compose(3, 10);
        let data1 = read_smf(&write_smf(&comp1)).unwrap();
        let (cf1, cp1) = data1.to_notes().unwrap();
        assert_eq!(cf1, comp1.cf);
        assert_eq!(cp1, comp1.cp);
    }
}
