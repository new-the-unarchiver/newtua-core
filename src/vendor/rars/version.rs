#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveFamily {
    Rar13,
    Rar15To40,
    Rar50Plus,
}

/// Версия формата, какой её называет сам RAR.
///
/// NEWTUA: `allow(dead_code)` — из девяти значений движок строит одно
/// (`Rar50` в описании неподдерживаемой возможности), остальные никто не
/// создаёт. Это перечень версий формата, а не наш набор состояний: выкидывать
/// из него по одному значению — значит ломать таблицу, осмысленную целиком.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveVersion {
    Rar13,
    Rar14,
    Rar15,
    Rar20,
    Rar29,
    Rar30,
    Rar40,
    Rar50,
    Rar70,
}
