//! RAR legacy and modern archive encryption primitives used by `rars`.

// NEWTUA: файл целиком наш — кэш выведенного ключа (тикеты 33 и 35).
pub mod cache;
pub mod rar13;
pub mod rar15;
pub mod rar20;
pub mod rar30;
pub mod rar50;
