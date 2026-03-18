/// Font capable of rendering emojis.
pub static EMOJI: &[u8] = include_bytes!("../../NotoEmoji-Regular.ttf");

/// The name of our emoji-capable font, used when constructing text elements that include emojis.
pub static EMOJI_NAME: &str = "Noto Emoji";
