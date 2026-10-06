use ratatui::style::Color;
#[derive(Clone, Debug)]
pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub accent: Color,
    pub muted: Color,
    pub severity: [Color; 5],
    pub border: Color,
}
impl Theme {
    pub fn default_dark() -> Self {
        Self {
            bg: Color::Black,
            fg: Color::White,
            accent: Color::Cyan,
            muted: Color::Gray,
            severity: [
                Color::Gray,
                Color::Blue,
                Color::Yellow,
                Color::LightRed,
                Color::Red,
            ],
            border: Color::DarkGray,
        }
    }
    pub fn high_contrast() -> Self {
        Self {
            bg: Color::Black,
            fg: Color::White,
            accent: Color::Yellow,
            muted: Color::White,
            severity: [
                Color::White,
                Color::Cyan,
                Color::Yellow,
                Color::LightRed,
                Color::LightMagenta,
            ],
            border: Color::White,
        }
    }
    pub fn no_color() -> Self {
        Self {
            bg: Color::Reset,
            fg: Color::Reset,
            accent: Color::Reset,
            muted: Color::Reset,
            severity: [Color::Reset; 5],
            border: Color::Reset,
        }
    }
}
