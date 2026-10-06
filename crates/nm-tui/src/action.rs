use crate::app::ScreenId;
use crossterm::event::KeyEvent;
use nm_app::JobEvent;
pub enum Action {
    Key(KeyEvent),
    Tick,
    Job(JobEvent),
    Navigate(ScreenId),
    Quit,
}
pub enum Effect {
    Quit,
    Interrupted,
    SaveSettings,
}
