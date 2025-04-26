use std::time::Duration;

use crossterm::event;

#[derive(Debug)]
pub enum Event {
    Key(event::KeyEvent),
    Mouse,
    Tick,
    Other,
}

/// Poll stdin for events with a timeout
pub fn poll(tick_rate: &Duration) -> Option<Event> {
    if !event::poll(*tick_rate).unwrap() {
        Some(Event::Tick)
    } else {
        match event::read() {
            Ok(event::Event::Key(key)) => Some(Event::Key(key)),
            Ok(event::Event::Mouse(_)) => Some(Event::Mouse),
            Ok(_) => Some(Event::Other),
            e => panic!("Unhandled error {e:?}"),
        }
    }
}
