use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event;

#[derive(Debug)]
pub enum Event {
    Key(event::KeyEvent),
    Mouse(event::MouseEvent),
    Tick,
    Other,
}

pub fn poll(tick_rate: &Duration) -> Result<Option<Event>> {
    if !event::poll(*tick_rate).context("polling terminal")? {
        Ok(Some(Event::Tick))
    } else {
        match event::read() {
            Ok(event::Event::Key(key)) => Ok(Some(Event::Key(key))),
            Ok(event::Event::Mouse(mev)) => Ok(Some(Event::Mouse(mev))),
            Ok(_) => Ok(Some(Event::Other)),
            e => panic!("Unhandled error {:?}", e),
        }
    }
}
