// vim: tw=80
use std::{error::Error, io, num::NonZeroUsize, time::Duration};

use clap::Parser;
use crossterm::event::KeyCode;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table},
    Terminal,
};
use regex::Regex;

mod app;
use self::app::App;
mod event;
use self::event::Event;

/// Display ZFS datasets' I/O in real time
// TODO: shorten the help options so they fit on 80 columns.
#[derive(Debug, Default, clap::Parser)]
struct Cli {
    /// only display datasets that have some activity.
    #[clap(short = 'a', long = "auto", verbatim_doc_comment)]
    auto:     bool,
    /// Include child datasets' stats with their parents'.
    #[clap(short = 'c', long = "children")]
    children: bool,
    /// display datasets no more than this many levels deep.
    #[clap(short = 'd', long = "depth")]
    depth:    Option<NonZeroUsize>,
    /// only display datasets with names matching filter, as a regex.
    #[clap(short = 'f', value_parser = Regex::new, long = "filter")]
    filter:   Option<Regex>,
    /// display update interval, in seconds or with the specified unit
    #[clap(short = 't', value_parser = Cli::duration_from_str, long = "time")]
    time:     Option<Duration>,
    /// Reverse the sort
    #[clap(short = 'r', long = "reverse")]
    reverse:  bool,
    /// Sort by the named column.  The name should match the column header.
    #[clap(short = 's', long = "sort")]
    sort:     Option<String>,
    /// Display these pools and their children
    pools:    Vec<String>,
}

impl Cli {
    fn duration_from_str(s: &str) -> Result<Duration, humanize_rs::ParseError> {
        if let Ok(fsecs) = s.parse::<f64>() {
            Ok(Duration::from_secs_f64(fsecs))
        } else {
            // Must have units
            humanize_rs::duration::parse(s)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FilterPopup {
    new_regex: String,
}

impl FilterPopup {
    pub fn on_enter(&mut self) -> Result<Regex, impl Error> {
        Regex::new(&self.new_regex)
    }

    pub fn on_backspace(&mut self) {
        self.new_regex.pop();
    }

    pub fn on_char(&mut self, c: char) {
        self.new_regex.push(c);
    }
}

mod ui {
    use ratatui::Frame;

    use super::*;

    // helper function to create a one-line popup box
    fn popup_layout(x: u16, y: u16, r: Rect) -> Rect {
        let popup_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Max(r.height.saturating_sub(y) / 2),
                    Constraint::Length(y),
                    Constraint::Max(r.height.saturating_sub(y) / 2),
                ]
                .as_ref(),
            )
            .split(r);

        Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Max(r.width.saturating_sub(x) / 2),
                    Constraint::Length(x),
                    Constraint::Max(r.width.saturating_sub(x) / 2),
                ]
                .as_ref(),
            )
            .split(popup_layout[1])[1]
    }

    pub fn draw(f: &mut Frame, app: &mut App) {
        let hstyle = Style::default().fg(Color::Red);
        let sstyle = hstyle.add_modifier(Modifier::REVERSED);
        let hcells = [
            Cell::from("   r/s"),
            Cell::from(" kB/s r"),
            Cell::from("   w/s"),
            Cell::from(" kB/s w"),
            Cell::from("   d/s"),
            Cell::from("kB/s d"),
            Cell::from("Dataset"),
        ]
        .into_iter()
        .enumerate()
        .map(|(i, cell)| {
            if Some(i) == app.sort_idx() {
                cell.style(sstyle)
            } else {
                cell.style(hstyle)
            }
        });
        let header = Row::new(hcells).style(Style::default().bg(Color::Blue));
        let rows = app
            .elements()
            .into_iter()
            .map(|elem| {
                Row::new([
                    Cell::from(format!("{:>6.0}", elem.ops_r)),
                    Cell::from(format!("{:>7.0}", elem.r_s / 1024.0)),
                    Cell::from(format!("{:>6.0}", elem.ops_w)),
                    Cell::from(format!("{:>7.0}", elem.w_s / 1024.0)),
                    Cell::from(format!("{:>6.0}", elem.ops_d)),
                    Cell::from(format!("{:>6.0}", elem.d_s / 1024.0)),
                    Cell::from(elem.name),
                ])
            })
            .collect::<Vec<_>>();
        let widths = [
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Min(6),
        ];
        let t = Table::new(rows, widths)
            .header(header)
            .block(Block::default())
            .segment_size(ratatui::layout::SegmentSize::LastTakesRemainder);
        f.render_widget(t, f.size());
    }

    #[rustfmt::skip]
    pub fn draw_filter(f: &mut Frame, app: &FilterPopup) {
        let area = popup_layout(40, 3, f.size());
        let popup_box = Paragraph::new(app.new_regex.as_str())
            .block(
                Block::default()
                .borders(Borders::ALL)
                .title("Filter regex")
            );
        f.render_widget(Clear, area);
        f.render_widget(popup_box, area);
    }

    // Needs a &String argument to work with Option<String>::as_ref
    #[allow(clippy::ptr_arg)]
    pub fn col_idx(col_name: &String) -> Option<usize> {
        match col_name.trim() {
            "r/s" => Some(0),
            "kB/s r" => Some(1),
            "w/s" => Some(2),
            "kB/s w" => Some(3),
            "d/s" => Some(4),
            "kB/s d" => Some(5),
            "Dataset" => Some(6),
            _ => None,
        }
    }
}

// https://github.com/rust-lang/rust-clippy/issues/7483
#[allow(clippy::or_fun_call)]
fn main() -> Result<(), Box<dyn Error>> {
    let cli: Cli = Cli::parse();
    let mut editting_filter = false;
    let mut tick_rate = cli.time.unwrap_or(Duration::from_secs(1));
    let col_idx = cli.sort.as_ref().map(ui::col_idx).unwrap_or(None);
    let mut app = App::new(
        cli.auto,
        cli.children,
        cli.pools,
        cli.depth,
        cli.filter,
        cli.reverse,
        col_idx,
    );
    let mut filter_popup = FilterPopup::default();
    let stdout = io::stdout();
    crossterm::terminal::enable_raw_mode().unwrap();

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    terminal.clear()?;
    while !app.should_quit() {
        terminal.draw(|f| {
            ui::draw(f, &mut app);
            if editting_filter {
                ui::draw_filter(f, &filter_popup)
            }
        })?;

        match event::poll(&tick_rate) {
            Some(Event::Tick) => {
                app.on_tick();
            }
            Some(Event::Key(kev)) => {
                match kev.code {
                    KeyCode::Esc if editting_filter => {
                        editting_filter = false;
                    }
                    KeyCode::Enter if editting_filter => {
                        let filter = filter_popup.on_enter()?;
                        app.set_filter(filter);
                        editting_filter = false;
                    }
                    KeyCode::Backspace if editting_filter => {
                        filter_popup.on_backspace();
                    }
                    KeyCode::Char(c) if editting_filter => {
                        filter_popup.on_char(c);
                    }
                    KeyCode::Char('+') => {
                        app.on_plus();
                    }
                    KeyCode::Char('-') => {
                        app.on_minus();
                    }
                    KeyCode::Char('<') => {
                        tick_rate /= 2;
                    }
                    KeyCode::Char('>') => {
                        tick_rate *= 2;
                    }
                    KeyCode::Char('a') => {
                        app.on_a();
                    }
                    KeyCode::Char('c') => {
                        app.on_c()?;
                    }
                    KeyCode::Char('D') => {
                        app.on_d(false);
                    }
                    KeyCode::Char('d') => {
                        app.on_d(true);
                    }
                    KeyCode::Char('F') => {
                        app.clear_filter();
                    }
                    KeyCode::Char('f') => {
                        editting_filter = true;
                    }
                    KeyCode::Char('q') => {
                        app.on_q();
                    }
                    KeyCode::Char('r') => {
                        app.on_r();
                    }
                    _ => {
                        // Ignore unknown keys
                    }
                }
            }
            None => {
                // stdin closed for some reason
                break;
            }
            _ => {
                // Ignore unknown events
            }
        }
    }
    terminal.set_cursor(0, crossterm::terminal::size()?.1 - 1)?;
    crossterm::terminal::disable_raw_mode().unwrap();
    Ok(())
}
