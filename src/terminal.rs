//! A terminal inside the main window, for SSH sessions: `alacritty_terminal` runs the
//! program in a pseudo-terminal and keeps track of the screen; this draws that screen with
//! egui and turns egui's input back into what a terminal program expects.

use std::collections::HashMap;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};

use alacritty_terminal::event::{Event as TermEvent, EventListener, Notify, OnResize, WindowSize};
use alacritty_terminal::event_loop::{EventLoop, EventLoopSender, Msg, Notifier};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::sync::FairMutex;
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config, Osc52, Term, TermMode, viewport_to_point};
use alacritty_terminal::tty;
use alacritty_terminal::vte::ansi::{Color, CursorShape, NamedColor, Rgb};
use anyhow::{Context, Result};
use eframe::egui::{self, Color32, Event, EventFilter, FontId, Key, Modifiers, Rect, Sense, pos2};

use crate::bus::Bus;

const FONT_SIZE: f32 = 13.5;
const BACKGROUND: Color32 = Color32::from_rgb(0x14, 0x14, 0x14);
const FOREGROUND: Color32 = Color32::from_rgb(0xd8, 0xd8, 0xd8);
const CURSOR: Color32 = Color32::from_rgb(0xd8, 0xd8, 0xd8);
/// The standard 16 colours (the VS Code dark theme's, which read well on this background).
const PALETTE: [Color32; 16] = [
    Color32::from_rgb(0x00, 0x00, 0x00),
    Color32::from_rgb(0xcd, 0x31, 0x31),
    Color32::from_rgb(0x0d, 0xbc, 0x79),
    Color32::from_rgb(0xe5, 0xe5, 0x10),
    Color32::from_rgb(0x24, 0x72, 0xc8),
    Color32::from_rgb(0xbc, 0x3f, 0xbc),
    Color32::from_rgb(0x11, 0xa8, 0xcd),
    Color32::from_rgb(0xe5, 0xe5, 0xe5),
    Color32::from_rgb(0x66, 0x66, 0x66),
    Color32::from_rgb(0xf1, 0x4c, 0x4c),
    Color32::from_rgb(0x23, 0xd1, 0x8b),
    Color32::from_rgb(0xf5, 0xf5, 0x43),
    Color32::from_rgb(0x3b, 0x8e, 0xea),
    Color32::from_rgb(0xd6, 0x70, 0xd6),
    Color32::from_rgb(0x29, 0xb8, 0xdb),
    Color32::from_rgb(0xff, 0xff, 0xff),
];

/// The screen's size before the first frame says how much room there is.
const START_SIZE: Size = Size {
    columns: 100,
    lines: 30,
};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Size {
    columns: usize,
    lines: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.lines
    }
    fn screen_lines(&self) -> usize {
        self.lines
    }
    fn columns(&self) -> usize {
        self.columns
    }
}

#[derive(Default)]
struct Shared {
    exit: Option<ExitStatus>,
    /// The event loop stopped, so the program can't be running any more.
    closed: bool,
    sender: Option<EventLoopSender>,
}

/// Hears from the terminal's background thread.
#[derive(Clone)]
struct Listener {
    shared: Arc<Mutex<Shared>>,
    bus: Bus,
}

impl EventListener for Listener {
    fn send_event(&self, event: TermEvent) {
        let reply = |text: String| {
            if let Some(sender) = &self.shared.lock().unwrap().sender {
                let _ = sender.send(Msg::Input(text.into_bytes().into()));
            }
        };
        match event {
            TermEvent::PtyWrite(text) => reply(text),
            // Programs ask for these to pick readable colours.
            TermEvent::ColorRequest(index, format) => reply(format(rgb_of(match index {
                256 => FOREGROUND,
                257 => BACKGROUND,
                258 => CURSOR,
                i => indexed(i.min(255) as u8),
            }))),
            TermEvent::ChildExit(status) => {
                self.shared.lock().unwrap().exit = Some(status);
                self.bus.wake();
            }
            TermEvent::Exit => {
                self.shared.lock().unwrap().closed = true;
                self.bus.wake();
            }
            TermEvent::Wakeup => self.bus.wake(),
            _ => {}
        }
    }
}

pub struct Terminal {
    term: Arc<FairMutex<Term<Listener>>>,
    notifier: Notifier,
    shared: Arc<Mutex<Shared>>,
    size: Size,
    selecting: bool,
    /// A paste was asked for with Ctrl+Shift+V, rather than typed as Ctrl+V.
    paste_requested: bool,
    /// Scroll distance not yet making up a whole line.
    scroll_rest: f32,
    took_first_focus: bool,
}

impl Terminal {
    pub fn spawn(program: &str, args: &[String], bus: &Bus) -> Result<Self> {
        let shared: Arc<Mutex<Shared>> = Arc::default();
        let listener = Listener {
            shared: shared.clone(),
            bus: bus.clone(),
        };
        let options = tty::Options {
            shell: Some(tty::Shell::new(program.to_string(), args.to_vec())),
            working_directory: None,
            drain_on_exit: true,
            env: HashMap::from([
                ("TERM".to_string(), "xterm-256color".to_string()),
                ("COLORTERM".to_string(), "truecolor".to_string()),
            ]),
        };
        let pty = tty::new(&options, window_size(START_SIZE, 8, 16), 0)
            .with_context(|| format!("Couldn't start `{program}`"))?;
        let config = Config {
            // The remote machine doesn't get to read or set the local clipboard.
            osc52: Osc52::Disabled,
            ..Default::default()
        };
        let term = Arc::new(FairMutex::new(Term::new(
            config,
            &START_SIZE,
            listener.clone(),
        )));
        let event_loop = EventLoop::new(term.clone(), listener, pty, true, false)
            .context("starting the terminal")?;
        let sender = event_loop.channel();
        shared.lock().unwrap().sender = Some(sender.clone());
        event_loop.spawn();
        Ok(Self {
            term,
            notifier: Notifier(sender),
            shared,
            size: START_SIZE,
            selecting: false,
            paste_requested: false,
            scroll_rest: 0.0,
            took_first_focus: false,
        })
    }

    /// The program has ended, and how, if that's known.
    pub fn ended(&self) -> Option<Option<i32>> {
        let shared = self.shared.lock().unwrap();
        match (shared.exit, shared.closed) {
            (Some(status), _) => Some(status.code()),
            (None, true) => Some(None),
            (None, false) => None,
        }
    }

    pub fn shutdown(&self) {
        let _ = self.notifier.0.send(Msg::Shutdown);
    }

    /// The widget's id, for telling whether keys should go to the terminal.
    pub fn focus_id() -> egui::Id {
        egui::Id::unique("terminal_view")
    }

    fn resize(&mut self, size: Size, cell: egui::Vec2) {
        if size == self.size {
            return;
        }
        self.size = size;
        self.term.lock().resize(size);
        self.notifier
            .on_resize(window_size(size, cell.x as u16, cell.y as u16));
    }

    /// Draws the screen in all the room there is and handles its input, unless a window
    /// on top has that (`interactive` is false).
    pub fn show(&mut self, ui: &mut egui::Ui, interactive: bool) {
        let alive = self.ended().is_none();
        let font = FontId::monospace(FONT_SIZE);
        let cell = ui.fonts_mut(|f| egui::vec2(f.glyph_width(&font, 'M'), f.row_height(&font)));
        let rect = ui.available_rect_before_wrap();
        let response = ui.interact(rect, Self::focus_id(), Sense::click_and_drag());
        ui.allocate_rect(rect, Sense::hover());
        response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Terminal, true, "Terminal"));

        self.resize(
            Size {
                columns: ((rect.width() / cell.x) as usize).max(2),
                lines: ((rect.height() / cell.y) as usize).max(1),
            },
            cell,
        );

        if interactive {
            // Once the program has ended the keyboard has nothing to do here, and goes back
            // to the app's shortcuts. What's on the screen can still be selected and copied.
            if !alive {
                response.surrender_focus();
                if response.hovered() {
                    self.handle_copy(ui.ctx());
                }
            } else if response.clicked() || response.drag_started() || !self.took_first_focus {
                self.took_first_focus = true;
                response.request_focus();
            }
            if alive && response.has_focus() {
                ui.memory_mut(|m| {
                    m.set_focus_lock_filter(
                        Self::focus_id(),
                        EventFilter {
                            tab: true,
                            horizontal_arrows: true,
                            vertical_arrows: true,
                            escape: true,
                        },
                    );
                });
                self.handle_keys(ui.ctx());
            }
            self.handle_pointer(ui, rect, cell, &response);
        }

        self.draw(ui, rect, cell, &font, response.has_focus());
    }

    fn handle_copy(&self, ctx: &egui::Context) {
        let wanted = ctx.input_mut(|i| i.consume_key(Modifiers::CTRL | Modifiers::SHIFT, Key::C));
        if wanted && let Some(text) = self.term.lock().selection_to_string() {
            ctx.copy_text(text);
        }
    }

    fn send(&self, bytes: Vec<u8>) {
        self.notifier.notify(bytes);
    }

    fn handle_keys(&mut self, ctx: &egui::Context) {
        let (events, modifiers) = ctx.input(|i| (i.events.clone(), i.modifiers));
        let mode = *self.term.lock().mode();
        let app_cursor = mode.contains(TermMode::APP_CURSOR);
        let mut typed = false;
        for event in events {
            match event {
                // egui has already turned plain Ctrl+C/X/V into these. In a terminal they're
                // just control characters, and Ctrl+Shift copies and pastes instead.
                Event::Copy => {
                    self.send(vec![0x03]);
                    typed = true;
                }
                Event::Cut => {
                    self.send(vec![0x18]);
                    typed = true;
                }
                Event::Paste(text) => {
                    if std::mem::take(&mut self.paste_requested) {
                        self.paste(&text, mode);
                    } else {
                        self.send(vec![0x16]);
                    }
                    typed = true;
                }
                // Alt combinations come through as keys below.
                Event::Text(text) if !modifiers.alt => {
                    self.send(text.into_bytes());
                    typed = true;
                }
                Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } => {
                    if modifiers.ctrl && modifiers.shift && key == Key::C {
                        if let Some(text) = self.term.lock().selection_to_string() {
                            ctx.copy_text(text);
                        }
                    } else if modifiers.ctrl && modifiers.shift && key == Key::V {
                        self.paste_requested = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                    } else if modifiers.shift && key == Key::PageUp {
                        self.term.lock().scroll_display(Scroll::PageUp);
                    } else if modifiers.shift && key == Key::PageDown {
                        self.term.lock().scroll_display(Scroll::PageDown);
                    } else if let Some(bytes) = key_bytes(key, modifiers, app_cursor) {
                        self.send(bytes);
                        typed = true;
                    }
                }
                _ => {}
            }
        }
        if typed {
            let mut term = self.term.lock();
            term.scroll_display(Scroll::Bottom);
            term.selection = None;
        }
    }

    fn paste(&self, text: &str, mode: TermMode) {
        if mode.contains(TermMode::BRACKETED_PASTE) {
            // A pasted end marker would end the paste early, and what follows would run.
            let clean = text.replace("\x1b[201~", "");
            self.send(format!("\x1b[200~{clean}\x1b[201~").into_bytes());
        } else {
            // Terminals send Enter as a carriage return.
            self.send(text.replace("\r\n", "\r").replace('\n', "\r").into_bytes());
        }
    }

    fn handle_pointer(
        &mut self,
        ui: &egui::Ui,
        rect: Rect,
        cell: egui::Vec2,
        response: &egui::Response,
    ) {
        let mode = *self.term.lock().mode();
        let reporting = mode.intersects(TermMode::MOUSE_MODE) && mode.contains(TermMode::SGR_MOUSE);
        let at = |pos: egui::Pos2| {
            let column = (((pos.x - rect.left()) / cell.x).max(0.0) as usize)
                .min(self.size.columns.saturating_sub(1));
            let line = (((pos.y - rect.top()) / cell.y).max(0.0) as usize)
                .min(self.size.lines.saturating_sub(1));
            let side = if (pos.x - rect.left()) % cell.x < cell.x / 2.0 {
                Side::Left
            } else {
                Side::Right
            };
            (line, column, side)
        };

        if response.hovered() {
            let (delta, pointer) = ui.input(|i| (i.smooth_scroll_delta.y, i.pointer.hover_pos()));
            if delta != 0.0 {
                self.scroll_rest += delta / cell.y;
                let lines = self.scroll_rest.trunc() as i32;
                self.scroll_rest -= lines as f32;
                if lines != 0 {
                    if reporting && let Some(pos) = pointer {
                        let (line, column, _) = at(pos);
                        let button = if lines > 0 { 64 } else { 65 };
                        for _ in 0..lines.abs() {
                            self.send(sgr_mouse(button, column, line, true));
                        }
                    } else if mode.contains(TermMode::ALT_SCREEN) {
                        // Full-screen programs like `less` scroll with the arrow keys.
                        let key = if lines > 0 {
                            Key::ArrowUp
                        } else {
                            Key::ArrowDown
                        };
                        let app_cursor = mode.contains(TermMode::APP_CURSOR);
                        if let Some(bytes) = key_bytes(key, Modifiers::NONE, app_cursor) {
                            for _ in 0..lines.abs() {
                                self.send(bytes.clone());
                            }
                        }
                    } else {
                        self.term.lock().scroll_display(Scroll::Delta(lines));
                    }
                }
            }
        }

        if reporting {
            let events = ui.input(|i| i.events.clone());
            for event in events {
                if let Event::PointerButton {
                    pos,
                    button,
                    pressed,
                    ..
                } = event
                    && rect.contains(pos)
                {
                    let code = match button {
                        egui::PointerButton::Primary => 0,
                        egui::PointerButton::Middle => 1,
                        egui::PointerButton::Secondary => 2,
                        _ => continue,
                    };
                    let (line, column, _) = at(pos);
                    self.send(sgr_mouse(code, column, line, pressed));
                }
            }
            return;
        }

        let offset = self.term.lock().grid().display_offset();
        let grid_point = |line: usize, column: usize| {
            viewport_to_point(offset, Point::new(line, Column(column)))
        };
        // Where the button went down: by the time it counts as a drag, the pointer has moved.
        if response.drag_started()
            && let Some(pos) = ui.input(|i| i.pointer.press_origin())
        {
            let (line, column, side) = at(pos);
            let start = grid_point(line, column);
            self.term.lock().selection = Some(Selection::new(SelectionType::Simple, start, side));
            self.selecting = true;
        } else if self.selecting
            && let Some(pos) = response.interact_pointer_pos()
        {
            let (line, column, side) = at(pos);
            let point = grid_point(line, column);
            if let Some(selection) = self.term.lock().selection.as_mut() {
                selection.update(point, side);
            }
        }
        if response.drag_stopped() {
            self.selecting = false;
        } else if response.clicked() {
            self.term.lock().selection = None;
        }
    }

    fn draw(&self, ui: &egui::Ui, rect: Rect, cell: egui::Vec2, font: &FontId, focused: bool) {
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, BACKGROUND);
        let term = self.term.lock();
        let content = term.renderable_content();
        let cursor = content.cursor;
        let selection = content.selection;
        let offset = content.display_offset as i32;
        let overrides = content.colors;

        let top_left = |line: Line, column: usize| {
            let row = line.0 + offset;
            pos2(
                rect.left() + column as f32 * cell.x,
                rect.top() + row as f32 * cell.y,
            )
        };

        // Runs of plain text in one style are drawn together, which is much cheaper than
        // cell by cell. Anything else gets its own cell, so that a glyph from a fallback
        // font of another width can't push the rest of the line out of place.
        let mut run = String::new();
        let mut run_start = pos2(0.0, 0.0);
        let mut run_color = FOREGROUND;
        let flush = |run: &mut String, start: egui::Pos2, color: Color32| {
            if !run.is_empty() {
                painter.text(
                    start,
                    egui::Align2::LEFT_TOP,
                    run.as_str(),
                    font.clone(),
                    color,
                );
                run.clear();
            }
        };
        let mut last: Option<(i32, usize)> = None;

        for indexed_cell in content.display_iter {
            let point = indexed_cell.point;
            let flags = indexed_cell.cell.flags;
            if flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER) {
                continue;
            }
            let mut fg = color_of(indexed_cell.cell.fg, flags, overrides);
            let mut bg = color_of(indexed_cell.cell.bg, Flags::empty(), overrides);
            if flags.contains(Flags::INVERSE) {
                std::mem::swap(&mut fg, &mut bg);
            }
            if selection.is_some_and(|s| s.contains(point)) {
                fg = BACKGROUND;
                bg = FOREGROUND;
            }
            if flags.contains(Flags::HIDDEN) {
                fg = bg;
            }
            let at = top_left(point.line, point.column.0);
            let width = if flags.contains(Flags::WIDE_CHAR) {
                2.0 * cell.x
            } else {
                cell.x
            };
            if bg != BACKGROUND {
                painter.rect_filled(Rect::from_min_size(at, egui::vec2(width, cell.y)), 0.0, bg);
            }
            if flags.intersects(Flags::ALL_UNDERLINES) {
                let y = at.y + cell.y - 1.0;
                painter.hline(at.x..=at.x + width, y, egui::Stroke::new(1.0, fg));
            }
            if flags.contains(Flags::STRIKEOUT) {
                let y = at.y + cell.y / 2.0;
                painter.hline(at.x..=at.x + width, y, egui::Stroke::new(1.0, fg));
            }

            let ch = indexed_cell.cell.c;
            let plain = ch.is_ascii_graphic() && indexed_cell.cell.zerowidth().is_none();
            let joins = last == Some((point.line.0, point.column.0.wrapping_sub(1)))
                && plain
                && fg == run_color;
            if !joins {
                flush(&mut run, run_start, run_color);
            }
            if plain {
                if run.is_empty() {
                    run_start = at;
                    run_color = fg;
                }
                run.push(ch);
                last = Some((point.line.0, point.column.0));
            } else {
                last = None;
                if ch != ' ' && ch != '\0' {
                    let mut text = ch.to_string();
                    if let Some(extra) = indexed_cell.cell.zerowidth() {
                        text.extend(extra);
                    }
                    painter.text(at, egui::Align2::LEFT_TOP, text, font.clone(), fg);
                }
            }
        }
        flush(&mut run, run_start, run_color);

        if cursor.shape != CursorShape::Hidden {
            let at = top_left(cursor.point.line, cursor.point.column.0);
            let block = Rect::from_min_size(at, cell);
            if !focused {
                painter.rect_stroke(
                    block,
                    0.0,
                    egui::Stroke::new(1.0, CURSOR),
                    egui::StrokeKind::Inside,
                );
            } else {
                match cursor.shape {
                    CursorShape::Beam => {
                        painter.vline(at.x, at.y..=at.y + cell.y, egui::Stroke::new(2.0, CURSOR));
                    }
                    CursorShape::Underline => {
                        let y = at.y + cell.y - 1.0;
                        painter.hline(at.x..=at.x + cell.x, y, egui::Stroke::new(2.0, CURSOR));
                    }
                    _ => {
                        // See-through, so the character under the cursor stays readable
                        // without a second pass over the text.
                        painter.rect_filled(block, 0.0, CURSOR.gamma_multiply(0.55));
                    }
                }
            }
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn window_size(size: Size, cell_width: u16, cell_height: u16) -> WindowSize {
    WindowSize {
        num_lines: size.lines as u16,
        num_cols: size.columns as u16,
        cell_width,
        cell_height,
    }
}

/// A mouse report in the form every modern terminal program understands.
fn sgr_mouse(button: u8, column: usize, line: usize, pressed: bool) -> Vec<u8> {
    let end = if pressed { 'M' } else { 'm' };
    format!("\x1b[<{button};{};{}{end}", column + 1, line + 1).into_bytes()
}

/// What a terminal sends for a key that isn't plain text (that comes as text events).
fn key_bytes(key: Key, modifiers: Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    if let Some(letter) = letter_of(key) {
        return if modifiers.ctrl {
            let control = letter - b'a' + 1;
            Some(if modifiers.alt {
                vec![0x1b, control]
            } else {
                vec![control]
            })
        } else if modifiers.alt {
            let letter = if modifiers.shift {
                letter.to_ascii_uppercase()
            } else {
                letter
            };
            Some(vec![0x1b, letter])
        } else {
            None
        };
    }
    // Other Ctrl combinations with long-standing meanings.
    if modifiers.ctrl {
        let control = match key {
            Key::OpenBracket => Some(0x1b),
            Key::Backslash => Some(0x1c),
            Key::CloseBracket => Some(0x1d),
            Key::Slash | Key::Minus => Some(0x1f),
            Key::Space => Some(0x00),
            _ => None,
        };
        if let Some(c) = control {
            return Some(vec![c]);
        }
    }

    // xterm's way of adding modifiers: `CSI 1;<code> X` and `CSI <n>;<code> ~`.
    let code =
        1 + u8::from(modifiers.shift) + 2 * u8::from(modifiers.alt) + 4 * u8::from(modifiers.ctrl);
    let letter_key = |letter: char| {
        Some(if code > 1 {
            format!("\x1b[1;{code}{letter}").into_bytes()
        } else if app_cursor {
            format!("\x1bO{letter}").into_bytes()
        } else {
            format!("\x1b[{letter}").into_bytes()
        })
    };
    let tilde = |n: u8| {
        Some(if code > 1 {
            format!("\x1b[{n};{code}~").into_bytes()
        } else {
            format!("\x1b[{n}~").into_bytes()
        })
    };
    let function = |letter: char| {
        Some(if code > 1 {
            format!("\x1b[1;{code}{letter}").into_bytes()
        } else {
            format!("\x1bO{letter}").into_bytes()
        })
    };
    match key {
        Key::Enter => Some(if modifiers.alt {
            vec![0x1b, b'\r']
        } else {
            vec![b'\r']
        }),
        Key::Tab if modifiers.shift => Some(b"\x1b[Z".to_vec()),
        Key::Tab => Some(vec![b'\t']),
        Key::Backspace if modifiers.ctrl => Some(vec![0x08]),
        Key::Backspace if modifiers.alt => Some(vec![0x1b, 0x7f]),
        Key::Backspace => Some(vec![0x7f]),
        Key::Escape => Some(vec![0x1b]),
        Key::ArrowUp => letter_key('A'),
        Key::ArrowDown => letter_key('B'),
        Key::ArrowRight => letter_key('C'),
        Key::ArrowLeft => letter_key('D'),
        Key::Home => letter_key('H'),
        Key::End => letter_key('F'),
        Key::Insert => tilde(2),
        Key::Delete => tilde(3),
        Key::PageUp => tilde(5),
        Key::PageDown => tilde(6),
        Key::F1 => function('P'),
        Key::F2 => function('Q'),
        Key::F3 => function('R'),
        Key::F4 => function('S'),
        Key::F5 => tilde(15),
        Key::F6 => tilde(17),
        Key::F7 => tilde(18),
        Key::F8 => tilde(19),
        Key::F9 => tilde(20),
        Key::F10 => tilde(21),
        Key::F11 => tilde(23),
        Key::F12 => tilde(24),
        _ => None,
    }
}

fn letter_of(key: Key) -> Option<u8> {
    let name = key.name();
    match name.as_bytes() {
        [c] if c.is_ascii_uppercase() => Some(c.to_ascii_lowercase()),
        _ => None,
    }
}

fn rgb_of(color: Color32) -> Rgb {
    Rgb {
        r: color.r(),
        g: color.g(),
        b: color.b(),
    }
}

fn indexed(index: u8) -> Color32 {
    match index {
        0..=15 => PALETTE[index as usize],
        16..=231 => {
            let i = index - 16;
            let level = |n: u8| if n == 0 { 0 } else { 55 + n * 40 };
            Color32::from_rgb(level(i / 36), level((i / 6) % 6), level(i % 6))
        }
        232..=255 => {
            let v = 8 + (index - 232) * 10;
            Color32::from_rgb(v, v, v)
        }
    }
}

fn color_of(
    color: Color,
    flags: Flags,
    overrides: &alacritty_terminal::term::color::Colors,
) -> Color32 {
    let from_palette = |index: usize| {
        overrides[index]
            .map(|c| Color32::from_rgb(c.r, c.g, c.b))
            .unwrap_or_else(|| match index {
                256 => FOREGROUND,
                257 => BACKGROUND,
                258 => CURSOR,
                i => indexed(i.min(255) as u8),
            })
    };
    match color {
        Color::Spec(c) => Color32::from_rgb(c.r, c.g, c.b),
        Color::Indexed(i) => {
            // Bold text in one of the first eight colours traditionally means its bright version.
            let i = if flags.contains(Flags::BOLD) && i < 8 {
                i + 8
            } else {
                i
            };
            from_palette(i as usize)
        }
        Color::Named(named) => match named {
            NamedColor::Foreground if flags.contains(Flags::DIM) => FOREGROUND.gamma_multiply(0.6),
            NamedColor::Foreground if flags.contains(Flags::BOLD) => Color32::WHITE,
            NamedColor::Foreground | NamedColor::BrightForeground => from_palette(256),
            NamedColor::Background => from_palette(257),
            NamedColor::Cursor => from_palette(258),
            NamedColor::DimForeground => FOREGROUND.gamma_multiply(0.6),
            NamedColor::DimBlack
            | NamedColor::DimRed
            | NamedColor::DimGreen
            | NamedColor::DimYellow
            | NamedColor::DimBlue
            | NamedColor::DimMagenta
            | NamedColor::DimCyan
            | NamedColor::DimWhite => {
                let base = named as usize - NamedColor::DimBlack as usize;
                from_palette(base).gamma_multiply(0.6)
            }
            other => {
                let index = other as usize;
                let index = if flags.contains(Flags::BOLD) && index < 8 {
                    index + 8
                } else {
                    index
                };
                from_palette(index)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mods(ctrl: bool, shift: bool, alt: bool) -> Modifiers {
        Modifiers {
            ctrl,
            shift,
            alt,
            ..Modifiers::NONE
        }
    }

    #[test]
    fn keys_translate_as_a_terminal_expects() {
        let none = Modifiers::NONE;
        let key = |k, m, app| key_bytes(k, m, app).unwrap();
        assert_eq!(key(Key::Enter, none, false), b"\r");
        assert_eq!(key(Key::Tab, none, false), b"\t");
        assert_eq!(key(Key::Backspace, none, false), [0x7f]);
        assert_eq!(key(Key::Escape, none, false), [0x1b]);
        assert_eq!(key(Key::ArrowUp, none, false), b"\x1b[A");
        assert_eq!(key(Key::ArrowUp, none, true), b"\x1bOA", "vim, less");
        assert_eq!(
            key(Key::ArrowLeft, mods(true, false, false), false),
            b"\x1b[1;5D"
        );
        assert_eq!(key(Key::Delete, none, false), b"\x1b[3~");
        assert_eq!(key(Key::F1, none, false), b"\x1bOP");
        assert_eq!(key(Key::F5, none, false), b"\x1b[15~");
        assert_eq!(key(Key::A, mods(true, false, false), false), [0x01]);
        assert_eq!(key(Key::D, mods(true, false, false), false), [0x04]);
        assert_eq!(key(Key::Z, mods(true, false, false), false), [0x1a]);
        assert_eq!(key(Key::B, mods(false, false, true), false), [0x1b, b'b']);
        assert_eq!(
            key(Key::OpenBracket, mods(true, false, false), false),
            [0x1b]
        );
    }

    #[test]
    fn plain_letters_are_left_to_the_text_events() {
        assert!(key_bytes(Key::A, Modifiers::NONE, false).is_none());
        assert!(key_bytes(Key::A, mods(false, true, false), false).is_none());
    }

    #[test]
    fn colours_cover_the_whole_palette() {
        assert_eq!(indexed(1), PALETTE[1]);
        assert_eq!(indexed(16), Color32::from_rgb(0, 0, 0));
        assert_eq!(indexed(231), Color32::from_rgb(255, 255, 255));
        assert_eq!(indexed(232), Color32::from_rgb(8, 8, 8));
        assert_eq!(indexed(255), Color32::from_rgb(238, 238, 238));
    }

    #[test]
    fn mouse_reports_are_one_based() {
        assert_eq!(sgr_mouse(0, 0, 0, true), b"\x1b[<0;1;1M");
        assert_eq!(sgr_mouse(2, 4, 9, false), b"\x1b[<2;5;10m");
    }

    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "timed out: {what}");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn screen_text(t: &Terminal) -> String {
        let term = t.term.lock();
        let grid = term.grid();
        (0..grid.screen_lines() as i32)
            .map(|l| {
                (0..grid.columns())
                    .map(|c| grid[Line(l)][Column(c)].c)
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_program_runs_in_a_real_terminal_and_input_reaches_it() {
        // `-i` isn't needed: a pseudo-terminal is what's being checked.
        let script = "[ -t 0 ] && echo on-a-tty; echo \"TERM=$TERM\"; read -r line; \
                      echo \"got:$line\"; exit 7";
        let args = vec!["-c".to_string(), script.to_string()];
        let t = Terminal::spawn("sh", &args, &Bus::default()).unwrap();
        wait_for("output", || screen_text(&t).contains("TERM=xterm-256color"));
        assert!(screen_text(&t).contains("on-a-tty"));

        t.send(b"hello\r".to_vec());
        wait_for("reply", || screen_text(&t).contains("got:hello"));
        wait_for("exit", || t.ended().is_some());
        assert_eq!(t.ended(), Some(Some(7)));
    }

    #[test]
    fn resizing_tells_the_program() {
        let args = vec![
            "-c".to_string(),
            "read -r _; stty size; sleep 5".to_string(),
        ];
        let mut t = Terminal::spawn("sh", &args, &Bus::default()).unwrap();
        t.resize(
            Size {
                columns: 77,
                lines: 22,
            },
            egui::vec2(8.0, 16.0),
        );
        t.send(b"\r".to_vec());
        wait_for("size", || screen_text(&t).contains("22 77"));
        t.shutdown();
    }

    #[test]
    fn a_missing_program_is_noticed() {
        // The pseudo-terminal's child reports this itself, or it fails to start at all.
        let args = Vec::new();
        if let Ok(t) = Terminal::spawn("/nonexistent/program", &args, &Bus::default()) {
            wait_for("exit", || t.ended().is_some());
        }
    }
}
