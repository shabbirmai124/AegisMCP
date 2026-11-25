use crate::audit::{AuditRecord, ChainVerificationReport, read_recent_records, verify_sqlite_chain};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Gauge, Paragraph, Row, Sparkline, Table, TableState, Wrap,
};
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

struct DashboardState {
    records: Vec<AuditRecord>,
    table_state: TableState,
    blocked_only: bool,
    chain_report: ChainVerificationReport,
    last_refresh: Instant,
    status_banner: String,
}

impl DashboardState {
    fn new(db_path: &Path) -> Result<Self> {
        let records = read_recent_records(db_path, 200).unwrap_or_default();
        let chain_report = verify_sqlite_chain(db_path)?;
        let mut table_state = TableState::default();
        if !records.is_empty() {
            table_state.select(Some(0));
        }
        Ok(Self {
            records,
            table_state,
            blocked_only: false,
            chain_report,
            last_refresh: Instant::now(),
            status_banner: "Live polling active".to_string(),
        })
    }

    fn filtered_records(&self) -> Vec<&AuditRecord> {
        if self.blocked_only {
            self.records
                .iter()
                .filter(|r| r.classification != "Success")
                .collect()
        } else {
            self.records.iter().collect()
        }
    }

    fn refresh(&mut self, db_path: &Path) {
        if let Ok(recs) = read_recent_records(db_path, 200) {
            self.records = recs;
        }
        if let Ok(report) = verify_sqlite_chain(db_path) {
            self.chain_report = report;
        }
        let len = self.filtered_records().len();
        if len == 0 {
            self.table_state.select(None);
        } else if self.table_state.selected().is_none_or(|i| i >= len) {
            self.table_state.select(Some(0));
        }
        self.last_refresh = Instant::now();
    }

    fn next(&mut self) {
        let len = self.filtered_records().len();
        if len == 0 {
            return;
        }
        let next = match self.table_state.selected() {
            Some(i) => (i + 1).min(len - 1),
            None => 0,
        };
        self.table_state.select(Some(next));
    }

    fn prev(&mut self) {
        let len = self.filtered_records().len();
        if len == 0 {
            return;
        }
        let prev = match self.table_state.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };
        self.table_state.select(Some(prev));
    }
}

fn classification_style(classification: &str) -> Style {
    match classification {
        "Success" => Style::default().fg(Color::Green),
        "OutOfFuel" | "EpochTimeout" | "MemoryLimitExceeded" => {
            Style::default().fg(Color::Yellow)
        }
        _ => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

pub fn run_monitor_tui(db_path: &Path, refresh_ms: u64) -> Result<()> {
    let mut state = DashboardState::new(db_path)?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let refresh_interval = Duration::from_millis(refresh_ms.max(50));
    let res = run_event_loop(&mut terminal, &mut state, db_path, refresh_interval);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut DashboardState,
    db_path: &Path,
    refresh_interval: Duration,
) -> Result<()> {
    loop {
        if state.last_refresh.elapsed() >= refresh_interval {
            state.refresh(db_path);
        }

        terminal.draw(|frame| draw_ui(frame, state, db_path))?;

        let timeout = refresh_interval.saturating_sub(state.last_refresh.elapsed());
        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('j') | KeyCode::Down => state.next(),
                KeyCode::Char('k') | KeyCode::Up => state.prev(),
                KeyCode::Char('f') => {
                    state.blocked_only = !state.blocked_only;
                    state.table_state.select(if state.filtered_records().is_empty() {
                        None
                    } else {
                        Some(0)
                    });
                    state.status_banner = if state.blocked_only {
                        "Filter: Blocked / Trapped Only".to_string()
                    } else {
                        "Filter: All Executions".to_string()
                    };
                }
                KeyCode::Char('v') => match verify_sqlite_chain(db_path) {
                    Ok(report) => {
                        state.status_banner = report.message.clone();
                        state.chain_report = report;
                    }
                    Err(e) => {
                        state.status_banner = format!("Verification error: {e}");
                    }
                },
                _ => {}
            }
        }
    }
    Ok(())
}

fn draw_ui(frame: &mut ratatui::Frame<'_>, state: &mut DashboardState, db_path: &Path) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(10),
            Constraint::Length(7),
            Constraint::Length(2),
        ])
        .split(area);

    let total_runs = state.records.len();
    let blocked_runs = state
        .records
        .iter()
        .filter(|r| r.classification != "Success")
        .count();

    let chain_badge = if state.chain_report.valid {
        Span::styled(
            " CHAIN VERIFIED ",
            Style::default()
                .bg(Color::Green)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " CHAIN TAMPERED ",
            Style::default()
                .bg(Color::Red)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " AegisMCP Flight Recorder ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "| DB: {} | Runs: {} | Blocked: {} | ",
            db_path.display(),
            total_runs,
            blocked_runs
        )),
        chain_badge,
    ]))
    .block(Block::default().borders(Borders::ALL).title("Engine Status"));
    frame.render_widget(header, chunks[0]);

    let metrics_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(chunks[1]);

    let spark_data: Vec<u64> = state
        .records
        .iter()
        .take(60)
        .rev()
        .map(|r| r.fuel_consumed / 1000)
        .collect();
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Fuel Consumed (k-units, recent)"),
        )
        .data(&spark_data)
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(sparkline, metrics_chunks[0]);

    let latest_peak_bytes = state
        .records
        .first()
        .map(|r| r.peak_memory_bytes)
        .unwrap_or(0);
    let cap_bytes = 32 * 1024 * 1024usize;
    let ram_ratio = (latest_peak_bytes as f64 / cap_bytes as f64).clamp(0.0, 1.0);
    let ram_mib = latest_peak_bytes as f64 / (1024.0 * 1024.0);
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Latest Sandbox Peak RAM"),
        )
        .gauge_style(Style::default().fg(Color::Magenta))
        .ratio(ram_ratio)
        .label(format!("{ram_mib:.2} / 32.00 MiB"));
    frame.render_widget(gauge, metrics_chunks[1]);

    let filtered = state.filtered_records();
    let inspector_text = if let Some(idx) = state.table_state.selected()
        && let Some(rec) = filtered.get(idx)
    {
        format!(
            "ID: {} | Code SHA-256: {}\nPrev: {}\nHash: {}\nSummary: {}",
            rec.execution_id, rec.code_sha256, rec.prev_hash, rec.entry_hash, rec.summary
        )
    } else {
        "No executions recorded yet. Run `aegis-mcp serve` or invoke sandbox tools.".to_string()
    };

    let rows: Vec<Row> = filtered
        .iter()
        .map(|r| {
            let short_hash: String = r.entry_hash.chars().take(12).collect();
            let ram_kb = r.peak_memory_bytes / 1024;
            Row::new(vec![
                Cell::from(r.seq.to_string()),
                Cell::from(r.timestamp_utc.clone()),
                Cell::from(r.tool_name.clone()),
                Cell::from(r.policy_tier.clone()),
                Cell::from(r.classification.clone()).style(classification_style(&r.classification)),
                Cell::from(format!("{}", r.fuel_consumed)),
                Cell::from(format!("{ram_kb} KiB")),
                Cell::from(format!("{} ms", r.duration_ms)),
                Cell::from(short_hash),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(24),
            Constraint::Length(20),
            Constraint::Length(18),
            Constraint::Length(21),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(12),
        ],
    )
    .header(
        Row::new([
            "Seq",
            "UTC Timestamp",
            "Tool",
            "Tier",
            "Classification",
            "Fuel",
            "Peak RAM",
            "Time",
            "Receipt",
        ])
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Execution Audit Stream"),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_stateful_widget(table, chunks[2], &mut state.table_state);

    let inspector = Paragraph::new(inspector_text)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Receipt & Payload Inspector"),
        );
    frame.render_widget(inspector, chunks[3]);

    let footer = Paragraph::new(format!(
        "Keys: [j/k or Up/Down] Navigate | [f] Toggle Blocked Filter | [v] Verify Hash Chain | [q] Quit   —   {}",
        state.status_banner
    ))
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, chunks[4]);
}
