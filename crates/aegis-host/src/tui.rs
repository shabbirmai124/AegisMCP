use crate::audit::{AuditRecord, ChainVerificationReport, read_recent_records, verify_chain};
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum StatusFilter {
    All,
    Pass,
    Trapped,
    Blocked,
}

impl StatusFilter {
    fn next(self) -> Self {
        match self {
            Self::All => Self::Pass,
            Self::Pass => Self::Trapped,
            Self::Trapped => Self::Blocked,
            Self::Blocked => Self::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Pass => "Pass",
            Self::Trapped => "Trapped",
            Self::Blocked => "Blocked",
        }
    }
}

struct DashboardState {
    records: Vec<AuditRecord>,
    table_state: TableState,
    filter: StatusFilter,
    chain_report: ChainVerificationReport,
    last_refresh: Instant,
    status_banner: String,
}

impl DashboardState {
    fn new(db_path: &Path) -> Result<Self> {
        let records = read_recent_records(db_path, 200).unwrap_or_default();
        let chain_report = verify_chain(db_path)?;
        let mut table_state = TableState::default();
        if !records.is_empty() {
            table_state.select(Some(0));
        }
        Ok(Self {
            records,
            table_state,
            filter: StatusFilter::All,
            chain_report,
            last_refresh: Instant::now(),
            status_banner: "Live WAL polling active".to_string(),
        })
    }

    fn filtered_records(&self) -> Vec<&AuditRecord> {
        self.records
            .iter()
            .filter(|r| match self.filter {
                StatusFilter::All => true,
                StatusFilter::Pass => r.status == "Pass",
                StatusFilter::Trapped => r.status == "Trapped",
                StatusFilter::Blocked => r.status == "Blocked",
            })
            .collect()
    }

    fn refresh(&mut self, db_path: &Path) {
        if let Ok(recs) = read_recent_records(db_path, 200) {
            self.records = recs;
        }
        if let Ok(report) = verify_chain(db_path) {
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

fn status_style(status: &str) -> Style {
    match status {
        "Pass" => Style::default().fg(Color::Green),
        "Trapped" => Style::default().fg(Color::Yellow),
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
                    state.filter = state.filter.next();
                    state.table_state.select(if state.filtered_records().is_empty() {
                        None
                    } else {
                        Some(0)
                    });
                    state.status_banner = format!("Filter: {}", state.filter.label());
                }
                KeyCode::Char('v') => match verify_chain(db_path) {
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
    let pass_runs = state.records.iter().filter(|r| r.status == "Pass").count();
    let blocked_or_trapped = total_runs.saturating_sub(pass_runs);
    let cache_hits = state.records.iter().filter(|r| r.cache_hit).count();
    let cache_hit_pct = if total_runs == 0 {
        0.0
    } else {
        (cache_hits as f64 / total_runs as f64) * 100.0
    };
    let mean_us = if total_runs == 0 {
        0
    } else {
        state.records.iter().map(|r| r.duration_us).sum::<u64>() / (total_runs as u64)
    };

    let chain_badge = if state.chain_report.valid {
        Span::styled(
            " VERIFIED ",
            Style::default()
                .bg(Color::Green)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " TAMPER DETECTED ",
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
            "| DB: {} | Total: {} | Pass: {} | Trapped/Blocked: {} | Cache: {:.1}% | Mean: {:.2}ms | ",
            db_path.display(),
            total_runs,
            pass_runs,
            blocked_or_trapped,
            cache_hit_pct,
            mean_us as f64 / 1000.0,
        )),
        chain_badge,
    ]))
    .block(Block::default().borders(Borders::ALL).title("KPI Header"));
    frame.render_widget(header, chunks[0]);

    let metrics_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Percentage(35),
            Constraint::Percentage(30),
        ])
        .split(chunks[1]);

    let fuel_spark: Vec<u64> = state
        .records
        .iter()
        .take(60)
        .rev()
        .map(|r| r.fuel_consumed / 1_000)
        .collect();
    let fuel_widget = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Fuel Burned (k-units)"),
        )
        .data(&fuel_spark)
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(fuel_widget, metrics_chunks[0]);

    let latency_spark: Vec<u64> = state
        .records
        .iter()
        .take(60)
        .rev()
        .map(|r| r.duration_us)
        .collect();
    let latency_widget = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Turnaround Latency (us)"),
        )
        .data(&latency_spark)
        .style(Style::default().fg(Color::Green));
    frame.render_widget(latency_widget, metrics_chunks[1]);

    let latest_peak_bytes = state
        .records
        .first()
        .map(|r| r.peak_memory_bytes)
        .unwrap_or(0);
    let cap_bytes = 32 * 1024 * 1024usize;
    let ram_ratio = (latest_peak_bytes as f64 / cap_bytes as f64).clamp(0.0, 1.0);
    let ram_mib = latest_peak_bytes as f64 / (1024.0 * 1024.0);
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Peak RAM"))
        .gauge_style(Style::default().fg(Color::Magenta))
        .ratio(ram_ratio)
        .label(format!("{ram_mib:.2} / 32.00 MiB"));
    frame.render_widget(gauge, metrics_chunks[2]);

    let filtered = state.filtered_records();
    let inspector_text = if let Some(idx) = state.table_state.selected()
        && let Some(rec) = filtered.get(idx)
    {
        format!(
            "Run ID: {} | Input SHA-256: {} | Output SHA-256: {}\nReceipt SHA-256: {}\nPrev Hash: {}\nTrap Diagnostic: {}",
            rec.run_id,
            rec.input_sha256,
            rec.output_sha256,
            rec.receipt_hash,
            rec.prev_hash,
            rec.trap_reason.as_deref().unwrap_or("None (Clean Pass)")
        )
    } else {
        "No executions recorded yet. Run `aegis-mcp serve` or invoke sandbox tools.".to_string()
    };

    let rows: Vec<Row> = filtered
        .iter()
        .map(|r| {
            let short_run: String = r.run_id.chars().take(12).collect();
            let ram_kb = r.peak_memory_bytes / 1024;
            let cache_label = if r.cache_hit { "Hit" } else { "Cold" };
            Row::new(vec![
                Cell::from(short_run),
                Cell::from(r.tool_name.clone()),
                Cell::from(r.tier.clone()),
                Cell::from(format!("{}", r.fuel_consumed)),
                Cell::from(format!("{ram_kb} KiB")),
                Cell::from(format!("{:.2} ms", r.duration_us as f64 / 1000.0)),
                Cell::from(cache_label),
                Cell::from(r.status.clone()).style(status_style(&r.status)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(22),
            Constraint::Length(18),
            Constraint::Length(12),
            Constraint::Length(11),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new([
            "Run ID",
            "Tool Name",
            "Tier",
            "Fuel Burned",
            "Peak RAM",
            "Duration",
            "Cache",
            "Status",
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
            .title(format!("Execution Stream [Filter: {}]", state.filter.label())),
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
                .title("Detail Inspector"),
        );
    frame.render_widget(inspector, chunks[3]);

    let footer = Paragraph::new(format!(
        "Keys: [j/k or Up/Down] Select | [f] Cycle Filter (All/Pass/Trapped/Blocked) | [v] Verify Hash Chain | [q] Quit  --  {}",
        state.status_banner
    ))
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, chunks[4]);
}
