use chrono::Local;
use msas_core::{Findings, Severity};
use printpdf::*;
use std::collections::BTreeMap;
use std::io::Write;


fn rgb(r: f32, g: f32, b: f32) -> Color {
    Color::Rgb(Rgb::new(r, g, b, None))
}

fn severity_color(severity: &Severity) -> Color {
    match severity {
        Severity::Critical => rgb(1.0, 0.784, 0.784),
        Severity::High => rgb(1.0, 0.863, 0.863),
        Severity::Medium => rgb(1.0, 1.0, 0.784),
        Severity::Low => rgb(0.863, 0.941, 1.0),
        Severity::Info => rgb(0.941, 0.941, 0.941),
    }
}

/// Single line of text at absolute coordinates via a builtin font.
fn text_op(text: impl Into<String>, size: f32, x: Mm, y: Mm) -> Vec<Op> {
    let pos = Point {
        x: x.into(),
        y: y.into(),
    };
    let handle = PdfFontHandle::Builtin(BuiltinFont::Helvetica);
    vec![
        Op::StartTextSection,
        Op::SetFont {
            font: handle,
            size: Pt(size),
        },
        Op::SetTextCursor { pos },
        Op::ShowText {
            items: vec![TextItem::Text(text.into())],
        },
        Op::EndTextSection,
    ]
}

/// Filled rectangle (no stroke).
fn rect_ops(x: Mm, y: Mm, w: Mm, h: Mm, color: Color) -> Vec<Op> {
    let pts = vec![
        LinePoint {
            p: Point::new(x, y),
            bezier: false,
        },
        LinePoint {
            p: Point::new(x + w, y),
            bezier: false,
        },
        LinePoint {
            p: Point::new(x + w, y + h),
            bezier: false,
        },
        LinePoint {
            p: Point::new(x, y + h),
            bezier: false,
        },
    ];
    let polygon = Polygon {
        rings: vec![PolygonRing { points: pts }],
        mode: PaintMode::Fill,
        winding_order: WindingOrder::NonZero,
    };
    vec![
        Op::SaveGraphicsState,
        Op::SetFillColor { col: color },
        Op::DrawPolygon { polygon },
        Op::RestoreGraphicsState,
    ]
}

/// `PageBuilder` representation
struct PageBuilder {
    pages: Vec<PdfPage>,
    ops: Vec<Op>,
    y: Mm,
}

impl PageBuilder {
    fn new() -> Self {
        Self {
            pages: Vec::new(),
            ops: Vec::new(),
            y: Mm(270.0),
        }
    }

    fn flush_page(&mut self) {
        let ops = std::mem::take(&mut self.ops);
        self.pages.push(PdfPage::new(Mm(210.0), Mm(297.0), ops));
        self.y = Mm(270.0);
    }

    fn ensure_space(&mut self, needed: Mm) {
        if self.y < Mm(20.0) + needed {
            self.flush_page();
        }
    }

    fn text(&mut self, s: impl Into<String>, size: f32, x: Mm) {
        let y = self.y;
        self.ops.extend(text_op(s, size, x, y));
    }

    fn advance(&mut self, dy: Mm) {
        self.y -= dy;
    }

    fn rect_bg(&mut self, x: Mm, h: Mm, color: Color) {
        let y = self.y - Mm(8.0);
        let w = Mm(195.0) - x;
        self.ops.extend(rect_ops(x, y, w, h, color));
    }

    fn finish(mut self) -> Vec<PdfPage> {
        if !self.ops.is_empty() {
            self.flush_page();
        }
        self.pages
    }
}


pub fn write_pdf_report<W: Write>(
    findings: &[Findings],
    mut writer: W,
) -> Result<(), Box<dyn std::error::Error>> {
    // `mut` because with_pages takes &mut self
    let mut doc = PdfDocument::new("MSAS Security Audit Report");

    let mut summary_ops: Vec<Op> = Vec::new();
    let mut y = Mm(250.0);

    summary_ops.extend(text_op("MSAS Security Audit Report", 24.0, Mm(20.0), y));
    y -= Mm(20.0);

    let date = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    summary_ops.extend(text_op(format!("Generated: {}", date), 12.0, Mm(20.0), y));
    y -= Mm(30.0);

    summary_ops.extend(text_op(
        format!("Total findings: {}", findings.len()),
        14.0,
        Mm(20.0),
        y,
    ));

    // sverity counts
    let mut severity_counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        *severity_counts
            .entry(format!("{:?}", f.severity))
            .or_insert(0) += 1;
    }
    y -= Mm(15.0);
    summary_ops.extend(text_op("Severity breakdown:", 12.0, Mm(20.0), y));
    y -= Mm(10.0);
    for (sev, count) in &severity_counts {
        summary_ops.extend(text_op(format!("  {}: {}", sev, count), 10.0, Mm(25.0), y));
        y -= Mm(8.0);
    }

    // compliance IDs
    let compliance_ids: Vec<String> = findings
        .iter()
        .filter_map(|f| f.compliance.as_ref())
        .flat_map(|v| v.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    if !compliance_ids.is_empty() {
        y -= Mm(10.0);
        summary_ops.extend(text_op("Compliance standards impacted:", 12.0, Mm(20.0), y));
        y -= Mm(10.0);
        for id in &compliance_ids {
            summary_ops.extend(text_op(format!("  \u{2022} {}", id), 10.0, Mm(25.0), y));
            y -= Mm(8.0);
        }
    }

    let summary_page = PdfPage::new(Mm(210.0), Mm(297.0), summary_ops);

    let mut pb = PageBuilder::new();
    pb.text("Detailed findings", 18.0, Mm(20.0));
    pb.advance(Mm(15.0));

    for f in findings {
        pb.ensure_space(Mm(38.0));

        pb.rect_bg(Mm(15.0), Mm(10.0), severity_color(&f.severity));

        pb.text(
            format!("[{:?}] {}: {}", f.severity, f.id, f.title),
            9.0,
            Mm(18.0),
        );
        pb.advance(Mm(8.0));

        pb.text(format!("Resource: {}", f.affected_resource), 8.0, Mm(25.0));
        pb.advance(Mm(6.0));

        pb.text(format!("Remediation: {}", f.remediation), 8.0, Mm(25.0));
        pb.advance(Mm(6.0));

        if let Some(comp) = &f.compliance {
            pb.text(format!("Compliance: {}", comp.join(", ")), 8.0, Mm(25.0));
            pb.advance(Mm(6.0));
        }

        pb.advance(Mm(8.0));
    }

    let mut all_pages = vec![summary_page];
    all_pages.extend(pb.finish());

    let mut warnings = Vec::new();
    let bytes = doc
        .with_pages(all_pages)
        .save(&PdfSaveOptions::default(), &mut warnings);

    writer.write_all(&bytes)?;
    Ok(())
}