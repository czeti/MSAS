use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
};
use chrono::Local;

use msas_core::{Findings, Severity};
use serde::Serialize;
use tera::{Context, Tera};

const TEMPLATE: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>MSAS Security Audit Report</title>
    <style>
        body { font-family: sans-serif; margin: 2em; }
        h1 { color: #333; }
        .summary { margin: 1em 0; padding: 1em; background: #f0f0f0; border-radius: 5px; }
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 10px;
            margin: 1em 0;
        }
        .severity-item {
            text-align: center;
            padding: 10px;
            border-radius: 5px;
            background: white;
        }
        .severity-critical { background-color: #ffcccc; border-left: 4px solid #d9534f; }
        .severity-high { background-color: #ffdddd; border-left: 4px solid #f0ad4e; }
        .severity-medium { background-color: #ffffcc; border-left: 4px solid #f0ad4e; }
        .severity-low { background-color: #e6f3ff; border-left: 4px solid #5bc0de; }
        .severity-info { background-color: #f0f0f0; border-left: 4px solid #999; }
        .compliance-badge {
            display: inline-block;
            background: #333;
            color: white;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-right: 4px;
        }
        table { border-collapse: collapse; width: 100%; margin-top: 1em; }
        th, td { border: 1px solid #ccc; padding: 0.5em; text-align: left; }
        th { background: #e0e0e0; }
        .severity-critical td:first-child { background-color: #ffcccc; }
        .severity-high td:first-child { background-color: #ffdddd; }
        .severity-medium td:first-child { background-color: #ffffcc; }
        .severity-low td:first-child { background-color: #e6f3ff; }
        .severity-info td:first-child { background-color: #f0f0f0; }
    </style>
</head>
<body>
    <h1>MSAS Security Audit Report</h1>
    <div class="summary">
        <p><strong>Total findings:</strong> {{ findings | length }}</p>
        <p><strong>Generated:</strong> {{ date }}</p>

        <div class="severity-grid">
            {% for item in severity_counts %}
            <div class="severity-item severity-{{ item.severity | lower }}">
                <strong>{{ item.severity }}</strong><br>
                {{ item.count }}
            </div>
            {% endfor %}
        </div>

        {% if compliance_ids | length > 0 %}
        <div>
            <strong>Compliance standards impacted:</strong>
            <ul>
                {% for id in compliance_ids %}
                <li>{{ id }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
    </div>

    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>ID</th>
                <th>Title</th>
                <th>Resource</th>
                <th>Remediation</th>
                <th>Compliance</th>
            </tr>
        </thead>
        <tbody>
            {% for finding in findings %}
            <tr class="severity-{{ finding.severity | lower }}">
                <td>{{ finding.severity }}</td>
                <td>{{ finding.id }}</td>
                <td>{{ finding.title }}</td>
                <td>{{ finding.affected_resource }}</td>
                <td>{{ finding.remediation }}</td>
                <td>
                    {% if finding.compliance | length > 0 %}
                        {% for id in finding.compliance %}
                        <span class="compliance-badge">{{ id }}</span>
                        {% endfor %}
                    {% else %}
                        .
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>"#;

#[derive(Serialize)]
pub struct SeveritySummary {
    severity: Severity,
    count: usize,
}

pub fn write_html_report<W: Write>(
    findings: &[Findings],
    mut writer: W,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tera = Tera::default();
    tera.add_raw_template("report.html", TEMPLATE)?;

    let mut severity_count: BTreeMap<Severity, usize> = BTreeMap::new();
    let mut compliance_set: BTreeSet<String> = BTreeSet::new();
    let mut report_findings: Vec<Findings> = Vec::with_capacity(findings.len());

    for f in findings {
        *severity_count.entry(f.severity.clone()).or_insert(0) += 1;

        let compliance = f.compliance.clone().unwrap_or_default();
        for id in &compliance {
            compliance_set.insert(id.clone());
        }

        report_findings.push(Findings {
            id: f.id.clone(),
            title: f.title.clone(),
            severity: f.severity.clone(),
            affected_resource: f.affected_resource.clone(),
            remediation: f.remediation.clone(),
            compliance: Some(compliance.clone()),
        });
    }

    let severity_list: Vec<SeveritySummary> = severity_count
        .into_iter()
        .map(|(severity, count)| SeveritySummary { severity, count })
        .collect();

    let compliance_ids: Vec<String> = compliance_set.into_iter().collect();

    let mut context = Context::new();
    context.insert("findings", &report_findings);
    context.insert(
        "date",
        &Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    );
    context.insert("severity_counts", &severity_list);
    context.insert("compliance_ids", &compliance_ids);

    let rendered = tera
        .render("report.html", &context)
        .map_err(|e| format!("Failed to render 'report.html': {e}"))?;

    writer.write_all(rendered.as_bytes())?;
    Ok(())
}
