
const fs = require('fs');
const path = require('path');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
  VerticalAlign, PageNumber, PageBreak, LevelFormat, Header, Footer,
} = require('docx');

const rawData = JSON.parse(fs.readFileSync('data/report_data.json','utf8'));
const { output_path, scan_date, findings, stats, severity_counts } = rawData;

const COLORS = {
  critical: 'C0392B', high: 'E74C3C', medium: 'E67E22',
  low:      'F1C40F', info: '3498DB', header: '1A1A2E',
  subhdr:   '16213E', accent: '0F3460', white: 'FFFFFF',
  lightgray:'F8F9FA', border: 'DEE2E6',
};

const border = { style: BorderStyle.SINGLE, size: 1, color: COLORS.border };
const borders = { top: border, bottom: border, left: border, right: border };

function hdrCell(text, w, color='1A1A2E') {
  return new TableCell({
    borders, width: { size: w, type: WidthType.DXA },
    shading: { fill: color, type: ShadingType.CLEAR },
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({ alignment: AlignmentType.CENTER,
      children: [new TextRun({ text, bold: true, color: COLORS.white, size: 18, font: 'Arial' })] })],
  });
}

function dataCell(text, w, color='F8F9FA', bold=false, textColor='000000') {
  return new TableCell({
    borders, width: { size: w, type: WidthType.DXA },
    shading: { fill: color, type: ShadingType.CLEAR },
    margins: { top: 60, bottom: 60, left: 100, right: 100 },
    children: [new Paragraph({ children: [
      new TextRun({ text: String(text||''), bold, color: textColor, size: 18, font: 'Arial' })
    ]})],
  });
}

function severityColor(sev) {
  const m = { Critical: COLORS.critical, High: COLORS.high, Medium: COLORS.medium, Low: COLORS.low };
  return m[sev] || COLORS.info;
}
function cvssRating(c) {
  if (c >= 9.0) return 'Critical'; if (c >= 7.0) return 'High';
  if (c >= 4.0) return 'Medium';   if (c > 0)    return 'Low';
  return 'Info';
}

// ── COVER PAGE ──────────────────────────────────
const coverPage = [
  new Paragraph({ spacing: { before: 2880 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: 'DIRECTORY TRAVERSAL', bold: true, size: 52, font: 'Arial', color: COLORS.header })] }),
  new Paragraph({ alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: 'VULNERABILITY ASSESSMENT REPORT', bold: true, size: 36, font: 'Arial', color: COLORS.accent })] }),
  new Paragraph({ spacing: { before: 480 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: '⚡ ML-Powered Security Analysis', size: 24, font: 'Arial', color: '7F8C8D', italics: true })] }),
  new Paragraph({ spacing: { before: 720 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: COLORS.accent, space: 1 } },
    children: [] }),
  new Paragraph({ spacing: { before: 480 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: `Report Date: ${scan_date}`, size: 22, font: 'Arial', color: '555555' })] }),
  new Paragraph({ spacing: { before: 200 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: `Classification: CONFIDENTIAL`, bold: true, size: 22, font: 'Arial', color: COLORS.critical })] }),
  new Paragraph({ children: [new PageBreak()] }),
];

// ── EXECUTIVE SUMMARY ───────────────────────────
const totalFindings = Object.values(severity_counts).reduce((a,b)=>a+b,0);
const riskLevel = severity_counts.critical > 0 ? 'CRITICAL' : severity_counts.high > 0 ? 'HIGH' : 'MEDIUM';
const riskColor = riskLevel === 'CRITICAL' ? COLORS.critical : riskLevel === 'HIGH' ? COLORS.high : COLORS.medium;

const execSummary = [
  new Paragraph({ heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text: '1. Executive Summary', font: 'Arial', bold: true, size: 32 })] }),
  new Paragraph({ spacing: { before: 200, after: 200 },
    children: [new TextRun({ text:
      `This report presents findings from an automated directory traversal vulnerability assessment ` +
      `conducted using ML-powered scanning technology. The scan identified ${totalFindings} findings ` +
      `across the target infrastructure, with an overall risk rating of `, size: 22, font: 'Arial' }),
      new TextRun({ text: riskLevel, bold: true, color: riskColor, size: 22, font: 'Arial' }),
      new TextRun({ text: '.', size: 22, font: 'Arial' })
    ]}),
];

// Risk summary table
const summaryTable = new Table({
  width: { size: 9360, type: WidthType.DXA },
  columnWidths: [2340, 2340, 2340, 2340],
  rows: [
    new TableRow({ children: [
      hdrCell('CRITICAL', 2340, COLORS.critical),
      hdrCell('HIGH', 2340, COLORS.high),
      hdrCell('MEDIUM', 2340, COLORS.medium),
      hdrCell('LOW', 2340, COLORS.low),
    ]}),
    new TableRow({ children: [
      dataCell(severity_counts.critical, 2340, 'FFF0F0', true, COLORS.critical),
      dataCell(severity_counts.high,     2340, 'FFF5F5', true, COLORS.high),
      dataCell(severity_counts.medium,   2340, 'FFFAF0', true, COLORS.medium),
      dataCell(severity_counts.low,      2340, 'FFFFF0', true, '7D6608'),
    ]}),
  ],
});

execSummary.push(summaryTable);
execSummary.push(new Paragraph({ spacing: { before: 400 },
  children: [new TextRun({ text: 'Scan Statistics', bold: true, size: 26, font: 'Arial' })] }));

const statsTable = new Table({
  width: { size: 9360, type: WidthType.DXA },
  columnWidths: [4680, 4680],
  rows: [
    new TableRow({ children: [ hdrCell('Metric', 4680), hdrCell('Value', 4680) ] }),
    ...Object.entries({
      'Total HTTP Requests':    stats.requests_made || 0,
      'Endpoints Discovered':   stats.endpoints_discovered || 0,
      'Scan Duration':          `${stats.scan_duration_sec || 0}s`,
      'ML Model':               'Ensemble (RF + GB + MLP + IsolationForest)',
      'Total Findings':         totalFindings,
    }).map(([k,v], i) => new TableRow({ children: [
      dataCell(k, 4680, i%2===0?'F8F9FA':'FFFFFF', true),
      dataCell(v, 4680, i%2===0?'F8F9FA':'FFFFFF'),
    ]})),
  ],
});

execSummary.push(statsTable);
execSummary.push(new Paragraph({ children: [new PageBreak()] }));

// ── ML ANALYSIS SECTION ─────────────────────────
const mlSection = [
  new Paragraph({ heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text: '2. ML-Assisted Analysis', bold: true, size: 32, font: 'Arial' })] }),
  new Paragraph({ spacing: { before: 200, after: 200 },
    children: [new TextRun({ text:
      'The scanner employs an ensemble of four machine learning models: Isolation Forest for anomaly ' +
      'detection, Random Forest Classifier, Gradient Boosting Classifier, and a Multi-Layer Perceptron ' +
      'neural network. Models are trained on synthetic data and then retrained in-session using real ' +
      'scan results, continuously improving detection accuracy.',
      size: 22, font: 'Arial' })] }),
  new Paragraph({ spacing: { before: 200 },
    children: [new TextRun({ text: 'Model Ensemble Architecture:', bold: true, size: 22, font: 'Arial' })] }),
  ...['Isolation Forest — Anomaly detection for unusual response patterns',
      'Random Forest (200 trees) — Supervised classification of traversal success',
      'Gradient Boosting (150 estimators) — Boosted ensemble for high-precision detection',
      'MLP Neural Network (128→64→32) — Deep pattern recognition in feature space',
  ].map(t => new Paragraph({ spacing: { before: 80 },
    numbering: { reference: 'bullets', level: 0 },
    children: [new TextRun({ text: t, size: 20, font: 'Arial' })] })),
  new Paragraph({ children: [new PageBreak()] }),
];

// ── DETAILED FINDINGS ───────────────────────────
const findingSection = [
  new Paragraph({ heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text: '3. Detailed Findings', bold: true, size: 32, font: 'Arial' })] }),
];

if (findings.length === 0) {
  findingSection.push(new Paragraph({ spacing: { before: 200 },
    children: [new TextRun({ text: 'No confirmed vulnerabilities found during this scan.', size: 22, font: 'Arial' })] }));
} else {
  findings.forEach((f, idx) => {
    const sev      = f.severity || 'Info';
    const sevColor = severityColor(sev);
    const mlConf   = f.ml_prediction ? `${(f.ml_prediction.confidence * 100).toFixed(1)}%` : 'N/A';
    const cvss     = typeof f.cvss === 'number' ? f.cvss.toFixed(1) : '0.0';
    const evidence = (f.evidence||[]).map(e=>e.indicator).join(', ') || 'ML-flagged anomaly';

    findingSection.push(
      new Paragraph({ spacing: { before: 400 }, heading: HeadingLevel.HEADING_2,
        children: [new TextRun({ text: `Finding #${idx+1}: ${sev} – ${f.category||'Unknown'}`,
          bold: true, size: 26, font: 'Arial', color: sevColor })] }),
    );

    const fTable = new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [2500, 6860],
      rows: [
        new TableRow({ children: [ hdrCell('Field', 2500), hdrCell('Value', 6860) ] }),
        ...([
          ['Target URL',      f.url || 'N/A'],
          ['Parameter',       f.parameter || 'N/A'],
          ['HTTP Method',     f.method || 'GET'],
          ['Payload',         f.payload || 'N/A'],
          ['Payload Category',f.payload_category || 'N/A'],
          ['Severity',        sev],
          ['CVSS Score',      `${cvss} (${cvssRating(parseFloat(cvss))})`],
          ['ML Confidence',   mlConf],
          ['Status Code',     String(f.status_code || 'N/A')],
          ['Response Size',   `${f.response_size || 0} bytes`],
          ['Evidence',        evidence],
          ['ML Flagged',      f.ml_flagged ? 'Yes (anomaly detected)' : 'No'],
        ].map(([k,v], i) => new TableRow({ children: [
          dataCell(k, 2500, i%2===0?'EBF5FB':'FFFFFF', true),
          dataCell(v, 6860, i%2===0?'EBF5FB':'FFFFFF',
            k==='Severity', k==='Severity' ? sevColor : '000000'),
        ]})))
      ],
    });

    findingSection.push(fTable);
  });
}
findingSection.push(new Paragraph({ children: [new PageBreak()] }));

// ── RECOMMENDATIONS ─────────────────────────────
const recommendations = [
  new Paragraph({ heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text: '4. Recommendations', bold: true, size: 32, font: 'Arial' })] }),
  ...([
    ['Input Validation & Sanitization', 'Implement strict allowlists for file paths. Reject any input containing traversal sequences (../, ..\\ , encoded variants). Use basename() or realpath() and verify the resolved path stays within the allowed directory.'],
    ['Disable Directory Listing', 'Ensure Apache/Nginx does not serve directory listings. In Apache: Options -Indexes. In Nginx: autoindex off.'],
    ['Use Chroot / Containers', 'Run web application processes in a chroot jail or container with minimal filesystem access. The process should have no visibility outside its document root.'],
    ['WAF Rules', 'Deploy ModSecurity or cloud WAF rules specifically targeting path traversal: CRS rules 930100, 930110, 930120, 930130.'],
    ['Least Privilege', 'Web server processes should run as low-privilege users with read-only access to only required directories.'],
    ['File Access Abstraction', 'Never pass user-supplied filenames directly to filesystem calls. Use an internal mapping or UUID to reference files.'],
    ['Security Headers', 'Implement X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, and Strict-Transport-Security headers.'],
    ['Regular Scanning', 'Schedule automated directory traversal scans as part of CI/CD pipeline and before each deployment.'],
  ].map(([title, body]) => [
    new Paragraph({ spacing: { before: 300 },
      children: [new TextRun({ text: title, bold: true, size: 22, font: 'Arial', color: COLORS.accent })] }),
    new Paragraph({ spacing: { before: 100, after: 200 },
      children: [new TextRun({ text: body, size: 20, font: 'Arial' })] }),
  ]).flat()),
];

// ── ASSEMBLE DOCUMENT ───────────────────────────
const doc = new Document({
  numbering: { config: [{
    reference: 'bullets',
    levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 720, hanging: 360 } } } }],
  }]},
  styles: {
    default: { document: { run: { font: 'Arial', size: 22 } } },
    paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 32, bold: true, font: 'Arial', color: COLORS.header },
        paragraph: { spacing: { before: 480, after: 240 }, outlineLevel: 0,
          border: { bottom: { style: BorderStyle.SINGLE, size: 3, color: COLORS.accent, space: 4 } } } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 26, bold: true, font: 'Arial' },
        paragraph: { spacing: { before: 360, after: 180 }, outlineLevel: 1 } },
    ],
  },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
      },
    },
    footers: {
      default: new Footer({ children: [
        new Paragraph({ alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: 'CONFIDENTIAL — Directory Traversal Scan Report  |  Page ', size: 18, font: 'Arial', color: '666666' }),
          new TextRun({ children: [PageNumber.CURRENT], size: 18, font: 'Arial', color: '666666' }),
        ]}),
      ]}),
    },
    children: [
      ...coverPage, ...execSummary, ...mlSection,
      ...findingSection, ...recommendations,
    ],
  }],
});

// ── TERMINAL FINDINGS SUMMARY ───────────────────
console.log('\n' + '='.repeat(70));
console.log('  DIRECTORY TRAVERSAL SCAN - FINDINGS SUMMARY');
console.log('='.repeat(70));
console.log(`  Scan Date  : ${scan_date}`);
console.log(`  Total      : ${totalFindings}  |  Risk Level: ${riskLevel}`);
console.log(`  Critical: ${severity_counts.critical}  High: ${severity_counts.high}  Medium: ${severity_counts.medium}  Low: ${severity_counts.low}`);
console.log('-'.repeat(70));

if (findings.length === 0) {
  console.log('  No confirmed vulnerabilities found.');
} else {
  findings.forEach((f, i) => {
    const sev    = f.severity || 'Info';
    const url    = f.url || 'N/A';
    const param  = f.parameter || 'N/A';
    const cvss   = typeof f.cvss === 'number' ? f.cvss.toFixed(1) : '0.0';
    const conf   = f.ml_prediction ? `${(f.ml_prediction.confidence * 100).toFixed(1)}%` : 'N/A';
    const evid   = (f.evidence||[]).map(e=>e.indicator).join(', ') || 'ML-flagged anomaly';
    const label  = sev.padEnd(8);
    console.log(`  [${String(i+1).padStart(2,'0')}] ${label} | CVSS ${cvss} | ML Conf: ${conf}`);
    console.log(`       URL   : ${url}`);
    console.log(`       Param : ${param}  |  Payload: ${(f.payload||'N/A').substring(0,60)}`);
    console.log(`       Evidence: ${evid}`);
    console.log('  ' + '-'.repeat(68));
  });
}
console.log('='.repeat(70) + '\n');

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync(output_path, buf);
  console.log('REPORT_OK:' + output_path);
}).catch(e => { console.error(e); process.exit(1); });
