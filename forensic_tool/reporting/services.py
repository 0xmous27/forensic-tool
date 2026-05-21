"""
Forensic Report Generator.

Generates structured forensic reports in PDF and HTML formats.
Reports include:
  - Case summary (disk image metadata, integrity hash)
  - Timeline reconstruction
  - Detected anomalies per file
  - Evidence scores and classification
  - Final conclusion

PDF generation uses ReportLab for precise layout control.
HTML reports are rendered via Django templates.
"""

import logging
import io
from datetime import datetime

from django.utils import timezone

from core.models import DiskImage, ForgeryResult, TimelineEntry

logger = logging.getLogger(__name__)


def generate_html_report(disk_image: DiskImage, investigator=None) -> str:
    """
    Generate a complete HTML forensic report as a string.
    investigator: Django User object (optional) — included in report header.
    """
    from django.template.loader import render_to_string
    import json

    results = ForgeryResult.objects.filter(disk_image=disk_image).order_by('-forgery_score')
    timeline = TimelineEntry.objects.filter(disk_image=disk_image).order_by('event_time')[:500]

    forged = results.filter(classification='forged')
    suspicious = results.filter(classification='suspicious')
    genuine = results.filter(classification='genuine')

    if forged.count() > 0:
        conclusion = (
            f"FORGERY DETECTED: {forged.count()} file(s) show strong evidence of timestamp "
            f"manipulation. {suspicious.count()} file(s) are suspicious and require further review."
        )
        verdict = 'forged'
    elif suspicious.count() > 0:
        conclusion = (
            f"SUSPICIOUS ACTIVITY: {suspicious.count()} file(s) show timestamp anomalies "
            "that may indicate manipulation. No definitive forgery confirmed."
        )
        verdict = 'suspicious'
    else:
        conclusion = (
            "NO FORGERY DETECTED: All analyzed files appear to have consistent timestamps "
            "across multiple forensic artifact sources."
        )
        verdict = 'genuine'

    # Chart data
    score_buckets = [0] * 10
    for r in results.values_list('forgery_score', flat=True):
        score_buckets[min(int(r // 10), 9)] += 1

    top10 = list(results[:10].values('file_name', 'forgery_score', 'classification'))

    chart_data = json.dumps({
        'classification': {
            'forged': forged.count(),
            'suspicious': suspicious.count(),
            'genuine': genuine.count(),
        },
        'score_buckets': score_buckets,
        'top10': top10,
    })

    context = {
        'disk_image': disk_image,
        'results': results,
        'timeline': timeline,
        'forged_count': forged.count(),
        'suspicious_count': suspicious.count(),
        'genuine_count': genuine.count(),
        'total_count': results.count(),
        'conclusion': conclusion,
        'verdict': verdict,
        'generated_at': timezone.now(),
        'investigator': investigator,
        'chart_data_json': chart_data,
    }
    return render_to_string('reporting/report_template.html', context)


def generate_pdf_report(disk_image: DiskImage, investigator=None) -> bytes:
    """
    Generate a PDF forensic report using ReportLab.
    Returns the PDF as bytes.
    """
    import io as _io
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, Image
    )

    def make_chart(chart_type, data):
        """Generate matplotlib chart as ReportLab Image."""
        fig, ax = plt.subplots(figsize=(6, 3), dpi=100)
        fig.patch.set_facecolor('white')
        ax.set_facecolor('white')

        if chart_type == 'pie':
            labels, values, colors_list = data
            ax.pie(values, labels=labels, autopct='%1.1f%%', colors=colors_list, startangle=90)
            ax.axis('equal')
        elif chart_type == 'bar':
            labels, values, colors_list = data
            ax.bar(labels, values, color=colors_list)
            ax.set_xlabel('Score Range', fontsize=9)
            ax.set_ylabel('Files', fontsize=9)
            ax.tick_params(labelsize=8)
            plt.xticks(rotation=45, ha='right')
        elif chart_type == 'barh':
            labels, values, colors_list = data
            ax.barh(labels, values, color=colors_list)
            ax.set_xlabel('Forgery Score', fontsize=9)
            ax.tick_params(labelsize=8)
            ax.set_xlim(0, 100)

        plt.tight_layout()
        buf = _io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', facecolor='white')
        plt.close(fig)
        buf.seek(0)
        return Image(buf, width=14*cm, height=7*cm)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'ForensicTitle',
        parent=styles['Title'],
        fontSize=18,
        spaceAfter=12,
        textColor=colors.HexColor('#1a1a2e'),
    )
    heading_style = ParagraphStyle(
        'ForensicHeading',
        parent=styles['Heading2'],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=6,
        textColor=colors.HexColor('#16213e'),
    )
    body_style = styles['Normal']
    small_style = ParagraphStyle('Small', parent=styles['Normal'], fontSize=8)

    results = ForgeryResult.objects.filter(disk_image=disk_image).order_by('-forgery_score')
    timeline = TimelineEntry.objects.filter(disk_image=disk_image).order_by('event_time')[:100]

    forged_count = results.filter(classification='forged').count()
    suspicious_count = results.filter(classification='suspicious').count()
    genuine_count = results.filter(classification='genuine').count()

    story = []

    # --- Title Page ---
    story.append(Paragraph("FORENSIC INVESTIGATION REPORT", title_style))
    story.append(Paragraph("Automated NTFS Timestamp Forgery Detection", heading_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0f3460')))
    story.append(Spacer(1, 0.5 * cm))

    # Case metadata table
    investigator_name = investigator.get_full_name() or investigator.username if investigator else 'N/A'
    investigator_id = (getattr(investigator, 'profile', None) and investigator.profile.investigator_id) or 'N/A' if investigator else 'N/A'
    meta_data = [
        ['Case / Image Name:', disk_image.name],
        ['File Size:', f"{disk_image.file_size / (1024**2):.2f} MB"],
        ['Hash Algorithm:', disk_image.hash_algorithm.upper()],
        ['Hash:', disk_image.sha256_hash or 'Not computed'],
        ['Hash Notes:', disk_image.notes or ''],
        ['Upload Date:', disk_image.uploaded_at.strftime('%Y-%m-%d %H:%M:%S UTC')],
        ['Analysis Date:', disk_image.processed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if disk_image.processed_at else 'N/A'],
        ['Report Generated:', timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
        ['Investigator Name:', investigator_name],
        ['Investigator ID:', investigator_id],
        ['Tool:', 'Automated Digital Forensic Tool v1.0 — Group 15, UDOM'],
    ]
    meta_table = Table(meta_data, colWidths=[5 * cm, 12 * cm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f4f8')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('WORDWRAP', (1, 0), (1, -1), True),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5 * cm))

    # --- Executive Summary ---
    story.append(Paragraph("1. Executive Summary", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))

    summary_data = [
        ['Total Files Analyzed', str(results.count())],
        ['Forged', str(forged_count)],
        ['Suspicious', str(suspicious_count)],
        ['Genuine', str(genuine_count)],
    ]
    summary_table = Table(summary_data, colWidths=[8 * cm, 4 * cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3 * cm))

    # Conclusion
    if forged_count > 0:
        conclusion_text = (
            f"<b>VERDICT: FORGERY DETECTED.</b> {forged_count} file(s) exhibit strong evidence "
            f"of timestamp manipulation. {suspicious_count} additional file(s) are suspicious."
        )
        verdict_color = colors.HexColor('#c0392b')
    elif suspicious_count > 0:
        conclusion_text = (
            f"<b>VERDICT: SUSPICIOUS.</b> {suspicious_count} file(s) show timestamp anomalies "
            "that may indicate manipulation. No definitive forgery confirmed."
        )
        verdict_color = colors.HexColor('#e67e22')
    else:
        conclusion_text = (
            "<b>VERDICT: GENUINE.</b> No timestamp forgery detected. All files show consistent "
            "timestamps across multiple forensic artifact sources."
        )
        verdict_color = colors.HexColor('#27ae60')

    verdict_style = ParagraphStyle(
        'Verdict', parent=body_style,
        textColor=verdict_color, fontSize=11, spaceBefore=6
    )
    story.append(Paragraph(conclusion_text, verdict_style))
    story.append(PageBreak())

    # --- Visual Analysis (Charts) ---
    story.append(Paragraph("2. Visual Analysis", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    story.append(Spacer(1, 0.3 * cm))

    # Pie chart
    story.append(Paragraph("Classification Breakdown", small_style))
    story.append(make_chart('pie', (
        ['Genuine', 'Suspicious', 'Forged'],
        [genuine_count, suspicious_count, forged_count],
        ['#27ae60', '#e67e22', '#c0392b'],
    )))
    story.append(Spacer(1, 0.4 * cm))

    # Score histogram
    story.append(Paragraph("Forgery Score Distribution", small_style))
    score_buckets = [0] * 10
    for r in results.values_list('forgery_score', flat=True):
        score_buckets[min(int(r // 10), 9)] += 1
    bucket_labels = ['0-10','10-20','20-30','30-40','40-50','50-60','60-70','70-80','80-90','90-100']
    bucket_colors = ['#27ae60' if i < 4 else '#e67e22' if i < 7 else '#c0392b' for i in range(10)]
    story.append(make_chart('bar', (bucket_labels, score_buckets, bucket_colors)))
    story.append(Spacer(1, 0.4 * cm))

    # Top 10 horizontal bar
    top10 = list(results[:10])
    if top10:
        story.append(Paragraph("Top 10 Files by Forgery Score", small_style))
        t10_labels = [r.file_name[:35] for r in reversed(top10)]
        t10_values = [r.forgery_score for r in reversed(top10)]
        t10_colors = ['#c0392b' if r.classification == 'forged' else '#e67e22' if r.classification == 'suspicious' else '#27ae60' for r in reversed(top10)]
        story.append(make_chart('barh', (t10_labels, t10_values, t10_colors)))

    story.append(PageBreak())

    # --- Forgery Results Table ---
    story.append(Paragraph("3. Forgery Detection Results", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))

    if results.exists():
        table_data = [['File Name', 'Score', 'Classification', 'Anomalies']]
        for r in results[:50]:  # Limit to 50 rows in PDF
            classification_display = r.classification.upper()
            table_data.append([
                Paragraph(r.file_name[:60], small_style),
                f"{r.forgery_score:.1f}",
                classification_display,
                str(len(r.anomalies)),
            ])

        results_table = Table(table_data, colWidths=[8 * cm, 2 * cm, 3.5 * cm, 2.5 * cm])
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(results_table)
    else:
        story.append(Paragraph("No results available. Run analysis and scoring first.", body_style))

    story.append(PageBreak())

    # --- Timeline Section ---
    story.append(Paragraph("4. Forensic Timeline (First 100 Events)", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))

    if timeline:
        tl_data = [['Timestamp (UTC)', 'Event Type', 'Source', 'File Name']]
        for entry in timeline:
            tl_data.append([
                entry.event_time.strftime('%Y-%m-%d %H:%M:%S'),
                entry.event_type.replace('_', ' ').title(),
                entry.source,
                Paragraph(entry.file_name[:50], small_style),
            ])
        tl_table = Table(tl_data, colWidths=[4.5 * cm, 3 * cm, 2.5 * cm, 6 * cm])
        tl_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
        ]))
        story.append(tl_table)
    else:
        story.append(Paragraph("No timeline data available.", body_style))

    story.append(PageBreak())

    # --- Anomaly Details ---
    story.append(Paragraph("5. Detected Anomalies", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))

    forged_results = results.filter(classification__in=['forged', 'suspicious'])[:20]
    for r in forged_results:
        story.append(Paragraph(f"<b>{r.file_name}</b> — Score: {r.forgery_score:.1f} ({r.classification.upper()})", body_style))
        for anomaly in r.anomalies:
            story.append(Paragraph(
                f"• [{anomaly.get('severity', '').upper()}] {anomaly.get('type', '')}: {anomaly.get('description', '')}",
                small_style
            ))
        story.append(Spacer(1, 0.2 * cm))

    # --- Footer note ---
    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    story.append(Paragraph(
        "This report was generated by the Automated Digital Forensic Tool — "
        "Group 15, Department of Computer Science and Engineering, University of Dodoma. "
        "Evidence integrity was maintained throughout analysis (read-only processing).",
        small_style
    ))

    doc.build(story)
    return buffer.getvalue()
