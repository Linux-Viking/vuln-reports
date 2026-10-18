"""Report writers. Each format lives in its own module and imports its optional
dependency (jinja2, weasyprint, openpyxl, python-docx, matplotlib) on its own, so
a missing library only disables that format."""
