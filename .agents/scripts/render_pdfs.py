from pathlib import Path
import fitz

PDFS = [
    Path("attached_assets/محضر_اجتماع_1789389701401.pdf"),
    Path("attached_assets/نموذج_تقرير_فعالية_كشفية_2027-2026م__1789389701402.pdf"),
]

output_dir = Path(".agents/outputs/pdf-pages")
output_dir.mkdir(parents=True, exist_ok=True)

for pdf_path in PDFS:
    document = fitz.open(pdf_path)
    stem = pdf_path.stem
    print(f"{pdf_path.name}: {len(document)} page(s)")
    for page_number, page in enumerate(document, start=1):
        print(f"  page {page_number}: {page.rect.width:.0f} x {page.rect.height:.0f} pt")
        pixmap = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
        output_path = output_dir / f"{stem}-page-{page_number}.png"
        pixmap.save(output_path)
        print(f"    rendered: {output_path}")