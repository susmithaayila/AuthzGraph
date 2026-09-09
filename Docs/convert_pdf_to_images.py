import fitz  # PyMuPDF
import os
import shutil

pdf_path = "C:/Users/ayila/OneDrive/Desktop/authgraph/Docs/ICCIDSDT2027_Paper_Preview.pdf"
output_dir = "C:/Users/ayila/OneDrive/Desktop/authgraph/Docs"
brain_dir = "C:/Users/ayila/.gemini/antigravity-ide/brain/f435f98d-2a59-4491-ac01-7c4c44a5c3f5"

doc = fitz.open(pdf_path)
print(f"Total pages in PDF: {len(doc)}")

page_files = []
for i, page in enumerate(doc):
    pix = page.get_pixmap(dpi=200)
    filename = f"pdf_page_{i+1}.png"
    filepath = os.path.join(output_dir, filename)
    pix.save(filepath)
    print(f"Saved page {i+1} image to: {filepath}")
    
    # Copy to brain dir for embedding in artifacts
    brain_filepath = os.path.join(brain_dir, filename)
    shutil.copy(filepath, brain_filepath)
    page_files.append(brain_filepath)

print("Finished rendering PDF page images!")
