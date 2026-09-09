import zipfile
import os

docs_dir = "C:/Users/ayila/OneDrive/Desktop/authgraph/Docs"
template_dir = os.path.join(docs_dir, "LaTeX_Template")
zip_path = os.path.join(docs_dir, "ICCIDSDT2027_Overleaf_Submission_Package.zip")

files_to_zip = [
    (os.path.join(docs_dir, "ICCIDSDT2027_Paper_LNCS.tex"), "main.tex"),
    (os.path.join(docs_dir, "ICCIDSDT2027_Paper_LNCS.tex"), "ICCIDSDT2027_Paper_LNCS.tex"),
    (os.path.join(template_dir, "llncs.cls"), "llncs.cls"),
    (os.path.join(template_dir, "splncs04.bst"), "splncs04.bst"),
    (os.path.join(docs_dir, "intro.png"), "intro.png"),
    (os.path.join(docs_dir, "architecture_diagram.png"), "architecture_diagram.png"),
    (os.path.join(docs_dir, "algorithm2.png"), "algorithm2.png"),
    (os.path.join(docs_dir, "algorithm.png"), "algorithm.png"),
    (os.path.join(docs_dir, "graph.png"), "graph.png"),
]

with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for src, arcname in files_to_zip:
        if os.path.exists(src):
            zipf.write(src, arcname)
            print(f"Added to zip: {arcname}")
        else:
            print(f"Warning: File not found {src}")

print(f"Successfully created Overleaf Submission Zip: {zip_path}")
