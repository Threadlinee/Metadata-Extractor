from tkinter import Tk, Label, Button, filedialog, Text, Frame, Scrollbar
from PIL import Image, ExifTags
from PyPDF2 import PdfReader
from docx import Document
from openpyxl import load_workbook
import os

def extract_image_metadata(file_path):
    metadata = []
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                metadata.append(f"{tag}: {value}")
        else:
            metadata.append("No EXIF metadata found.")
    except Exception as e:
        metadata.append(f"Error reading image metadata: {e}")
    return metadata

def extract_pdf_metadata(file_path):
    metadata = []
    try:
        reader = PdfReader(file_path)
        info = reader.metadata
        if info:
            for key, value in info.items():
                metadata.append(f"{key}: {value}")
        else:
            metadata.append("No PDF metadata found.")
    except Exception as e:
        metadata.append(f"Error reading PDF metadata: {e}")
    return metadata

def extract_docx_metadata(file_path):
    metadata = []
    try:
        doc = Document(file_path)
        core_props = doc.core_properties
        for prop in dir(core_props):
            if not prop.startswith('_') and not callable(getattr(core_props, prop)):
                value = getattr(core_props, prop)
                if value:
                    metadata.append(f"{prop}: {value}")
    except Exception as e:
        metadata.append(f"Error reading Word metadata: {e}")
    return metadata

def extract_xlsx_metadata(file_path):
    metadata = []
    try:
        wb = load_workbook(file_path)
        props = wb.properties
        for prop in dir(props):
            if not prop.startswith('_') and not callable(getattr(props, prop)):
                value = getattr(props, prop)
                if value:
                    metadata.append(f"{prop}: {value}")
    except Exception as e:
        metadata.append(f"Error reading Excel metadata: {e}")
    return metadata

def extract_metadata(file_path):
    ext = file_path.lower().split('.')[-1]
    if ext in ['jpg', 'jpeg', 'png', 'tiff']:
        return extract_image_metadata(file_path)
    elif ext == 'pdf':
        return extract_pdf_metadata(file_path)
    elif ext == 'docx':
        return extract_docx_metadata(file_path)
    elif ext == 'xlsx':
        return extract_xlsx_metadata(file_path)
    else:
        return ["Unsupported file type."]

def open_files():
    files = filedialog.askopenfilenames(title="Select Files")
    output.delete(1.0, "end")
    for file in files:
        output.insert("end", f"📄 File: {file}\n", "filename")
        metadata = extract_metadata(file)
        for line in metadata:
            output.insert("end", f"{line}\n")
        output.insert("end", "\n" + "-"*60 + "\n\n")

# GUI Setup
root = Tk()
root.title("Metadata Extractor Pro")
root.geometry("800x600")
root.config(bg="#1e1e2f")

title = Label(root, text="📂 Metadata Extractor Pro", font=("Helvetica", 20, "bold"), bg="#1e1e2f", fg="cyan")
title.pack(pady=20)

btn_frame = Frame(root, bg="#1e1e2f")
btn_frame.pack()

select_btn = Button(btn_frame, text="Select Files", command=open_files, font=("Helvetica", 14), bg="#444", fg="white", padx=20, pady=10)
select_btn.pack()

output_frame = Frame(root, bg="#1e1e2f")
output_frame.pack(pady=10, fill="both", expand=True)

scrollbar = Scrollbar(output_frame)
scrollbar.pack(side="right", fill="y")

output = Text(output_frame, wrap="word", font=("Courier", 11), yscrollcommand=scrollbar.set, bg="#121219", fg="#00FFAA", insertbackground='white')
output.pack(side="left", fill="both", expand=True)

output.tag_config("filename", foreground="cyan", font=("Courier", 11, "bold"))

scrollbar.config(command=output.yview)

root.mainloop()
