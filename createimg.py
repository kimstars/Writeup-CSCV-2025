import os
import shutil
import re
import sys


if len(sys.argv) != 2:
    print("Usage: createimg <host> ")
    exit(0)



FILE_NAME = sys.argv[1]

FOLDER_IMG = "image"

with open(FILE_NAME, "r", encoding="utf-8") as f:
    data = f.read()

# Tìm các đường dẫn chứa hình ảnh trong nội dung file readme.md
image_paths = re.findall(r'!\[.*?\]\((.*?)\)', data)

if not os.path.exists(FOLDER_IMG):
    os.makedirs(FOLDER_IMG)

for path in image_paths:
    if os.path.isabs(path):
        # Tạo tên file mới cho hình ảnh
        filename = os.path.basename(path)
        # Sao chép hình ảnh vào thư mục image
        shutil.copy(path, os.path.join(FOLDER_IMG, filename))
        # Sửa lại đường dẫn tương đối trong nội dung file readme.md
        new_path = "./"+ os.path.join(FOLDER_IMG, filename).replace("\\", "/")
        data = data.replace(path, new_path)

# Ghi lại nội dung đã được chỉnh sửa vào file readme.md
with open(FILE_NAME, "w", encoding="utf-8") as f:
    f.write(data)
