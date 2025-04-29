from rope.base.project import Project
from rope.refactor.move import MoveModule
from rope.base import libutils
import os

# 1️⃣ Point this at your project root:
project_root = r'C:\Users\shant\Desktop\New folder (7)\test'
project = Project(project_root)

# 2️⃣ Define your source & destination _relative_ to project_root:
src_folder = 'quantcrypt'
dst_folder = 'standalone/quantcrypt'

# 3️⃣ Ensure the destination package exists (with __init__.py):
dst_abs = os.path.join(project_root, dst_folder)
os.makedirs(dst_abs, exist_ok=True)
init_py = os.path.join(dst_abs, '__init__.py')
if not os.path.exists(init_py):
    open(init_py, 'w').close()

# 4️⃣ Convert destination path to a Rope resource:
dst_parent = libutils.path_to_resource(project, dst_abs)

# 5️⃣ Loop through each .py in src, get its resource, move it, and fix imports:
for fname in os.listdir(os.path.join(project_root, src_folder)):
    if not fname.endswith('.py'):
        continue
    src_abs = os.path.join(project_root, src_folder, fname)
    resource = libutils.path_to_resource(project, src_abs)

    mover = MoveModule(project, resource)
    # ← here we pass _only_ dst_parent:
    changes = mover.get_changes(dst_parent)
    project.do(changes)

    print(f"✔ Moved {src_folder}/{fname} → {dst_folder}/{fname}")

project.close()
