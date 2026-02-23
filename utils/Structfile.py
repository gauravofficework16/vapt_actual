import os
from utils.Agentschema import VAPTState


IGNORE_DIRS = {
    ".git", ".idea", ".vscode", ".github",
    "node_modules", "venv", "env", ".venv",
    ".next", "dist", "build", "out", "__pycache__", ".pytest_cache",
    "media", "static", "public", "assets", "fonts", "images",
    "migrations"
}

IGNORE_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".mp4",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".bin", ".dll", ".so", ".pyc",
    "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "poetry.lock",
    #".md" #check
    
}

def get_tree_string(dir_path: str, prefix: str = "") -> str:
    output = ""
    try:
        entries = sorted([
            e for e in os.listdir(dir_path)
            if e not in IGNORE_DIRS
            and os.path.splitext(e)[1].lower() not in IGNORE_EXTS
        ])
    except PermissionError:
        return ""

    entries_count = len(entries)
    
    for i, entry in enumerate(entries):
        is_last = (i == entries_count - 1)
        connector = "└── " if is_last else "├── "
        
        output += f"{prefix}{connector}{entry}\n"
        
        full_path = os.path.join(dir_path, entry)
        if os.path.isdir(full_path):
            extension = "    " if is_last else "│   "
            output += get_tree_string(full_path, prefix + extension)
            
    return output

def generate_repo_structure(state: VAPTState) -> VAPTState:
    repo_path = state["repo_path"]
    file_struct_path = state["file_struct_path"]

    if not os.path.exists(repo_path):
        print(f"CRITICAL ERROR: Directory '{repo_path}' not found.")
        return state

    root_name = os.path.basename(os.path.abspath(repo_path))
    print(f"Generating optimized structure for: {root_name}...")
    
    tree_body = get_tree_string(repo_path)
    
    full_report = (
        "PROJECT DIRECTORY TREE \n"
        "NOTE: Context restricted to Application Logic. Excluded: Build Artifacts, Static Assets, External Dependencies, and Binaries.\n\n"
        "========================\n"
        f"Root: {root_name}/\n"
        f"{tree_body}"
    )

    output_dir = os.path.dirname(file_struct_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(file_struct_path, "w", encoding="utf-8") as f:
        f.write(full_report)

    return state

if __name__ == "__main__":
    real_repo_path = "cloned_code"      
    output_file = "repo_structure.txt"  

    state = {
        "repo_path": real_repo_path,
        "file_struct_path": output_file,
    }

    try:
        generate_repo_structure(state)
        
        if os.path.exists(output_file):
            print(f"Success! Optimized structure saved to: {output_file}")
            print("-" * 30)
            with open(output_file, "r", encoding="utf-8") as f:
                head = [next(f) for _ in range(25)]
                print("".join(head))
            print("..." + "-" * 30)
        else:
            print("Error: Output file not created.")

    except Exception as e:
        print(f"An error occurred: {e}")