import os

def get_content_stats(directory_path):
    char_counts = []
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    char_counts.append(len(content))
            except Exception:
                continue
    
    if char_counts:
        return {
            "largest_content_length": max(char_counts)
        }
    
if __name__=='__main__':
    print(get_content_stats("cloned_code"))
