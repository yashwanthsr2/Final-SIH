import os, shutil

src_dir = r"C:\Users\sryas\.gemini\antigravity-ide\brain\ba351d89-3cd7-4cc5-86f4-c0231eb79518"
dest_dir = r"c:\Users\sryas\OneDrive\Desktop\SIH CYBER\CODEZILLA-SIH26145\scripts\presentation_assets"
os.makedirs(dest_dir, exist_ok=True)

files_to_copy = {
    "overview_dark": "overview_dark_mode_1789505596289.png",
    "overview_light": "overview_light_mode_1789505606483.png",
    "threat_center": "threat_center_page_1789277472864.png",
    "live_traffic": "live_traffic_flows_table_1789309280511.png",
    "network_graph": "network_graph_page_1789277488640.png",
    "trajectory": "trajectory_page_1789277499050.png",
    "model_center": "model_center_page_1789277511630.png",
    "settings_diag": "settings_diagnostics_1789505650950.png"
}

for key, fname in files_to_copy.items():
    src = os.path.join(src_dir, fname)
    dst = os.path.join(dest_dir, f"{key}.png")
    if os.path.exists(src):
        shutil.copyfile(src, dst)
        print(f"Copied {key} ({os.path.getsize(dst)} bytes)")
    else:
        print(f"Not found: {src}")
