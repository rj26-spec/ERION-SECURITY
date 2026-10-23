import os
import re

files_to_update = [
    r"CyberGuard-Image-Detection\templates\admin_dashboard.html",
    r"CyberGuard-Image-Detection\templates\index.html",
    r"CyberGuard-Image-Detection\templates\login.html",
    r"cybervideo\templates\index.html",
    r"templates\admin_dashboard.html",
    r"templates\login.html"
]

logo_tag = '<img src="/static/logo.jpg" alt="Logo" style="height: 40px; vertical-align: middle; margin-right: 10px;">'
logo_tag_large = '<div style="display:flex; flex-direction:column; align-items:center; gap: 10px;"><img src="/static/logo.jpg" alt="Logo" style="height: 60px;">'
logo_tag_brand = '<div class="brand" style="display:flex; align-items:center;"><img src="/static/logo.jpg" alt="Logo" style="height: 40px; margin-right: 10px;">ERION <span>SECURITY</span></div>'

for f in files_to_update:
    if os.path.exists(f):
        with open(f, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Replace titles
        content = content.replace("CyberGuard | Admin Dashboard", "ERION SECURITY | Admin Dashboard")
        content = content.replace("CyberGuard - AI Security Analysis", "ERION SECURITY - AI Security Analysis")
        content = content.replace("CyberGuard - Login", "ERION SECURITY - Login")
        content = content.replace("CyberGuard | AI Video Detector", "ERION SECURITY | AI Video Detector")
        
        # Replace headers and branding
        content = content.replace('<div class="brand">Cyber<span>Guard</span></div>', logo_tag_brand)
        content = content.replace('Monitor your CyberGuard security', 'Monitor your ERION SECURITY environment')
        content = content.replace('<footer>CyberGuard Admin Dashboard</footer>', '<footer>ERION SECURITY Admin Dashboard</footer>')
        content = content.replace('<h1>CyberGuard</h1>', f'<h1>{logo_tag}ERION SECURITY</h1>')
        content = content.replace('CyberGuard\n        </div>', 'ERION SECURITY\n        </div>') # from image login.html
        content = content.replace('<h1>CYBERGUARD</h1>', f'<h1>{logo_tag}ERION SECURITY</h1>')
        content = content.replace('CyberGuard AI Security System', 'ERION SECURITY System')
        
        with open(f, 'w', encoding='utf-8') as file:
            file.write(content)
        print(f"Updated {f}")
