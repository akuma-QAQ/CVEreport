#!/usr/bin/env python
# -*- coding: utf-8 -*-
import openpyxl
import os
import shutil
import re
from pathlib import Path

# 配置
EXCEL_FILE = 'cve申请2026.1.21.xlsx'
VULNERABILITY_DIR = '漏洞复现'
IMAGES_DIR = 'typora-user-images'
OUTPUT_BASE = 'D-link'

# 特殊映射：用于处理无法自动匹配的CVE
SPECIAL_MAPPING = {
    'CVE-2025-63301': 'linux：.md',  # D-Link DIR-852 漏洞
    'CVE-2025-70223': 'DIR513_formAdvNetwork.md',  # 明确映射
    'CVE-2025-70252': 'AC6_formWifiWpsStart.md',  # Tenda AC6
    'CVE-2026-24101': None,  # 暂无对应文件，跳过
}

def extract_images_from_md(md_file):
    """从markdown文件中提取图片文件名"""
    images = []
    with open(md_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 查找所有图片引用 ![...](imagename.png 或完整路径)
    pattern = r'!\[([^\]]*)\]\(([^)]+)\)'
    matches = re.findall(pattern, content)
    
    for alt_text, path in matches:
        # 从路径中提取文件名（即使是完整的Typora路径）
        filename = os.path.basename(path)
        if filename.endswith('.png'):
            images.append(filename)
    
    return list(set(images))  # 去重

def read_cve_data():
    """从Excel文件读取CVE数据"""
    wb = openpyxl.load_workbook(EXCEL_FILE)
    ws = wb.active
    
    cve_data = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        if row[0]:
            cve_num = str(row[0]).strip()
            component = str(row[1]).strip() if row[1] else ''
            firmware = str(row[2]).strip() if row[2] else ''
            cve_data[cve_num] = {
                'component': component,
                'firmware': firmware
            }
    
    return cve_data

def find_vulnerability_file(cve_num, component_path):
    """根据CVE编号和组件路径找到对应的漏洞复现文件"""
    
    # 优先检查特殊映射
    if cve_num in SPECIAL_MAPPING:
        mapped_file = SPECIAL_MAPPING[cve_num]
        if mapped_file:
            full_path = os.path.join(VULNERABILITY_DIR, mapped_file)
            if os.path.exists(full_path):
                return full_path
        else:
            return None
    
    # 处理多个组件的情况，用逗号或其他分隔符分割
    components = re.split(r'[,;，；]', component_path)
    
    for component in components:
        component = component.strip()
        
        # 去掉 goform/ 或 /goform/
        component = component.replace('goform/', '').replace('/goform/', '').strip()
        
        if not component:
            continue
        
        # 在漏洞复现文件夹中查找
        for filename in os.listdir(VULNERABILITY_DIR):
            if not filename.endswith('.md'):
                continue
            
            # 更灵活的匹配：检查组件名是否在文件名中（不区分大小写）
            if component.lower() in filename.lower():
                return os.path.join(VULNERABILITY_DIR, filename)
        
        # 如果找不到精确匹配，尝试模糊匹配
        for filename in os.listdir(VULNERABILITY_DIR):
            if not filename.endswith('.md'):
                continue
            
            # 检查文件名中是否包含组件的关键词
            component_words = component.split('_')
            if len(component_words) > 0:
                first_word = component_words[0]
                if first_word.lower() in filename.lower():
                    return os.path.join(VULNERABILITY_DIR, filename)
    
    return None

def read_vulnerability_content(vuln_file):
    """读取漏洞复现文件的内容，并将图片路径转换为相对路径"""
    with open(vuln_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 将图片引用路径转换为相对路径（只保留文件名）
    # 匹配 ![text](任意路径/图片名.png) 并转换为 ![text](图片名.png)
    content = re.sub(
        r'!\[([^\]]*)\]\([^)]*?([^/\\]*\.png)\)',
        r'![\1](\2)',
        content
    )
    
    return content

def create_cve_document(cve_num, cve_info):
    """为单个CVE创建文档"""
    component = cve_info['component']
    firmware = cve_info['firmware']
    
    # 查找对应的漏洞复现文件
    vuln_file = find_vulnerability_file(cve_num, component)
    
    if not vuln_file:
        print(f"⚠️  {cve_num}: 未找到漏洞复现文件 (component: {component[:40]})")
        return False
    
    # 创建CVE文件夹
    cve_folder = os.path.join(OUTPUT_BASE, cve_num)
    os.makedirs(cve_folder, exist_ok=True)
    
    # 提取漏洞复现文件中的图片文件名
    images = extract_images_from_md(vuln_file)
    
    # 复制图片到CVE文件夹
    copied_images = []
    missing_images = []
    
    for img_file in images:
        src_img = os.path.join(IMAGES_DIR, img_file)
        if os.path.exists(src_img):
            dst_img = os.path.join(cve_folder, img_file)
            shutil.copy2(src_img, dst_img)
            copied_images.append(img_file)
        else:
            missing_images.append(img_file)
    
    if missing_images:
        print(f"  ⚠️  缺失图片: {', '.join(missing_images[:3])}")
    
    # 读取漏洞复现内容并转换图片路径
    vuln_content = read_vulnerability_content(vuln_file)
    
    # 生成README.md
    readme_content = f"""# {cve_num} 漏洞信息

## 基础信息
- **CVE编号**: {cve_num}
- **影响组件**: {component}
- **固件版本**: {firmware}

## 漏洞详情

{vuln_content}
"""
    
    # 写入README.md
    readme_path = os.path.join(cve_folder, 'README.md')
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    print(f"✓ {cve_num}: 成功创建 ({len(copied_images)} 张图片) - 使用 {os.path.basename(vuln_file)}")
    return True

def main():
    """主函数"""
    print("="*70)
    print("CVE漏洞文档自动生成工具 v3.0 (已添加特殊映射)")
    print("="*70)
    
    # 读取CVE数据
    cve_data = read_cve_data()
    print(f"\n📊 读取到 {len(cve_data)} 条CVE记录\n")
    
    # 统计信息
    success = 0
    failed = 0
    
    # 为每个CVE创建文档
    for cve_num in sorted(cve_data.keys()):
        cve_info = cve_data[cve_num]
        if create_cve_document(cve_num, cve_info):
            success += 1
        else:
            failed += 1
    
    # 打印统计信息
    print("\n" + "="*70)
    print(f"📈 处理完成: 成功 {success}, 失败 {failed}, 总计 {len(cve_data)}")
    print("="*70)

if __name__ == '__main__':
    main()
