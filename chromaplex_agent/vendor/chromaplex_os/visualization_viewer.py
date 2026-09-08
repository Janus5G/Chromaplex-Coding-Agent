"""
ChromaPlex OS Visualiseringsfremviser
Indlæser krystaldata genereret AF ChromaPlex-programmer og visualiserer det.
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, Circle, Rectangle
import numpy as np
from mpl_toolkits.mplot3d import Axes3D
from mpl_toolkits.mplot3d.art3d import Poly3DCollection
import matplotlib.gridspec as gridspec
import json
import sys
from chromaplex_os.spec import WAVELENGTHS, WAVELENGTH_LIST, COLOUR_NAMES_REVERSE, encode_value, decode_value

WL_COLORS = {
    350: '#9B30FF',
    405: '#8A2BE2',
    473: '#1E90FF',
    532: '#00FF41',
    650: '#FF3333',
}

def load_crystal_state(json_file):
    with open(json_file, 'r') as f:
        return json.load(f)

def create_crystal_visualization(crystal_data, output_file='chromaplex_crystal_viz.png'):
    fig = plt.figure(figsize=(20, 12))
    fig.suptitle("ChromaPlex OS - Krystaldata Visualisering\n(Data Genereret af ChromaPlex Program)", fontsize=16, fontweight='bold')
    
    ax1 = fig.add_subplot(231, projection='3d')
    ax1.set_title("3D Krystal Voxel Kort", fontsize=12, fontweight='bold')
    
    voxel_size = 0.8
    spacing = 1.0
    color_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    total_voxels = 0
    
    for key_str, colors in crystal_data.items():
        x, y, z = map(int, key_str.split(','))
        if x > 15 or y > 15 or z > 15:
            continue
        for color_idx_str, value in colors.items():
            color_idx = int(color_idx_str)
            value = int(value)
            if value == 0:
                continue
            wl = WAVELENGTH_LIST[color_idx]
            face_color = WL_COLORS[wl]
            color_counts[color_idx] += 1
            total_voxels += 1
            
            verts = [
                [[x*spacing, y*spacing, z*spacing], [x*spacing+voxel_size, y*spacing, z*spacing],
                 [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing], [x*spacing, y*spacing+voxel_size, z*spacing]],
                [[x*spacing, y*spacing, z*spacing+voxel_size], [x*spacing+voxel_size, y*spacing, z*spacing+voxel_size],
                 [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing+voxel_size], [x*spacing, y*spacing+voxel_size, z*spacing+voxel_size]],
                [[x*spacing, y*spacing, z*spacing], [x*spacing+voxel_size, y*spacing, z*spacing],
                 [x*spacing+voxel_size, y*spacing, z*spacing+voxel_size], [x*spacing, y*spacing, z*spacing+voxel_size]],
                [[x*spacing+voxel_size, y*spacing, z*spacing], [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing],
                 [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing+voxel_size], [x*spacing+voxel_size, y*spacing, z*spacing+voxel_size]],
                [[x*spacing, y*spacing+voxel_size, z*spacing], [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing],
                 [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing+voxel_size], [x*spacing, y*spacing+voxel_size, z*spacing+voxel_size]],
                [[x*spacing, y*spacing, z*spacing], [x*spacing, y*spacing+voxel_size, z*spacing],
                 [x*spacing, y*spacing+voxel_size, z*spacing+voxel_size], [x*spacing, y*spacing, z*spacing+voxel_size]],
            ]
            poly3d = Poly3DCollection(verts, alpha=0.7, linewidths=0.5, edgecolors='white')
            poly3d.set_facecolor(face_color)
            ax1.add_collection3d(poly3d)
    
    ax1.set_xlabel('X akse')
    ax1.set_ylabel('Y akse')
    ax1.set_zlabel('Z akse')
    ax1.set_xlim(0, 12)
    ax1.set_ylim(0, 12)
    ax1.set_zlim(0, 12)
    ax1.view_init(elev=25, azim=45)
    
    ax2 = fig.add_subplot(232)
    labels = ['UV (350nm)', 'Violet (405nm)', 'Blå (473nm)', 'Grøn (532nm)', 'Rød (650nm)']
    colors = [WL_COLORS[350], WL_COLORS[405], WL_COLORS[473], WL_COLORS[532], WL_COLORS[650]]
    sizes = [color_counts[i] for i in range(5)]
    if sum(sizes) > 0:
        ax2.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax2.set_title("Datafordeling per Bølgelængde", fontsize=12, fontweight='bold')
    
    ax3 = fig.add_subplot(233)
    x_pos = np.arange(len(WAVELENGTH_LIST))
    wl_labels = [f"{wl}nm" for wl in WAVELENGTH_LIST]
    ax3.bar(x_pos, [color_counts[i] for i in range(5)], color=[WL_COLORS[wl] for wl in WAVELENGTH_LIST])
    ax3.set_xticks(x_pos)
    ax3.set_xticklabels(wl_labels)
    ax3.set_ylabel('Antal Voxels')
    ax3.set_title("Voxels per Bølgelængde", fontsize=12, fontweight='bold')
    
    ax4 = fig.add_subplot(234)
    ax4.axis('off')
    ax4.set_title("Krystal Statistik", fontsize=12, fontweight='bold')
    stats_text = f"""Totalt Antal Voxels Skrevet: {total_voxels}
    
Pr. Bølgelængde:
  UV (350nm):     {color_counts[0]} voxels
  Violet (405nm): {color_counts[1]} voxels
  Blå (473nm):    {color_counts[2]} voxels
  Grøn (532nm):   {color_counts[3]} voxels
  Rød (650nm):    {color_counts[4]} voxels

Krystal Kapacitet: 1024³ × 5 farver = 5,3 mia. voxels
Hver voxel gemmer 32 bits via eksponentiel kodning
Teoretisk maks: ~21 GB/cm³"""
    ax4.text(0.1, 0.9, stats_text, fontsize=10, fontfamily='monospace', va='top', transform=ax4.transAxes)
    
    ax5 = fig.add_subplot(235)
    ax5.axis('off')
    ax5.set_title("Hvordan ChromaPlex Læser/Skriver", fontsize=12, fontweight='bold')
    ax5.set_xlim(0, 10)
    ax5.set_ylim(0, 6)
    laser = Circle((1.5, 3), 0.5, facecolor='red', edgecolor='darkred', linewidth=2, alpha=0.8)
    ax5.add_patch(laser)
    ax5.text(1.5, 3, "LASER", ha='center', va='center', fontsize=8, fontweight='bold', color='white')
    crystal_rect = Rectangle((4, 1.5), 2, 3, facecolor='lightyellow', edgecolor='orange', linewidth=2, alpha=0.5)
    ax5.add_patch(crystal_rect)
    ax5.text(5, 3, "KRYS\nTAL", ha='center', va='center', fontsize=9, fontweight='bold')
    camera_rect = Rectangle((7.5, 2), 1.5, 2, facecolor='lightgray', edgecolor='gray', linewidth=2, alpha=0.6)
    ax5.add_patch(camera_rect)
    ax5.text(8.25, 3, "KAMERA", ha='center', va='center', fontsize=8, fontweight='bold')
    ax5.annotate('', xy=(4, 3), xytext=(2, 3), arrowprops=dict(arrowstyle='->', lw=2, color='red'))
    ax5.annotate('', xy=(7.5, 3), xytext=(6, 3), arrowprops=dict(arrowstyle='->', lw=2, color='green'))
    
    ax6 = fig.add_subplot(236)
    ax6.axis('off')
    ax6.set_title("ChromaPlex Kode Der Genererede Dette", fontsize=12, fontweight='bold')
    code_lines = [
        "var data = 1234567;",
        "store data at (5,5,5) colour GREEN;",
        "store data at (5,5,5) colour UV;",
        "store data at (5,5,5) colour BLUE;",
        "store data at (5,5,5) colour RED;",
        "load result from (5,5,5) colour GREEN;",
        "print result;  // 1234567 ✓"
    ]
    for i, line in enumerate(code_lines):
        ax6.text(0.05, 0.9 - i*0.11, line, fontsize=9, fontfamily='monospace', transform=ax6.transAxes)
    
    legend_elements = [
        mpatches.Patch(facecolor=WL_COLORS[350], alpha=0.7, label='UV (350nm)'),
        mpatches.Patch(facecolor=WL_COLORS[405], alpha=0.7, label='Violet (405nm)'),
        mpatches.Patch(facecolor=WL_COLORS[473], alpha=0.7, label='Blå (473nm)'),
        mpatches.Patch(facecolor=WL_COLORS[532], alpha=0.7, label='Grøn (532nm)'),
        mpatches.Patch(facecolor=WL_COLORS[650], alpha=0.7, label='Rød (650nm)'),
    ]
    fig.legend(handles=legend_elements, loc='lower center', ncol=5, fontsize=10)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight', facecolor='white')
    print(f"Krystalvisualisering gemt som '{output_file}'")

def main():
    if len(sys.argv) < 2:
        print("Brug: python -m chromaplex_os.visualization_viewer <crystal_state.json>")
        sys.exit(1)
    crystal_file = sys.argv[1]
    crystal_data = load_crystal_state(crystal_file)
    create_crystal_visualization(crystal_data)
    print("Visualisering fuldført!")

if __name__ == "__main__":
    main()
