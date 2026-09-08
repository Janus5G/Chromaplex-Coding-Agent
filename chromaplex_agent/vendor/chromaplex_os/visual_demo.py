"""
ChromaPlex OS - Visuel demonstration af laserbaseret krystaldata lagring.
Genererer et omfattende visualiseringsbillede der viser:
- De 5 bølgelængder og deres farver
- 3D krystal voxel-adressering
- Eksponentiel datakodningsproces
- Laser skrive/læse-operationer
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
from chromaplex_os.spec import (
    WAVELENGTHS, WAVELENGTH_LIST, COLOUR_NAMES, COLOUR_NAMES_REVERSE,
    encode_value, decode_value, DIM_X, DIM_Y, DIM_Z
)
from chromaplex_os.storage import CrystalStorage

WL_COLORS = {
    350: '#9B30FF',
    405: '#8A2BE2',
    473: '#1E90FF',
    532: '#00FF41',
    650: '#FF3333',
}

def draw_crystal_lattice(ax, storage_data):
    voxel_size = 1
    spacing = 1.2
    for (x, y, z), colors in storage_data.items():
        if x > 9 or y > 9 or z > 9:
            continue
        for color_idx, value in colors.items():
            if value == 0:
                continue
            wl = WAVELENGTH_LIST[color_idx]
            face_color = WL_COLORS[wl]
            verts = [
                [[x*spacing, y*spacing, z*spacing],
                 [x*spacing+voxel_size, y*spacing, z*spacing],
                 [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing],
                 [x*spacing, y*spacing+voxel_size, z*spacing]],
                [[x*spacing, y*spacing, z*spacing+voxel_size],
                 [x*spacing+voxel_size, y*spacing, z*spacing+voxel_size],
                 [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing+voxel_size],
                 [x*spacing, y*spacing+voxel_size, z*spacing+voxel_size]],
                [[x*spacing, y*spacing, z*spacing],
                 [x*spacing+voxel_size, y*spacing, z*spacing],
                 [x*spacing+voxel_size, y*spacing, z*spacing+voxel_size],
                 [x*spacing, y*spacing, z*spacing+voxel_size]],
                [[x*spacing+voxel_size, y*spacing, z*spacing],
                 [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing],
                 [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing+voxel_size],
                 [x*spacing+voxel_size, y*spacing, z*spacing+voxel_size]],
                [[x*spacing, y*spacing+voxel_size, z*spacing],
                 [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing],
                 [x*spacing+voxel_size, y*spacing+voxel_size, z*spacing+voxel_size],
                 [x*spacing, y*spacing+voxel_size, z*spacing+voxel_size]],
                [[x*spacing, y*spacing, z*spacing],
                 [x*spacing, y*spacing+voxel_size, z*spacing],
                 [x*spacing, y*spacing+voxel_size, z*spacing+voxel_size],
                 [x*spacing, y*spacing, z*spacing+voxel_size]],
            ]
            poly3d = Poly3DCollection(verts, alpha=0.7, linewidths=0.5, edgecolors='white')
            poly3d.set_facecolor(face_color)
            ax.add_collection3d(poly3d)

def create_visualization():
    storage = CrystalStorage(16, 16, 16)
    sample_data = {
        (2, 3, 1, 3): 1000,
        (5, 5, 5, 0): 50000,
        (3, 7, 2, 4): 75000,
        (8, 2, 4, 2): 2500,
        (1, 8, 3, 1): 12000,
        (6, 4, 6, 3): 8888,
        (9, 9, 9, 0): 99999,
        (4, 1, 7, 4): 33000,
    }
    for (x, y, z, color_idx), value in sample_data.items():
        encoded = encode_value(value)
        storage.write_voxel(x, y, z, color_idx, encoded)
    
    fig = plt.figure(figsize=(20, 14))
    fig.suptitle("ChromaPlex OS - Krystalbaseret Optisk Datalagringssystem", fontsize=18, fontweight='bold')
    
    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.3, wspace=0.3)
    
    ax1 = fig.add_subplot(gs[0, 0], projection='3d')
    ax1.set_title("3D Krystal Voxel Kort", fontsize=12, fontweight='bold')
    draw_crystal_lattice(ax1, storage.data)
    ax1.set_xlabel('X akse')
    ax1.set_ylabel('Y akse')
    ax1.set_zlabel('Z akse')
    ax1.set_xlim(0, 12)
    ax1.set_ylim(0, 12)
    ax1.set_zlim(0, 12)
    
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.axis('off')
    ax2.set_title("Eksponentiel Kodning", fontsize=12, fontweight='bold')
    value = 1234567
    packed = encode_value(value)
    e = (packed >> 24) & 0xFF
    remainder = packed & 0xFFFFFF
    ax2.text(0.5, 0.8, f"Originalt tal: {value:,}", fontsize=12, ha='center', transform=ax2.transAxes)
    ax2.text(0.5, 0.6, f"Kodet: 2^{e} + {remainder:,}", fontsize=11, ha='center', transform=ax2.transAxes)
    ax2.text(0.5, 0.4, f"Pakket (32-bit): 0x{packed:08X}", fontsize=10, ha='center', fontfamily='monospace', transform=ax2.transAxes)
    ax2.text(0.5, 0.2, f"32 bits per voxel × 5 farver = 160 bits/voxel", fontsize=10, ha='center', transform=ax2.transAxes)
    
    ax3 = fig.add_subplot(gs[1, 0])
    ax3.axis('off')
    ax3.set_title("Lasersystem Diagram", fontsize=12, fontweight='bold')
    ax3.set_xlim(0, 10)
    ax3.set_ylim(0, 6)
    laser = Circle((1.5, 3), 0.5, facecolor='red', edgecolor='darkred', linewidth=2, alpha=0.8)
    ax3.add_patch(laser)
    ax3.text(1.5, 3, "LASER", ha='center', va='center', fontsize=8, fontweight='bold', color='white')
    crystal_rect = Rectangle((4, 1.5), 2, 3, facecolor='lightyellow', edgecolor='orange', linewidth=2, alpha=0.5)
    ax3.add_patch(crystal_rect)
    ax3.text(5, 3, "KRYS\nTAL", ha='center', va='center', fontsize=9, fontweight='bold')
    camera_rect = Rectangle((7.5, 2), 1.5, 2, facecolor='lightgray', edgecolor='gray', linewidth=2, alpha=0.6)
    ax3.add_patch(camera_rect)
    ax3.text(8.25, 3, "KAMERA", ha='center', va='center', fontsize=8, fontweight='bold')
    ax3.annotate('', xy=(4, 3), xytext=(2, 3), arrowprops=dict(arrowstyle='->', lw=2, color='red'))
    ax3.annotate('', xy=(7.5, 3), xytext=(6, 3), arrowprops=dict(arrowstyle='->', lw=2, color='green'))
    ax3.text(5, 1, "1024³ × 5 farver = 5,3 mia. voxels", ha='center', fontsize=9, color='gray')
    
    ax4 = fig.add_subplot(gs[1, 1])
    ax4.axis('off')
    ax4.set_title("5 Multipleksede Bølgelængder", fontsize=12, fontweight='bold')
    wavelengths = [350, 405, 473, 532, 650]
    colors = [WL_COLORS[w] for w in wavelengths]
    names = ["UV - Højenergi", "Violet - Præcision", "Blå - Datalag 3", "Grøn - Standard", "Rød - Dybarkiv"]
    for i, (wl, color, name) in enumerate(zip(wavelengths, colors, names)):
        y = 4 - i
        rect = FancyBboxPatch((0.3, y-0.3), 3, 0.6, boxstyle="round,pad=0.05", facecolor=color, alpha=0.7, edgecolor='white')
        ax4.add_patch(rect)
        ax4.text(3.6, y, f"{wl}nm", fontsize=10, fontweight='bold', va='center', color=color)
        ax4.text(5.5, y, name, fontsize=9, va='center', color='gray')
    ax4.set_xlim(0, 10)
    ax4.set_ylim(-0.5, 5)
    
    legend_elements = [
        mpatches.Patch(facecolor=WL_COLORS[350], alpha=0.7, label='UV (350nm)'),
        mpatches.Patch(facecolor=WL_COLORS[405], alpha=0.7, label='Violet (405nm)'),
        mpatches.Patch(facecolor=WL_COLORS[473], alpha=0.7, label='Blå (473nm)'),
        mpatches.Patch(facecolor=WL_COLORS[532], alpha=0.7, label='Grøn (532nm)'),
        mpatches.Patch(facecolor=WL_COLORS[650], alpha=0.7, label='Rød (650nm)'),
    ]
    fig.legend(handles=legend_elements, loc='lower center', ncol=5, fontsize=10)
    
    plt.tight_layout()
    plt.savefig('chromaplex_visualization.png', dpi=150, bbox_inches='tight', facecolor='white')
    print("Visualisering gemt som 'chromaplex_visualization.png'")

if __name__ == "__main__":
    create_visualization()
    print("ChromaPlex OS Visuel Demonstration Fuldført!")
