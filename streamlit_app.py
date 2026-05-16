"""
DEAD Sector Merger — $300 Data Recovery

Compares two copies of one or more binary dumps (firmware modules / system
files) sector-by-sector, merges non-DEAD sectors, and zero-fills sectors that
are DEAD in both copies.

Single-pair mode: drop two files (or a ZIP with two files) and get a hex-viewer
inspection plus two merged binary downloads.

Batch mode: drop a bunch of files / a ZIP of folders / multiple ZIPs and the
tool auto-pairs files using folder names (Copy 0 / Copy 1) or filename markers
(02x0.bad / 02x1.bad). Outputs are bundled into ZIPs.
"""
import io
import re
import zipfile
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import streamlit as st

# ============================================================================
# Config
# ============================================================================

st.set_page_config(
    page_title="Module Compare & Merge — $300 Data Recovery",
    page_icon="🔧",
    layout="wide",
)

PASSWORD = "11390"
SECTOR_SIZE = 512
DEAD_SECTOR = bytes([0xDE, 0xAD] * 256)

STATUS_MATCH = 0
STATUS_RECOVER_A = 1
STATUS_RECOVER_B = 2
STATUS_ZEROED = 3
STATUS_CONFLICT = 4

STATUS_LABELS = {
    STATUS_MATCH: "BOTH MATCH",
    STATUS_RECOVER_A: "RECOVERED FROM A",
    STATUS_RECOVER_B: "RECOVERED FROM B",
    STATUS_ZEROED: "ZEROED (BOTH DEAD)",
    STATUS_CONFLICT: "CONFLICT",
}

STATUS_COLORS = {
    STATUS_MATCH: "#4ade80",
    STATUS_RECOVER_A: "#4da3ff",
    STATUS_RECOVER_B: "#c084fc",
    STATUS_ZEROED: "#f87171",
    STATUS_CONFLICT: "#fbbf24",
}

FILTER_OPTIONS = {
    "All sectors": None,
    "Match only": [STATUS_MATCH],
    "Recovered from A only": [STATUS_RECOVER_A],
    "Recovered from B only": [STATUS_RECOVER_B],
    "Zeroed only": [STATUS_ZEROED],
    "Conflicts only": [STATUS_CONFLICT],
    "Dead in A (any)": [STATUS_ZEROED, STATUS_RECOVER_B],
    "Dead in B (any)": [STATUS_ZEROED, STATUS_RECOVER_A],
}

# Folder names like "Copy 0", "copy_1", "Copy-2", "COPY3"
COPY_FOLDER_RE = re.compile(r"^[Cc][Oo][Pp][Yy][\s_\-]*(\d+)$")

# Filename patterns where the copy marker is at the end (before extension)
COPY_FILENAME_PATTERNS = [
    # 02_copy0.bad / 02-copy-1.bad / 02 copy 0.bad
    re.compile(r"^(.+?)[_\-\s]+[Cc]opy[\s_\-]*(\d+)(\.[^./\\]*)?$"),
    # 02x0.bad / 02X1.bad
    re.compile(r"^(.+)[xX](\d+)(\.[^./\\]*)?$"),
    # 02_0.bad / 02-1.bad — last fallback, more aggressive
    re.compile(r"^(.+)[_\-](\d+)(\.[^./\\]*)?$"),
]

# ============================================================================
# Password gate
# ============================================================================

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.markdown("# 🔒 Module Compare & Merge")
    st.markdown("Restricted tool — password required.")
    pw = st.text_input("Password", type="password", key="pw_input")
    if pw:
        if pw == PASSWORD:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Incorrect password")
    st.stop()

# ============================================================================
# Helpers — formatting / pure
# ============================================================================

def format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.2f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.2f} MB"
    return f"{n / 1024 / 1024 / 1024:.2f} GB"


def pct(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{(n / total) * 100:.2f}%"


def is_zip_filename(name: str) -> bool:
    return name.lower().endswith(".zip")


# ============================================================================
# Smart A/B detection for the explicit "two-file" case
# ============================================================================

def detect_ab(name1: str, name2: str) -> Tuple[int, str]:
    """For exactly-two-files input. Returns (index_of_A, reason)."""
    base1 = re.sub(r"\.[^./\\]+$", "", name1)
    base2 = re.sub(r"\.[^./\\]+$", "", name2)

    # copy1 / copy2
    copy_re = re.compile(r"copy[\s_\-]*(\d+)", re.IGNORECASE)
    m1c = copy_re.search(base1)
    m2c = copy_re.search(base2)
    if m1c and m2c and m1c.group(1) != m2c.group(1):
        n1, n2 = int(m1c.group(1)), int(m2c.group(1))
        if n1 < n2:
            return 0, f'"copy{m1c.group(1)}" < "copy{m2c.group(1)}"'
        return 1, f'"copy{m2c.group(1)}" < "copy{m1c.group(1)}"'

    # _a / _b suffix
    ab_re = re.compile(r"[_\-\s.]([ab])(?=\.[^.]+$|$)", re.IGNORECASE)
    m1ab = ab_re.search(name1)
    m2ab = ab_re.search(name2)
    if m1ab and m2ab and m1ab.group(1).lower() != m2ab.group(1).lower():
        if m1ab.group(1).lower() == "a":
            return 0, f'"{m1ab.group(1)}" suffix vs "{m2ab.group(1)}"'
        return 1, f'"{m2ab.group(1)}" suffix vs "{m1ab.group(1)}"'

    # trailing number on common prefix
    i = 0
    while i < len(base1) and i < len(base2) and base1[i] == base2[i]:
        i += 1
    suf1, suf2 = base1[i:], base2[i:]
    num_re = re.compile(r"^[_\-\s.]?(\d+)$")
    m1n = num_re.match(suf1)
    m2n = num_re.match(suf2)
    if m1n and m2n:
        n1, n2 = int(m1n.group(1)), int(m2n.group(1))
        if n1 != n2:
            if n1 < n2:
                return 0, f"trailing #{m1n.group(1)} < #{m2n.group(1)}"
            return 1, f"trailing #{m2n.group(1)} < #{m1n.group(1)}"

    # lowest standalone digit
    nums1 = [int(x) for x in re.findall(r"\d+", base1)]
    nums2 = [int(x) for x in re.findall(r"\d+", base2)]
    if nums1 and nums2:
        min1, min2 = min(nums1), min(nums2)
        if min1 != min2:
            if min1 < min2:
                return 0, f"lowest number {min1} < {min2}"
            return 1, f"lowest number {min2} < {min1}"

    if name1.lower() <= name2.lower():
        return 0, "alphabetical fallback"
    return 1, "alphabetical fallback"


# ============================================================================
# Recursive flatten of arbitrary uploads (files + ZIPs)
# ============================================================================

def _skip_archive_entry(path: str, base: str) -> bool:
    if not base or base.startswith("."):
        return True
    if "__MACOSX" in path:
        return True
    return False


def flatten_inputs(uploaded_files) -> Tuple[List[Tuple[str, bytes]], List[str]]:
    """
    Walk uploaded files. ZIPs get expanded (one level deep).

    Returns (entries, errors). entries is a list of (relative_path, content_bytes).
    """
    entries: List[Tuple[str, bytes]] = []
    errors: List[str] = []

    for uf in uploaded_files:
        name = uf.name
        try:
            data = uf.getvalue()
        except Exception as e:
            errors.append(f"{name}: failed to read upload ({e})")
            continue

        if is_zip_filename(name):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for info in z.infolist():
                        if info.is_dir():
                            continue
                        path = info.filename
                        base = path.split("/")[-1]
                        if _skip_archive_entry(path, base):
                            continue
                        try:
                            entries.append((path, z.read(info)))
                        except Exception as e:
                            errors.append(f"{name}/{path}: {e}")
            except zipfile.BadZipFile:
                # Not actually a zip — treat as a plain binary
                entries.append((name, data))
        else:
            entries.append((name, data))
    return entries, errors


# ============================================================================
# Pairing logic — folder-based and filename-based
# ============================================================================

def _detect_copy_in_path(path: str) -> Optional[Tuple[str, int, str]]:
    """
    Look for a parent folder matching the Copy-N pattern.
    Returns (pair_key, copy_num, output_filename) or None.
    """
    parts = re.split(r"[/\\]", path)
    if len(parts) < 2:
        return None
    filename = parts[-1]
    folders = parts[:-1]
    for i, folder in enumerate(folders):
        m = COPY_FOLDER_RE.match(folder)
        if m:
            copy_num = int(m.group(1))
            remaining = folders[:i] + folders[i + 1:]
            pair_key = "folder::" + "/".join(remaining + [filename]).lower()
            return (pair_key, copy_num, filename)
    return None


def _detect_copy_in_filename(filename: str, folder_prefix: str) -> Optional[Tuple[str, int, str]]:
    """
    Look for a copy marker in the filename itself.
    Returns (pair_key, copy_num, output_filename) or None.
    """
    for pattern in COPY_FILENAME_PATTERNS:
        m = pattern.match(filename)
        if m:
            base = m.group(1)
            copy_num = int(m.group(2))
            ext = m.group(3) or ""
            # Sanity check on the copy number — anything > 99 is suspicious for a copy marker
            if copy_num > 99:
                continue
            out_name = base + ext
            key = "filename::" + (folder_prefix + "/" if folder_prefix else "") + out_name.lower()
            return (key, copy_num, out_name)
    return None


def classify_file(path: str) -> Optional[Tuple[str, str, int, str]]:
    """
    Returns (strategy, pair_key, copy_num, output_filename) or None.
    """
    folder_hit = _detect_copy_in_path(path)
    if folder_hit:
        pair_key, copy_num, out_name = folder_hit
        return ("folder", pair_key, copy_num, out_name)

    parts = re.split(r"[/\\]", path)
    filename = parts[-1]
    folder_prefix = "/".join(parts[:-1])
    fn_hit = _detect_copy_in_filename(filename, folder_prefix)
    if fn_hit:
        pair_key, copy_num, out_name = fn_hit
        return ("filename", pair_key, copy_num, out_name)

    return None


def find_pairs(entries: List[Tuple[str, bytes]]) -> Tuple[List[Dict], List[Tuple[str, str]]]:
    """
    Group entries into pairs.

    Returns:
        pairs: list of {out_name, name_a, name_b, data_a, data_b, strategy, copy_num_a, copy_num_b}
        unpaired: list of (path, reason)
    """
    groups: Dict[Tuple[str, str, str], List[Tuple[str, bytes, int]]] = defaultdict(list)
    unpaired: List[Tuple[str, str]] = []

    for path, content in entries:
        cls = classify_file(path)
        if cls is None:
            unpaired.append((path, "no copy pattern in path or filename"))
            continue
        strategy, key, copy_num, out_name = cls
        groups[(strategy, key, out_name)].append((path, content, copy_num))

    pairs: List[Dict] = []

    for (strategy, key, out_name), members in groups.items():
        members.sort(key=lambda x: x[2])
        if len(members) < 2:
            for path, _, _ in members:
                unpaired.append((path, "only one copy found; need 2"))
            continue
        a_path, a_data, a_num = members[0]
        b_path, b_data, b_num = members[1]
        if len(a_data) != len(b_data):
            unpaired.append((a_path, f"size mismatch with {b_path} ({len(a_data):,} vs {len(b_data):,})"))
            unpaired.append((b_path, f"size mismatch with {a_path}"))
            for path, _, _ in members[2:]:
                unpaired.append((path, "extra copy ignored"))
            continue
        if len(a_data) == 0 or len(a_data) % SECTOR_SIZE != 0:
            unpaired.append((a_path, f"file size {len(a_data):,} not aligned to {SECTOR_SIZE}-byte sectors"))
            unpaired.append((b_path, f"file size {len(b_data):,} not aligned to {SECTOR_SIZE}-byte sectors"))
            continue
        pairs.append({
            "out_name": out_name,
            "name_a": a_path,
            "name_b": b_path,
            "data_a": a_data,
            "data_b": b_data,
            "strategy": strategy,
            "copy_num_a": a_num,
            "copy_num_b": b_num,
            "status": None,
            "stats": None,
        })
        for path, _, _ in members[2:]:
            unpaired.append((path, f"extra copy ignored (already paired with copy {a_num} and {b_num})"))

    # Sort pairs by output name for stable display
    pairs.sort(key=lambda p: p["out_name"].lower())
    return pairs, unpaired


# ============================================================================
# Sector processing — pure functions
# ============================================================================

def process_one_pair(data_a: bytes, data_b: bytes) -> Tuple[bytes, Dict]:
    """Returns (status_bytes, stats_dict). Caller validated sizes."""
    total_sectors = len(data_a) // SECTOR_SIZE
    status = bytearray(total_sectors)
    stats = {
        "totalSectors": total_sectors,
        "totalBytes": len(data_a),
        "deadInA": 0,
        "deadInB": 0,
        "deadInBoth": 0,
        "matching": 0,
        "recoveredFromA": 0,
        "recoveredFromB": 0,
        "conflicts": 0,
    }
    mv_a = memoryview(data_a)
    mv_b = memoryview(data_b)
    for i in range(total_sectors):
        offset = i * SECTOR_SIZE
        sec_a = bytes(mv_a[offset:offset + SECTOR_SIZE])
        sec_b = bytes(mv_b[offset:offset + SECTOR_SIZE])
        a_dead = sec_a == DEAD_SECTOR
        b_dead = sec_b == DEAD_SECTOR
        if a_dead:
            stats["deadInA"] += 1
        if b_dead:
            stats["deadInB"] += 1
        if a_dead and b_dead:
            stats["deadInBoth"] += 1
            status[i] = STATUS_ZEROED
        elif a_dead:
            stats["recoveredFromB"] += 1
            status[i] = STATUS_RECOVER_B
        elif b_dead:
            stats["recoveredFromA"] += 1
            status[i] = STATUS_RECOVER_A
        elif sec_a == sec_b:
            stats["matching"] += 1
            status[i] = STATUS_MATCH
        else:
            stats["conflicts"] += 1
            status[i] = STATUS_CONFLICT
    return bytes(status), stats


def build_output(data_a: bytes, data_b: bytes, status: bytes, prefer_b: bool) -> bytes:
    out = bytearray(len(data_a))
    mv_a = memoryview(data_a)
    mv_b = memoryview(data_b)
    for i, s in enumerate(status):
        offset = i * SECTOR_SIZE
        if s == STATUS_ZEROED:
            continue
        if s == STATUS_MATCH or s == STATUS_RECOVER_A:
            out[offset:offset + SECTOR_SIZE] = mv_a[offset:offset + SECTOR_SIZE]
        elif s == STATUS_RECOVER_B:
            out[offset:offset + SECTOR_SIZE] = mv_b[offset:offset + SECTOR_SIZE]
        elif s == STATUS_CONFLICT:
            src = mv_b if prefer_b else mv_a
            out[offset:offset + SECTOR_SIZE] = src[offset:offset + SECTOR_SIZE]
    return bytes(out)


def build_zip(pairs: List[Dict], prefer_b: bool) -> bytes:
    """Bundle all merged outputs into a flat ZIP. Returns the ZIP bytes."""
    buf = io.BytesIO()
    used_names = set()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in pairs:
            if p["status"] is None:
                continue
            out = build_output(p["data_a"], p["data_b"], p["status"], prefer_b=prefer_b)
            name = p["out_name"]
            # Disambiguate collisions
            final_name = name
            n = 1
            while final_name in used_names:
                stem, dot, ext = name.rpartition(".")
                if dot:
                    final_name = f"{stem}_{n}.{ext}"
                else:
                    final_name = f"{name}_{n}"
                n += 1
            used_names.add(final_name)
            z.writestr(final_name, out)
    return buf.getvalue()


# ============================================================================
# Hex viewer rendering
# ============================================================================

def _hex_to_rgb(hex_color: str) -> str:
    h = hex_color.lstrip("#")
    return f"{int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)}"


def render_sector_block(sector_idx: int, data_a: bytes, data_b: bytes,
                        status: bytes, view_version: str) -> str:
    offset = sector_idx * SECTOR_SIZE
    s = status[sector_idx]
    label = STATUS_LABELS[s]
    color = STATUS_COLORS[s]
    rgb = _hex_to_rgb(color)

    if s == STATUS_ZEROED:
        display = None
    elif s in (STATUS_RECOVER_A, STATUS_MATCH):
        display = data_a
    elif s == STATUS_RECOVER_B:
        display = data_b
    else:
        display = data_a if view_version == "A" else data_b

    rows = []
    for row in range(SECTOR_SIZE // 16):
        row_off = offset + row * 16
        offset_hex = f"{row_off:010X}"
        hex_cells = []
        ascii_chars = []
        for b in range(16):
            byte_off = row_off + b
            byte = 0 if s == STATUS_ZEROED else display[byte_off]
            hex_str = f"{byte:02X}"
            if s == STATUS_CONFLICT and data_a[byte_off] != data_b[byte_off]:
                hex_cells.append(
                    f'<span style="background:rgba(251,191,36,0.25);color:#fbbf24;'
                    f'padding:0 1px;border-radius:2px">{hex_str}</span>'
                )
            else:
                hex_cells.append(hex_str)
            ascii_chars.append(chr(byte) if 0x20 <= byte <= 0x7E else ".")
        hex_str_full = " ".join(hex_cells[:8]) + "  " + " ".join(hex_cells[8:])
        ascii_html = "".join(ascii_chars).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        rows.append(
            f'<div style="white-space:pre">'
            f'<span style="color:#8b95a4">{offset_hex}</span>  '
            f'<span>{hex_str_full}</span>  '
            f'<span style="color:#8b95a4">{ascii_html}</span>'
            f'</div>'
        )

    return (
        f'<div style="margin-bottom:12px;padding:8px;border-radius:4px;'
        f'border-left:3px solid {color};background:rgba({rgb},0.05);'
        f'font-family:ui-monospace,\'SF Mono\',Menlo,monospace;font-size:12px;line-height:1.5">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;'
        f'color:#8b95a4;font-size:11px;margin-bottom:4px">'
        f'<span>Sector {sector_idx:,} — offset 0x{offset:X}</span>'
        f'<span style="font-weight:600;padding:2px 8px;border-radius:3px;'
        f'background:rgba({rgb},0.15);color:{color};font-size:10px;'
        f'text-transform:uppercase">{label}</span>'
        f'</div>'
        f'{"".join(rows)}'
        f'</div>'
    )


# ============================================================================
# Hex viewer (shared by single + batch modes)
# ============================================================================

def render_hex_viewer(pair: Dict):
    s = pair["stats"]
    status_bytes = pair["status"]
    total_sectors = s["totalSectors"]

    legend_html = '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;font-size:12px">'
    for color, label in [
        ("#4ade80", "Both match"),
        ("#4da3ff", "Recovered from A (B dead)"),
        ("#c084fc", "Recovered from B (A dead)"),
        ("#f87171", "Zeroed (both dead)"),
        ("#fbbf24", "Conflict"),
    ]:
        legend_html += (
            f'<div style="display:flex;align-items:center;gap:6px;color:#8b95a4">'
            f'<div style="width:12px;height:12px;border-radius:2px;background:{color}"></div>'
            f'{label}</div>'
        )
    legend_html += "</div>"
    st.markdown(legend_html, unsafe_allow_html=True)

    # Unique key per pair — using both source paths so two pairs that happen
    # to share an out_name (e.g., 02.BAD from different drive folders) don't
    # collide on Streamlit widget keys.
    pair_id = f"{pair['name_a']}::{pair['name_b']}"
    ctrl_cols = st.columns([2, 2, 1, 2, 1])
    with ctrl_cols[0]:
        view_version = st.radio(
            "Showing version", ["A", "B"], horizontal=True,
            help="Only matters for conflict sectors.",
            key=f"view_version_{pair_id}",
        )
    with ctrl_cols[1]:
        filter_label = st.selectbox(
            "Filter", list(FILTER_OPTIONS.keys()),
            key=f"filter_{pair_id}",
        )
    with ctrl_cols[2]:
        page_size = st.selectbox(
            "Sectors/page", [1, 4, 8, 16], index=1,
            key=f"page_size_{pair_id}",
        )
    with ctrl_cols[3]:
        jump_sector = st.number_input(
            "Jump to sector", min_value=0,
            max_value=max(0, total_sectors - 1), value=0, step=1,
            key=f"jump_{pair_id}",
        )
    with ctrl_cols[4]:
        st.markdown("&nbsp;")
        do_jump = st.button("Go", use_container_width=True, key=f"go_{pair_id}")

    allowed = FILTER_OPTIONS[filter_label]
    if allowed is None:
        filter_indices = None
        total_for_page = total_sectors
    else:
        allowed_set = set(allowed)
        filter_indices = [i for i, st_ in enumerate(status_bytes) if st_ in allowed_set]
        total_for_page = len(filter_indices)

    total_pages = max(1, -(-total_for_page // page_size))

    if do_jump:
        if filter_indices is None:
            st.session_state.page = jump_sector // page_size
        else:
            idx = next((k for k, v in enumerate(filter_indices) if v >= jump_sector), None)
            if idx is None:
                st.warning(f"No sector ≥ {jump_sector} matches the current filter.")
            else:
                st.session_state.page = idx // page_size

    if st.session_state.page >= total_pages:
        st.session_state.page = max(0, total_pages - 1)

    page_cols = st.columns([1, 4, 1])
    with page_cols[0]:
        if st.button("← Previous", disabled=(st.session_state.page == 0), key=f"prev_{pair_id}"):
            st.session_state.page = max(0, st.session_state.page - 1)
            st.rerun()
    with page_cols[1]:
        suffix = " (filtered)" if filter_indices is not None else ""
        st.markdown(
            f"<div style='text-align:center;color:#8b95a4;font-size:12px;"
            f"font-family:ui-monospace,monospace;padding-top:6px'>"
            f"Page {st.session_state.page + 1:,} of {total_pages:,} • "
            f"{total_for_page:,} sector{'s' if total_for_page != 1 else ''}{suffix}"
            f"</div>",
            unsafe_allow_html=True,
        )
    with page_cols[2]:
        if st.button("Next →", disabled=(st.session_state.page >= total_pages - 1), key=f"next_{pair_id}"):
            st.session_state.page = min(total_pages - 1, st.session_state.page + 1)
            st.rerun()

    start = st.session_state.page * page_size
    end = start + page_size
    if filter_indices is None:
        visible = list(range(start, min(end, total_sectors)))
    else:
        visible = filter_indices[start:end]

    if not visible:
        st.info("No sectors match the current filter.")
    else:
        html = '<div style="background:#0f1419;padding:12px;border-radius:6px;border:1px solid #2d3744">'
        for idx in visible:
            html += render_sector_block(
                idx, pair["data_a"], pair["data_b"], status_bytes, view_version,
            )
        html += "</div>"
        st.markdown(html, unsafe_allow_html=True)


# ============================================================================
# Session state init
# ============================================================================

for k, v in [
    ("pairs", None),                # list of pair dicts (None == not uploaded yet)
    ("unpaired", None),             # list of (path, reason)
    ("flatten_errors", None),       # list of error strings from ZIP read
    ("detection_msg", None),        # human-readable summary of detection
    ("current_pair_idx", 0),
    ("page", 0),
    ("last_upload_sig", None),
    ("explicit_a", None),           # (name, data) — File A single uploader
    ("explicit_b", None),           # (name, data) — File B single uploader
    ("last_a_sig", None),
    ("last_b_sig", None),
    ("processed", False),
]:
    if k not in st.session_state:
        st.session_state[k] = v


# ============================================================================
# UI — Title
# ============================================================================

st.title("🔧 Module Compare & Merge")
st.caption(
    "Compare copies of HDD firmware modules / system files sector-by-sector. "
    "Merge non-DEAD sectors, zero-fill double-DEAD sectors. "
    "Drop one pair or a whole folder of pairs. 512-byte sectors. "
    "DEAD = full sector of `DE AD DE AD ...`"
)

# ============================================================================
# UI — Upload
# ============================================================================

with st.container(border=True):
    st.markdown("**📦 Drop files, folders (as a ZIP), or multiple ZIPs**")
    st.caption(
        "Pairs are detected by either folder structure (e.g. `Copy 0/02.BAD` ↔ "
        "`Copy 1/02.BAD`) or filename markers (e.g. `02x0.bad` ↔ `02x1.bad`, "
        "or `02_copy0.bad` ↔ `02_copy1.bad`). Unpaired files are listed below."
    )
    uploaded = st.file_uploader(
        "Upload",
        type=None,
        accept_multiple_files=True,
        key="multi_uploader",
        label_visibility="collapsed",
    )

    if uploaded:
        sig = tuple((f.name, f.size) for f in uploaded)
        if sig != st.session_state.last_upload_sig:
            entries, ferrs = flatten_inputs(uploaded)
            # If only two binary files (no ZIPs), apply the explicit smart A/B detection
            # rather than the pattern-based pairing (to preserve the single-pair UX).
            if len(uploaded) == 2 and not any(is_zip_filename(f.name) for f in uploaded) and len(entries) == 2:
                n1, d1 = entries[0]
                n2, d2 = entries[1]
                a_idx, reason = detect_ab(n1, n2)
                if a_idx == 0:
                    pair = {
                        "out_name": n1, "name_a": n1, "name_b": n2,
                        "data_a": d1, "data_b": d2,
                        "strategy": "two-file", "copy_num_a": 0, "copy_num_b": 1,
                        "status": None, "stats": None,
                    }
                else:
                    pair = {
                        "out_name": n2, "name_a": n2, "name_b": n1,
                        "data_a": d2, "data_b": d1,
                        "strategy": "two-file", "copy_num_a": 0, "copy_num_b": 1,
                        "status": None, "stats": None,
                    }
                st.session_state.pairs = [pair]
                st.session_state.unpaired = []
                st.session_state.detection_msg = (
                    f"✓ Two-file mode: **{pair['name_a']}** → File A, "
                    f"**{pair['name_b']}** → File B ({reason})"
                )
            else:
                pairs, unpaired = find_pairs(entries)
                st.session_state.pairs = pairs
                st.session_state.unpaired = unpaired
                if len(pairs) == 0:
                    st.session_state.detection_msg = (
                        "No pairs detected. Files must be named or organized so the tool "
                        "can match copies — see the help text above the uploader."
                    )
                elif len(pairs) == 1:
                    p = pairs[0]
                    st.session_state.detection_msg = (
                        f"✓ 1 pair detected: **{p['name_a']}** (copy {p['copy_num_a']}) ↔ "
                        f"**{p['name_b']}** (copy {p['copy_num_b']}) — "
                        f"output: `{p['out_name']}`"
                    )
                else:
                    st.session_state.detection_msg = (
                        f"✓ Batch mode: **{len(pairs)} pairs detected**."
                    )
            st.session_state.flatten_errors = ferrs
            st.session_state.current_pair_idx = 0
            st.session_state.page = 0
            st.session_state.processed = False
            st.session_state.last_upload_sig = sig

# ----- Optional single-pair manual uploaders -----
with st.expander("Or upload File A and File B separately (single-pair only)"):
    col1, col2 = st.columns(2)
    with col1:
        file_a_upload = st.file_uploader("File A", type=None, key="file_a_uploader")
        if file_a_upload is not None:
            a_sig = (file_a_upload.name, file_a_upload.size)
            if a_sig != st.session_state.last_a_sig:
                st.session_state.explicit_a = (file_a_upload.name, file_a_upload.getvalue())
                st.session_state.last_a_sig = a_sig
                st.session_state.processed = False
    with col2:
        file_b_upload = st.file_uploader("File B", type=None, key="file_b_uploader")
        if file_b_upload is not None:
            b_sig = (file_b_upload.name, file_b_upload.size)
            if b_sig != st.session_state.last_b_sig:
                st.session_state.explicit_b = (file_b_upload.name, file_b_upload.getvalue())
                st.session_state.last_b_sig = b_sig
                st.session_state.processed = False

    if st.session_state.explicit_a or st.session_state.explicit_b:
        a_status = ("✓ " + st.session_state.explicit_a[0] + " (" + format_bytes(len(st.session_state.explicit_a[1])) + ")") if st.session_state.explicit_a else "— File A not loaded"
        b_status = ("✓ " + st.session_state.explicit_b[0] + " (" + format_bytes(len(st.session_state.explicit_b[1])) + ")") if st.session_state.explicit_b else "— File B not loaded"
        st.caption(f"{a_status} • {b_status}")

# If user has filled both explicit uploaders, override pairs (single-pair flow)
if st.session_state.explicit_a and st.session_state.explicit_b:
    n_a, d_a = st.session_state.explicit_a
    n_b, d_b = st.session_state.explicit_b
    st.session_state.pairs = [{
        "out_name": n_a, "name_a": n_a, "name_b": n_b,
        "data_a": d_a, "data_b": d_b,
        "strategy": "explicit", "copy_num_a": 0, "copy_num_b": 1,
        "status": None, "stats": None,
    }]
    st.session_state.unpaired = []
    st.session_state.detection_msg = f"✓ Explicit single-pair: **{n_a}** → A, **{n_b}** → B"

# ----- Detection summary -----
if st.session_state.detection_msg:
    if st.session_state.pairs:
        st.info(st.session_state.detection_msg)
    else:
        st.warning(st.session_state.detection_msg)

if st.session_state.flatten_errors:
    with st.expander(f"⚠️ {len(st.session_state.flatten_errors)} archive-read warning(s)"):
        for err in st.session_state.flatten_errors:
            st.write(f"- {err}")

if st.session_state.unpaired:
    with st.expander(f"⚠️ {len(st.session_state.unpaired)} unpaired file(s) — will be skipped"):
        for path, reason in st.session_state.unpaired:
            st.write(f"- `{path}` — {reason}")

# ----- Pair preview for batch mode (before processing) -----
if st.session_state.pairs and len(st.session_state.pairs) > 1 and not st.session_state.processed:
    with st.expander(f"📋 Preview {len(st.session_state.pairs)} detected pair(s)", expanded=False):
        for i, p in enumerate(st.session_state.pairs):
            st.markdown(
                f"**{i+1}. `{p['out_name']}`** ({format_bytes(len(p['data_a']))}) — "
                f"`{p['name_a']}` ↔ `{p['name_b']}` "
                f"(strategy: {p['strategy']})"
            )

# ============================================================================
# UI — Action buttons
# ============================================================================

ready = bool(st.session_state.pairs)

action_cols = st.columns([1, 1, 1, 5])
with action_cols[0]:
    swap_disabled = not ready
    if st.button("⇅ Swap A ↔ B (all)", disabled=swap_disabled, help="Globally swap A and B for every pair"):
        for p in st.session_state.pairs:
            p["data_a"], p["data_b"] = p["data_b"], p["data_a"]
            p["name_a"], p["name_b"] = p["name_b"], p["name_a"]
            p["copy_num_a"], p["copy_num_b"] = p["copy_num_b"], p["copy_num_a"]
            # Invalidate per-pair results
            p["status"] = None
            p["stats"] = None
        st.session_state.processed = False
        st.rerun()

with action_cols[1]:
    process_label = "▶ Process Pair" if (ready and len(st.session_state.pairs) == 1) else "▶ Process All"
    process_clicked = st.button(process_label, type="primary", disabled=not ready)

with action_cols[2]:
    if st.button("Reset"):
        for k in ["pairs", "unpaired", "flatten_errors", "detection_msg",
                  "current_pair_idx", "page", "last_upload_sig",
                  "explicit_a", "explicit_b", "last_a_sig", "last_b_sig",
                  "processed"]:
            if k in st.session_state:
                st.session_state[k] = None if k not in ("current_pair_idx", "page", "processed") else (0 if k != "processed" else False)
        for widget_key in ["multi_uploader", "file_a_uploader", "file_b_uploader"]:
            if widget_key in st.session_state:
                del st.session_state[widget_key]
        st.rerun()

# ----- Process -----

if process_clicked and st.session_state.pairs:
    progress = st.progress(0.0, text="Processing pairs...")
    n = len(st.session_state.pairs)
    for i, p in enumerate(st.session_state.pairs):
        try:
            status_bytes, stats = process_one_pair(p["data_a"], p["data_b"])
            p["status"] = status_bytes
            p["stats"] = stats
        except Exception as e:
            p["status"] = None
            p["stats"] = None
            p["error"] = str(e)
        progress.progress((i + 1) / n, text=f"Processing pair {i + 1} of {n}: {p['out_name']}")
    progress.empty()
    st.session_state.processed = True
    st.session_state.current_pair_idx = 0
    st.session_state.page = 0

# ============================================================================
# UI — Results
# ============================================================================

if st.session_state.processed and st.session_state.pairs:
    pairs = st.session_state.pairs
    successful = [p for p in pairs if p["status"] is not None]
    failed = [p for p in pairs if p["status"] is None]

    st.divider()

    # --------------------------------------------------------------------------
    # BATCH MODE (multiple pairs)
    # --------------------------------------------------------------------------
    if len(pairs) > 1:
        st.subheader(f"Batch Summary — {len(successful)} of {len(pairs)} pair(s) processed")

        agg = {
            "totalSectors": sum(p["stats"]["totalSectors"] for p in successful),
            "matching": sum(p["stats"]["matching"] for p in successful),
            "recoveredFromA": sum(p["stats"]["recoveredFromA"] for p in successful),
            "recoveredFromB": sum(p["stats"]["recoveredFromB"] for p in successful),
            "deadInBoth": sum(p["stats"]["deadInBoth"] for p in successful),
            "conflicts": sum(p["stats"]["conflicts"] for p in successful),
        }

        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Pairs", f"{len(successful):,}")
        m2.metric("Total sectors", f"{agg['totalSectors']:,}")
        m3.metric("Total recovered", f"{agg['recoveredFromA'] + agg['recoveredFromB']:,}", "sectors saved from DEAD")
        m4.metric("Zeroed (both DEAD)", f"{agg['deadInBoth']:,}")
        m5.metric("Conflicts", f"{agg['conflicts']:,}")
        m6.metric("Both match", f"{agg['matching']:,}")

        # ----- Per-pair table -----
        st.markdown("##### Per-pair results")
        table_rows = []
        for p in successful:
            s = p["stats"]
            table_rows.append({
                "Output filename": p["out_name"],
                "File A": p["name_a"],
                "File B": p["name_b"],
                "Sectors": f"{s['totalSectors']:,}",
                "Match": s["matching"],
                "From A": s["recoveredFromA"],
                "From B": s["recoveredFromB"],
                "Zeroed": s["deadInBoth"],
                "Conflicts": s["conflicts"],
            })
        if table_rows:
            st.dataframe(table_rows, use_container_width=True, hide_index=True)

        if failed:
            with st.expander(f"❌ {len(failed)} pair(s) failed", expanded=True):
                for p in failed:
                    st.write(f"- `{p['out_name']}`: {p.get('error', 'unknown error')}")

        # ----- ZIP Downloads -----
        st.markdown("##### Downloads")
        if successful:
            has_conflicts = any(p["stats"]["conflicts"] > 0 for p in successful)
            dl_cols = st.columns(2)
            with dl_cols[0]:
                zip_a = build_zip(successful, prefer_b=False)
                st.download_button(
                    f"⬇ merged_preferA.zip ({format_bytes(len(zip_a))})",
                    data=zip_a,
                    file_name="merged_preferA.zip",
                    mime="application/zip",
                    use_container_width=True,
                )
            with dl_cols[1]:
                if has_conflicts:
                    zip_b = build_zip(successful, prefer_b=True)
                    st.download_button(
                        f"⬇ merged_preferB.zip ({format_bytes(len(zip_b))})",
                        data=zip_b,
                        file_name="merged_preferB.zip",
                        mime="application/zip",
                        use_container_width=True,
                    )
                else:
                    st.button("merged_preferB.zip (identical — no conflicts)", disabled=True, use_container_width=True)
            st.caption(
                "ZIPs contain all merged outputs flat, named after the matched source filename. "
                "preferA and preferB only differ on conflict sectors (both copies good but bytes differ)."
            )

        # ----- Hex viewer with pair selector -----
        st.divider()
        st.subheader("Inspect a pair")

        pair_options = [f"{i+1}. {p['out_name']}" for i, p in enumerate(successful)]
        if pair_options:
            selected = st.selectbox("Pair to inspect", pair_options, index=min(st.session_state.current_pair_idx, len(pair_options) - 1))
            new_idx = pair_options.index(selected)
            if new_idx != st.session_state.current_pair_idx:
                st.session_state.current_pair_idx = new_idx
                st.session_state.page = 0
            render_hex_viewer(successful[st.session_state.current_pair_idx])

    # --------------------------------------------------------------------------
    # SINGLE-PAIR MODE
    # --------------------------------------------------------------------------
    elif len(successful) == 1:
        p = successful[0]
        s = p["stats"]
        st.subheader("Summary")

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total Sectors", f"{s['totalSectors']:,}", format_bytes(s["totalBytes"]))
        m2.metric("Both Match", f"{s['matching']:,}", pct(s["matching"], s["totalSectors"]))
        m3.metric("Recovered from A", f"{s['recoveredFromA']:,}", "B was DEAD")
        m4.metric("Recovered from B", f"{s['recoveredFromB']:,}", "A was DEAD")
        m5.metric("Zeroed (Both DEAD)", f"{s['deadInBoth']:,}", pct(s["deadInBoth"], s["totalSectors"]))

        m6, m7, m8, m9, m10 = st.columns(5)
        m6.metric("Conflicts", f"{s['conflicts']:,}", pct(s["conflicts"], s["totalSectors"]))
        m7.metric("DEAD in A (total)", f"{s['deadInA']:,}", pct(s["deadInA"], s["totalSectors"]))
        m8.metric("DEAD in B (total)", f"{s['deadInB']:,}", pct(s["deadInB"], s["totalSectors"]))
        m9.metric("Total Recovered",
                  f"{s['recoveredFromA'] + s['recoveredFromB']:,}",
                  "sectors saved from DEAD")
        m10.metric("Conflicts present?", "Yes" if s["conflicts"] > 0 else "No",
                   "A and B downloads will differ" if s["conflicts"] > 0 else "downloads identical")

        st.divider()
        st.subheader("Downloads")
        dl_cols = st.columns(2)
        with dl_cols[0]:
            out_a = build_output(p["data_a"], p["data_b"], p["status"], prefer_b=False)
            st.download_button(
                "⬇ merged_preferA.bin",
                data=out_a,
                file_name="merged_preferA.bin",
                mime="application/octet-stream",
            )
        with dl_cols[1]:
            out_b = build_output(p["data_a"], p["data_b"], p["status"], prefer_b=True)
            st.download_button(
                "⬇ merged_preferB.bin",
                data=out_b,
                file_name="merged_preferB.bin",
                mime="application/octet-stream",
            )
        st.caption(
            "Files are identical when there are no conflicts. On conflicts: "
            "Version A uses File A's bytes; Version B uses File B's bytes."
        )

        st.divider()
        st.subheader("Hex Viewer")
        render_hex_viewer(p)

# ============================================================================
# Footer
# ============================================================================

st.divider()
st.caption(
    "$300 Data Recovery — Sector size: 512 bytes — All processing happens on the server. "
    "Files are not persisted after the session ends."
)
