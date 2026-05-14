"""
DEAD Sector Merger — $300 Data Recovery

Compares two binary dumps (firmware modules / system files) sector-by-sector,
merges non-DEAD sectors, and zero-fills sectors that are DEAD in both copies.
"""
import io
import re
import zipfile
from typing import List, Tuple

import streamlit as st

# ============================================================================
# Config
# ============================================================================

st.set_page_config(
    page_title="DEAD Sector Merger — $300 Data Recovery",
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

# ============================================================================
# Password gate
# ============================================================================

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.markdown("# 🔒 DEAD Sector Merger")
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
# Helpers
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


def detect_ab(name1: str, name2: str) -> Tuple[int, str]:
    """
    Smart filename pattern detection.

    Returns (which_index_is_a, reason). 0 means name1 is A, 1 means name2 is A.
    """
    base1 = re.sub(r"\.[^./\\]+$", "", name1)
    base2 = re.sub(r"\.[^./\\]+$", "", name2)

    # Pattern 1: copy1 / copy2
    copy_re = re.compile(r"copy[\s_\-]*(\d+)", re.IGNORECASE)
    m1c = copy_re.search(base1)
    m2c = copy_re.search(base2)
    if m1c and m2c and m1c.group(1) != m2c.group(1):
        n1, n2 = int(m1c.group(1)), int(m2c.group(1))
        if n1 < n2:
            return 0, f'"copy{m1c.group(1)}" < "copy{m2c.group(1)}"'
        return 1, f'"copy{m2c.group(1)}" < "copy{m1c.group(1)}"'

    # Pattern 2: trailing _a / _b (with separator)
    ab_re = re.compile(r"[_\-\s.]([ab])(?=\.[^.]+$|$)", re.IGNORECASE)
    m1ab = ab_re.search(name1)
    m2ab = ab_re.search(name2)
    if m1ab and m2ab and m1ab.group(1).lower() != m2ab.group(1).lower():
        if m1ab.group(1).lower() == "a":
            return 0, f'"{m1ab.group(1)}" suffix vs "{m2ab.group(1)}"'
        return 1, f'"{m2ab.group(1)}" suffix vs "{m1ab.group(1)}"'

    # Pattern 3: common-prefix differs only by a trailing number
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

    # Pattern 4: lowest standalone digit anywhere
    nums1 = [int(x) for x in re.findall(r"\d+", base1)]
    nums2 = [int(x) for x in re.findall(r"\d+", base2)]
    if nums1 and nums2:
        min1, min2 = min(nums1), min(nums2)
        if min1 != min2:
            if min1 < min2:
                return 0, f"lowest number {min1} < {min2}"
            return 1, f"lowest number {min2} < {min1}"

    # Fallback: case-insensitive alphabetical
    if name1.lower() <= name2.lower():
        return 0, "alphabetical fallback"
    return 1, "alphabetical fallback"


def is_zip_filename(name: str) -> bool:
    return name.lower().endswith(".zip")


def extract_pair_from_zip(zip_bytes: bytes) -> List[Tuple[str, bytes]]:
    """Return list of (basename, content_bytes), filtered to data files only."""
    out = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            base = info.filename.split("/")[-1]
            if not base:
                continue
            if base.startswith("."):
                continue
            if "__MACOSX" in info.filename:
                continue
            out.append((base, z.read(info)))
    return out


def process(data_a: bytes, data_b: bytes):
    """Return (status_bytes, stats_dict). Raises ValueError on bad input."""
    if len(data_a) != len(data_b):
        raise ValueError(
            f"Size mismatch: File A is {len(data_a):,} bytes, "
            f"File B is {len(data_b):,} bytes. Files must be exactly the same size."
        )
    if len(data_a) == 0:
        raise ValueError("Files are empty.")
    if len(data_a) % SECTOR_SIZE != 0:
        raise ValueError(
            f"File size ({len(data_a):,} bytes) is not a multiple of {SECTOR_SIZE}. "
            "Sector-based comparison requires aligned files."
        )

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

    # Use memoryview for slice efficiency
    mv_a = memoryview(data_a)
    mv_b = memoryview(data_b)

    progress = st.progress(0.0, text="Analyzing sectors...")
    chunk = max(1, total_sectors // 100)
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

        if i % chunk == 0:
            progress.progress(i / total_sectors, text=f"Analyzing sectors... {i:,} / {total_sectors:,}")

    progress.progress(1.0, text="Done.")
    progress.empty()
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


def _hex_to_rgb(hex_color: str) -> str:
    h = hex_color.lstrip("#")
    return f"{int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)}"


def render_sector_block(sector_idx: int, data_a: bytes, data_b: bytes,
                        status: bytes, view_version: str) -> str:
    """Return HTML for a single sector's hex display."""
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
    else:  # CONFLICT
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
        # Insert a small gap after byte 8
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
# Session state init
# ============================================================================

for k, v in [
    ("data_a", None), ("data_b", None),
    ("name_a", None), ("name_b", None),
    ("status", None), ("stats", None),
    ("auto_match_msg", None),
    ("page", 0),
]:
    if k not in st.session_state:
        st.session_state[k] = v


# ============================================================================
# UI
# ============================================================================

st.title("🔧 DEAD Sector Merger")
st.caption(
    "Compare two binary dumps, merge non-DEAD sectors, zero-fill double-DEAD sectors. "
    f"512-byte sectors. DEAD = full sector of `DE AD DE AD ...`"
)

# ----- Upload section -----

with st.container(border=True):
    st.markdown("**📦 Upload a ZIP or both files at once**")
    st.caption(
        "A and B will be auto-assigned by filename pattern "
        "(copy1/copy2, _a/_b, 1/2, etc.). ZIPs must contain exactly two files."
    )
    pair_files = st.file_uploader(
        "Drop a ZIP or pick two files",
        type=None,
        accept_multiple_files=True,
        key="pair_uploader",
        label_visibility="collapsed",
    )

    if pair_files:
        try:
            # Case 1: single ZIP
            if len(pair_files) == 1 and is_zip_filename(pair_files[0].name):
                zip_bytes = pair_files[0].read()
                extracted = extract_pair_from_zip(zip_bytes)
                if len(extracted) != 2:
                    st.error(f"ZIP must contain exactly 2 files. Found {len(extracted)}.")
                else:
                    (n1, d1), (n2, d2) = extracted
                    a_idx, reason = detect_ab(n1, n2)
                    if a_idx == 0:
                        st.session_state.data_a, st.session_state.name_a = d1, n1
                        st.session_state.data_b, st.session_state.name_b = d2, n2
                    else:
                        st.session_state.data_a, st.session_state.name_a = d2, n2
                        st.session_state.data_b, st.session_state.name_b = d1, n1
                    st.session_state.auto_match_msg = (
                        f'✓ From ZIP "{pair_files[0].name}": '
                        f'**{st.session_state.name_a}** → File A, '
                        f'**{st.session_state.name_b}** → File B ({reason})'
                    )
                    # Invalidate any prior results
                    st.session_state.status = None
                    st.session_state.stats = None

            # Case 2: exactly two files dropped
            elif len(pair_files) == 2:
                n1, d1 = pair_files[0].name, pair_files[0].read()
                n2, d2 = pair_files[1].name, pair_files[1].read()
                a_idx, reason = detect_ab(n1, n2)
                if a_idx == 0:
                    st.session_state.data_a, st.session_state.name_a = d1, n1
                    st.session_state.data_b, st.session_state.name_b = d2, n2
                else:
                    st.session_state.data_a, st.session_state.name_a = d2, n2
                    st.session_state.data_b, st.session_state.name_b = d1, n1
                st.session_state.auto_match_msg = (
                    f'✓ From multi-file selection: '
                    f'**{st.session_state.name_a}** → File A, '
                    f'**{st.session_state.name_b}** → File B ({reason})'
                )
                st.session_state.status = None
                st.session_state.stats = None

            else:
                st.error(
                    f"Expected exactly 2 files (or a ZIP containing 2 files). "
                    f"Got {len(pair_files)}."
                )
        except Exception as e:
            st.error(f"Failed to process upload: {e}")

st.markdown("###### or upload separately")

col1, col2 = st.columns(2)
with col1:
    file_a_upload = st.file_uploader("File A", type=None, key="file_a_uploader")
    if file_a_upload is not None:
        st.session_state.data_a = file_a_upload.read()
        st.session_state.name_a = file_a_upload.name
        st.session_state.status = None
        st.session_state.stats = None
with col2:
    file_b_upload = st.file_uploader("File B", type=None, key="file_b_uploader")
    if file_b_upload is not None:
        st.session_state.data_b = file_b_upload.read()
        st.session_state.name_b = file_b_upload.name
        st.session_state.status = None
        st.session_state.stats = None

# ----- Status of current loaded files -----

if st.session_state.auto_match_msg:
    st.info(st.session_state.auto_match_msg)

status_cols = st.columns(2)
with status_cols[0]:
    if st.session_state.data_a is not None:
        st.success(f"**File A**: {st.session_state.name_a} — {format_bytes(len(st.session_state.data_a))}")
    else:
        st.warning("**File A**: not loaded")
with status_cols[1]:
    if st.session_state.data_b is not None:
        st.success(f"**File B**: {st.session_state.name_b} — {format_bytes(len(st.session_state.data_b))}")
    else:
        st.warning("**File B**: not loaded")

# ----- Action buttons -----

action_cols = st.columns([1, 1, 1, 5])
with action_cols[0]:
    swap_disabled = not (st.session_state.data_a is not None and st.session_state.data_b is not None)
    if st.button("⇅ Swap A ↔ B", disabled=swap_disabled):
        st.session_state.data_a, st.session_state.data_b = st.session_state.data_b, st.session_state.data_a
        st.session_state.name_a, st.session_state.name_b = st.session_state.name_b, st.session_state.name_a
        st.session_state.status = None
        st.session_state.stats = None
        if st.session_state.auto_match_msg:
            st.session_state.auto_match_msg = (
                f"↻ Swapped: **{st.session_state.name_a}** → File A, "
                f"**{st.session_state.name_b}** → File B."
            )
        st.rerun()

with action_cols[1]:
    process_disabled = not (st.session_state.data_a is not None and st.session_state.data_b is not None)
    process_clicked = st.button("▶ Process Files", type="primary", disabled=process_disabled)

with action_cols[2]:
    if st.button("Reset"):
        for k in ["data_a", "data_b", "name_a", "name_b", "status", "stats",
                  "auto_match_msg", "page"]:
            if k in st.session_state:
                st.session_state[k] = None if k != "page" else 0
        st.rerun()

# ----- Run processing -----

if process_clicked:
    try:
        status_bytes, stats = process(st.session_state.data_a, st.session_state.data_b)
        st.session_state.status = status_bytes
        st.session_state.stats = stats
        st.session_state.page = 0
    except ValueError as e:
        st.error(str(e))

# ============================================================================
# Results
# ============================================================================

if st.session_state.status is not None and st.session_state.stats is not None:
    stats = st.session_state.stats
    status_bytes = st.session_state.status

    st.divider()
    st.subheader("Summary")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Sectors", f"{stats['totalSectors']:,}", format_bytes(stats['totalBytes']))
    m2.metric("Both Match", f"{stats['matching']:,}", pct(stats['matching'], stats['totalSectors']))
    m3.metric("Recovered from A", f"{stats['recoveredFromA']:,}", "B was DEAD")
    m4.metric("Recovered from B", f"{stats['recoveredFromB']:,}", "A was DEAD")
    m5.metric("Zeroed (Both DEAD)", f"{stats['deadInBoth']:,}", pct(stats['deadInBoth'], stats['totalSectors']))

    m6, m7, m8, m9, m10 = st.columns(5)
    m6.metric("Conflicts", f"{stats['conflicts']:,}", pct(stats['conflicts'], stats['totalSectors']))
    m7.metric("DEAD in A (total)", f"{stats['deadInA']:,}", pct(stats['deadInA'], stats['totalSectors']))
    m8.metric("DEAD in B (total)", f"{stats['deadInB']:,}", pct(stats['deadInB'], stats['totalSectors']))
    m9.metric("Total Recovered",
              f"{stats['recoveredFromA'] + stats['recoveredFromB']:,}",
              "sectors saved from DEAD")
    m10.metric("Conflicts present?", "Yes" if stats['conflicts'] > 0 else "No",
               "A and B downloads will differ" if stats['conflicts'] > 0 else "downloads identical")

    # ----- Downloads -----
    st.divider()
    st.subheader("Downloads")
    dl_cols = st.columns(2)
    with dl_cols[0]:
        # Build output A on demand
        out_a = build_output(st.session_state.data_a, st.session_state.data_b, status_bytes, prefer_b=False)
        st.download_button(
            "⬇ merged_preferA.bin",
            data=out_a,
            file_name="merged_preferA.bin",
            mime="application/octet-stream",
        )
    with dl_cols[1]:
        out_b = build_output(st.session_state.data_a, st.session_state.data_b, status_bytes, prefer_b=True)
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

    # ----- Hex viewer -----
    st.divider()
    st.subheader("Hex Viewer")

    # Legend
    legend_html = '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;font-size:12px">'
    legend_items = [
        ("#4ade80", "Both match"),
        ("#4da3ff", "Recovered from A (B dead)"),
        ("#c084fc", "Recovered from B (A dead)"),
        ("#f87171", "Zeroed (both dead)"),
        ("#fbbf24", "Conflict"),
    ]
    for color, label in legend_items:
        legend_html += (
            f'<div style="display:flex;align-items:center;gap:6px;color:#8b95a4">'
            f'<div style="width:12px;height:12px;border-radius:2px;background:{color}"></div>'
            f'{label}</div>'
        )
    legend_html += '</div>'
    st.markdown(legend_html, unsafe_allow_html=True)

    # Controls
    ctrl_cols = st.columns([2, 2, 1, 2, 1])
    with ctrl_cols[0]:
        view_version = st.radio(
            "Showing version",
            ["A", "B"],
            horizontal=True,
            help="Only matters for conflict sectors.",
        )
    with ctrl_cols[1]:
        filter_label = st.selectbox("Filter", list(FILTER_OPTIONS.keys()))
    with ctrl_cols[2]:
        page_size = st.selectbox("Sectors/page", [1, 4, 8, 16], index=1)
    with ctrl_cols[3]:
        jump_sector = st.number_input(
            "Jump to sector",
            min_value=0,
            max_value=stats["totalSectors"] - 1,
            value=0,
            step=1,
        )
    with ctrl_cols[4]:
        st.markdown("&nbsp;")
        do_jump = st.button("Go", use_container_width=True)

    # Compute filter
    allowed = FILTER_OPTIONS[filter_label]
    if allowed is None:
        filter_indices = None
        total_for_page = stats["totalSectors"]
    else:
        allowed_set = set(allowed)
        filter_indices = [i for i, s in enumerate(status_bytes) if s in allowed_set]
        total_for_page = len(filter_indices)

    total_pages = max(1, -(-total_for_page // page_size))  # ceil

    # Handle jump
    if do_jump:
        if filter_indices is None:
            st.session_state.page = jump_sector // page_size
        else:
            # find first filtered index >= jump_sector
            idx = next((k for k, v in enumerate(filter_indices) if v >= jump_sector), None)
            if idx is None:
                st.warning(f"No sector ≥ {jump_sector} matches the current filter.")
            else:
                st.session_state.page = idx // page_size

    if st.session_state.page >= total_pages:
        st.session_state.page = max(0, total_pages - 1)

    # Pagination controls
    page_cols = st.columns([1, 4, 1])
    with page_cols[0]:
        if st.button("← Previous", disabled=(st.session_state.page == 0)):
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
        if st.button("Next →", disabled=(st.session_state.page >= total_pages - 1)):
            st.session_state.page = min(total_pages - 1, st.session_state.page + 1)
            st.rerun()

    # Render hex blocks for the current page
    start = st.session_state.page * page_size
    end = start + page_size
    if filter_indices is None:
        visible = list(range(start, min(end, stats["totalSectors"])))
    else:
        visible = filter_indices[start:end]

    if not visible:
        st.info("No sectors match the current filter.")
    else:
        hex_html = '<div style="background:#0f1419;padding:12px;border-radius:6px;border:1px solid #2d3744">'
        for idx in visible:
            hex_html += render_sector_block(
                idx, st.session_state.data_a, st.session_state.data_b,
                status_bytes, view_version,
            )
        hex_html += '</div>'
        st.markdown(hex_html, unsafe_allow_html=True)

# ============================================================================
# Footer
# ============================================================================

st.divider()
st.caption(
    "$300 Data Recovery — Sector size: 512 bytes — All processing happens on the server. "
    "Files are not persisted after the session ends."
)
