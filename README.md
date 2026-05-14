# DEAD Sector Merger

A small tool for HDD firmware-module repair. Compares two binary dumps of the same module (or system file) sector-by-sector and produces a clean merged copy by:

- Taking the **good sector from whichever copy has it** when only one is DEAD
- **Zero-filling** any sector that is DEAD in both copies
- Flagging **conflicts** where both copies are readable but differ — output is produced in two versions (prefer-A and prefer-B) so the operator can compare

A "DEAD" sector is a 512-byte sector entirely filled with the repeating pattern `DE AD DE AD ...` — the standard fill an imager writes when a sector can't be read off the platter.

---

## Run locally

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

Open the URL Streamlit prints (typically `http://localhost:8501`).

## Deploy

This is a single-file Streamlit app — drop it on [Streamlit Community Cloud](https://share.streamlit.io), Hugging Face Spaces, or any host that runs `streamlit run streamlit_app.py`.

`requirements.txt` only needs `streamlit`; everything else is in the Python standard library (`zipfile`, `re`, `io`).

---

## Usage

1. **Enter the password** at the gate.
2. Upload two binary dumps. Three ways:
   - **Drop a ZIP** containing exactly two files
   - **Pick two files at once** in the multi-file uploader
   - **Upload them separately** into the File A / File B slots
3. When uploading as a pair or ZIP, the app auto-assigns A and B by filename pattern. The detection priority is:
   1. `copy1` / `copy2` (lower number = A)
   2. `_a` / `_b` suffix (case-insensitive)
   3. Common-prefix files differing only by a trailing number
   4. Lowest standalone digit anywhere in the filename
   5. Case-insensitive alphabetical fallback
   Use the **Swap A ↔ B** button if it guessed wrong.
4. Click **Process Files**.
5. Review the summary stats, download `merged_preferA.bin` and/or `merged_preferB.bin`, and inspect specific sectors in the hex viewer.

The hex viewer color-codes each sector by its status (match / recovered / zeroed / conflict). Conflict sectors highlight the bytes that actually differ between A and B in yellow.

## Constraints

- Both files must be **exactly the same size** in bytes
- File size must be a **multiple of 512** (sector-aligned)
- ZIPs must contain **exactly two files** (hidden files and `__MACOSX/` metadata are ignored)
- All processing happens on the server hosting the Streamlit app — files are not persisted after the session ends

## Files in this repo

- `streamlit_app.py` — the app
- `requirements.txt` — Python deps
- `dead-sector-merger.html` — standalone browser version (no server required; opens directly in any browser; client-side processing only)
- `test_a.bin`, `test_b.bin` — synthetic test fixtures (8 sectors each, exercising every code path)
- `test_pair.zip` — the same fixtures bundled into a ZIP renamed `module_copy1.bin` / `module_copy2.bin` to demo the pattern detection
- `expected_preferA.bin`, `expected_preferB.bin` — what the merged downloads should look like for the test fixtures (bytewise diff = 512 bytes, the one conflict sector)
- `checksum-research.md` — notes on which drive architectures use module checksums and where their algorithms are (or are not) documented

## Password

The app is gated by a single shared password defined at the top of `streamlit_app.py` as the `PASSWORD` constant. To change it, edit the constant. For production use you may prefer to read it from `st.secrets` instead.

---

Built for [$300 Data Recovery](https://www.300dollardatarecovery.com).
