#!/usr/bin/env python3
"""PE Import Inspector: a small Tkinter GUI for checking Windows application
EXE/DLL imports against an optional directory of available system DLLs.

Requires: python -m pip install pefile - no i cant be fucking bothered to write a requirements file
Run:      python pe_import_inspector.py

Checks regular and delay-load import tables, including ordinal imports and
export forwarders. This is a STATIC audit: runtime LoadLibrary/GetProcAddress
calls and the correctness of exported implementations are not inspected.
"""
from __future__ import annotations

import csv
import queue
import threading
import tkinter as tk
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import pefile
except ImportError:
    pefile = None

PE_EXTENSIONS = {".exe", ".dll", ".pyd", ".ocx", ".cpl", ".scr", ".drv"}
MISSING_STATUSES = {
    "MISSING DLL", "MISSING EXPORT", "BAD FORWARDER", "FORWARDER LOOP",
    "INVALID DLL", "UNMAPPED API SET",
}
FIELDS = [
    "binary", "import_kind", "requested_dll", "symbol", "status",
    "resolved_dll", "provider_file", "detail",
]


def dll_key(value: bytes | str) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    name = value.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    if name and "." not in name:
        name += ".dll"
    return name


def decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def pe_files(directory: Path) -> list[Path]:
    return sorted(
        (p for p in directory.rglob("*")
         if p.is_file() and p.suffix.lower() in PE_EXTENSIONS),
        key=lambda p: str(p).lower(),
    )


def read_imports(path: Path) -> list[tuple[str, str, str]]:
    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ])
        result = []
        for section, kind in (("DIRECTORY_ENTRY_IMPORT", "normal"),
                              ("DIRECTORY_ENTRY_DELAY_IMPORT", "delay-load")):
            for descriptor in getattr(pe, section, []):
                name = dll_key(descriptor.dll)
                for item in descriptor.imports:
                    symbol = decode(item.name) if item.name else f"#{item.ordinal}"
                    result.append((kind, name, symbol))
        return result
    finally:
        pe.close()


def read_exports(path: Path) -> dict[str, str | None]:
    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]
        ])
        exports: dict[str, str | None] = {}
        directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if directory is not None:
            for entry in directory.symbols:
                forwarder = decode(entry.forwarder) if entry.forwarder else None
                exports[f"#{entry.ordinal}"] = forwarder
                if entry.name:
                    exports[decode(entry.name)] = forwarder
        return exports
    finally:
        pe.close()


def apiset_host(dll: str) -> str | None:
    """VEILOS-style API-set fallback, used only if the named DLL is absent.

    Real Windows' API-set mappings vary with OS versions. Treat results
    involving this fallback as estimates, not proof of OS compatibility.
    """
    if dll.startswith("api-ms-win-crt-"):
        return "ucrtbase.dll"
    if dll.startswith("api-ms-win-core-rtlsupport-"):
        return "ntdll.dll"
    if dll.startswith("api-ms-win-"):
        return "kernel32.dll"
    return None


@dataclass
class ImportRow:
    binary: str
    import_kind: str
    requested_dll: str
    symbol: str
    status: str
    resolved_dll: str = ""
    provider_file: str = ""
    detail: str = ""


class ImportAuditor:
    def __init__(self, app_folder: Path, system_folder: Path | None,
                 system_first: bool = True):
        self.app_folder = app_folder
        self.system_folder = system_folder
        self.system_first = system_first
        self.app_files = pe_files(app_folder)
        # Don't scan the same directory twice when both selections are identical.
        self.system_files = (
            pe_files(system_folder) if system_folder and system_folder.resolve() != app_folder.resolve()
            else []
        )
        self.app_index: dict[str, list[Path]] = defaultdict(list)
        self.system_index: dict[str, list[Path]] = defaultdict(list)
        for path in self.app_files:
            self.app_index[path.name.lower()].append(path)
        for path in self.system_files:
            self.system_index[path.name.lower()].append(path)
        self.exports_cache: dict[Path, dict[str, str | None]] = {}
        self.imports_cache: dict[Path, list[tuple[str, str, str]]] = {}
        self.errors: list[str] = []

    def provider(self, dll: str, requester: Path) -> tuple[Path | None, str]:
        # Selecting a system folder means exactly that directory is the set
        # being compared. The checkbox can emulate VEILOS' system-first search.
        system = self.system_index.get(dll, [])
        local = self.app_index.get(dll, [])
        if self.system_first and system:
            return system[0], "system-first selection"
        if local:
            for p in local:
                if p.parent == requester.parent:
                    return p, "application-local"
            for p in local:
                if p.parent == self.app_folder:
                    return p, "application root"
            if len(local) > 1:
                return local[0], f"ambiguous: {len(local)} application DLLs have this name"
            return local[0], "application subfolder (search order approximate)"
        if system:
            return system[0], "supplied system DLL directory"
        return None, ""

    def exports(self, path: Path) -> dict[str, str | None]:
        if path not in self.exports_cache:
            self.exports_cache[path] = read_exports(path)
        return self.exports_cache[path]

    def resolve(self, dll: str, symbol: str, requester: Path,
                visited: set[tuple[str, str, Path]] | None = None
                ) -> tuple[str, str, str, str]:
        if visited is None:
            visited = set()
        if len(visited) >= 24:
            return "FORWARDER LOOP", dll, "", "Export forwarder chain exceeded 24 steps"

        path, how = self.provider(dll, requester)
        effective_dll = dll
        mapping_note = ""
        if path is None and (dll.startswith("api-ms-win-") or dll.startswith("ext-ms-win-")):
            host = apiset_host(dll)
            if host is None:
                return "UNMAPPED API SET", dll, "", "No fallback mapping for this API-set contract"
            effective_dll = host
            mapping_note = f"API-set estimated host {dll} -> {host}; "
            path, how = self.provider(host, requester)

        if path is None:
            if self.system_folder is None:
                return "NOT CHECKED", effective_dll, "", mapping_note + "Not in application; no system DLL directory supplied"
            return "MISSING DLL", effective_dll, "", mapping_note + "Not present in the folders supplied"

        signature = (effective_dll, symbol, path)
        if signature in visited:
            return "FORWARDER LOOP", effective_dll, str(path), "Cyclic export forwarding"
        visited = visited | {signature}
        try:
            exports = self.exports(path)
        except Exception as exc:
            return "INVALID DLL", effective_dll, str(path), f"Could not parse exports: {exc}"

        if symbol not in exports:
            return "MISSING EXPORT", effective_dll, str(path), mapping_note + "Symbol not exported"

        forwarded_to = exports[symbol]
        if forwarded_to:
            if "." not in forwarded_to:
                return "BAD FORWARDER", effective_dll, str(path), f"Invalid forwarder: {forwarded_to}"
            dest, dest_symbol = forwarded_to.rsplit(".", 1)
            status, final_dll, provider, detail = self.resolve(
                dll_key(dest), dest_symbol, path, visited
            )
            return status, final_dll, provider, (
                mapping_note + f"{effective_dll}!{symbol} -> {forwarded_to}; " + detail
            ).rstrip("; ")
        return "EXPORTED", effective_dll, str(path), mapping_note + how

    def scan(self, notify) -> list[ImportRow]:
        rows = []
        total = len(self.app_files)
        for i, path in enumerate(self.app_files, start=1):
            try:
                imports = read_imports(path)
                self.imports_cache[path] = imports
                for kind, dll, symbol in imports:
                    status, resolved, provider, detail = self.resolve(dll, symbol, path)
                    rows.append(ImportRow(
                        binary=str(path.relative_to(self.app_folder)),
                        import_kind=kind,
                        requested_dll=dll,
                        symbol=symbol,
                        status=status,
                        resolved_dll=resolved,
                        provider_file=provider,
                        detail=detail,
                    ))
            except Exception as exc:
                self.errors.append(f"{path}: {exc}")
            if i == 1 or i % 3 == 0 or i == total:
                notify(i, total, path.name)
        return rows


class InspectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PE Import Inspector")
        self.geometry("1160x690")
        self.minsize(820, 500)

        self.app_dir = tk.StringVar()
        default_system = Path.cwd() / "storage" / "system"
        self.system_dir = tk.StringVar(value=str(default_system) if default_system.is_dir() else "")
        self.system_first = tk.BooleanVar(value=True)
        self.missing_only = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="Choose an application folder, then click Scan.")
        self.stats = tk.StringVar(value="No scan yet")
        self.rows: list[ImportRow] = []
        self.errors: list[str] = []
        self.scanned_app = ""
        self.scanned_system = ""
        self.messages: queue.Queue = queue.Queue()
        self.working = False
        self.sort_col = ""
        self.sort_reverse = False

        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)
        root.columnconfigure(1, weight=1)

        ttk.Label(root, text="Application folder").grid(row=0, column=0, sticky="w", pady=(0, 7))
        ttk.Entry(root, textvariable=self.app_dir).grid(row=0, column=1, sticky="ew", padx=8, pady=(0, 7))
        ttk.Button(root, text="Browse…", command=lambda: self.choose_folder(self.app_dir)).grid(row=0, column=2, pady=(0, 7))

        ttk.Label(root, text="System DLLs (optional)").grid(row=1, column=0, sticky="w", pady=(0, 7))
        ttk.Entry(root, textvariable=self.system_dir).grid(row=1, column=1, sticky="ew", padx=8, pady=(0, 7))
        ttk.Button(root, text="Browse…", command=lambda: self.choose_folder(self.system_dir)).grid(row=1, column=2, pady=(0, 7))

        options = ttk.Frame(root)
        options.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0, 9))
        ttk.Checkbutton(options, text="Prefer system DLLs (VEILOS)", variable=self.system_first).pack(side="left")
        self.scan_button = ttk.Button(options, text="Scan imports", command=self.begin_scan)
        self.scan_button.pack(side="right")
        self.export_button = ttk.Button(options, text="Export CSV reports…", command=self.export, state="disabled")
        self.export_button.pack(side="right", padx=(0, 8))

        stats_row = ttk.Frame(root)
        stats_row.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 5))
        ttk.Label(stats_row, textvariable=self.stats).pack(side="left")
        ttk.Checkbutton(stats_row, text="Missing / not checked only", variable=self.missing_only,
                        command=self.refresh_table).pack(side="right")

        self.progress = ttk.Progressbar(root, mode="determinate", maximum=100)
        self.progress.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(0, 8))

        table_frame = ttk.Frame(root)
        table_frame.grid(row=5, column=0, columnspan=3, sticky="nsew")
        root.rowconfigure(5, weight=1)
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        cols = ("binary", "import_kind", "requested_dll", "symbol", "status", "resolved_dll")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        labels = {
            "binary": "Importing file", "import_kind": "Kind", "requested_dll": "DLL",
            "symbol": "Function / ordinal", "status": "Status", "resolved_dll": "Resolved DLL",
        }
        widths = {"binary": 205, "import_kind": 78, "requested_dll": 205,
                  "symbol": 285, "status": 135, "resolved_dll": 160}
        for col in cols:
            self.tree.heading(col, text=labels[col], command=lambda c=col: self.toggle_sort(c))
            self.tree.column(col, width=widths[col], stretch=col in ("binary", "symbol"), minwidth=75)
        self.tree.tag_configure("missing", foreground="#B4262D")
        self.tree.tag_configure("unchecked", foreground="#7B6B24")
        self.tree.grid(row=0, column=0, sticky="nsew")
        ybar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        ybar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=ybar.set)
        xbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        xbar.grid(row=1, column=0, sticky="ew")
        self.tree.configure(xscrollcommand=xbar.set)
        self.tree.bind("<<TreeviewSelect>>", self.selected_row)
        self.detail = tk.StringVar(value="Select a result to see its provider and resolution details.")
        ttk.Label(root, textvariable=self.detail, wraplength=1100, foreground="#666666").grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(8, 4)
        )
        ttk.Label(root, textvariable=self.status).grid(row=7, column=0, columnspan=3, sticky="ew")
        self.after(120, self.poll_messages)

    def choose_folder(self, variable: tk.StringVar):
        initial = variable.get()
        if not Path(initial).is_dir():
            initial = str(Path.cwd())
        result = filedialog.askdirectory(parent=self, initialdir=initial, mustexist=True)
        if result:
            variable.set(result)

    def begin_scan(self):
        app = Path(self.app_dir.get().strip().strip('"')).expanduser()
        system_name = self.system_dir.get().strip().strip('"')
        system = Path(system_name).expanduser() if system_name else None
        if not app.is_dir():
            messagebox.showerror("Invalid application folder", "Choose an existing application folder.")
            return
        if system is not None and not system.is_dir():
            messagebox.showerror("Invalid system folder", "The system DLL folder doesn't exist.\nLeave it blank to scan application imports only.")
            return
        if pefile is None:
            messagebox.showerror("Missing dependency", "Install pefile first:\n\npython -m pip install pefile")
            return
        self.working = True
        self.scan_button.configure(state="disabled")
        self.export_button.configure(state="disabled")
        self.progress["value"] = 0
        self.stats.set("Scanning…")
        self.status.set("Reading PE headers and comparing exports…")
        current_items = self.tree.get_children()
        if current_items:
            self.tree.delete(*current_items)
        self.rows = []
        self.errors = []
        self.scanned_app, self.scanned_system = str(app), str(system) if system else ""
        t = threading.Thread(target=self.worker, args=(app, system, self.system_first.get()), daemon=True)
        t.start()

    def worker(self, app: Path, system: Path | None, system_first: bool):
        try:
            auditor = ImportAuditor(app, system, system_first)
            if not auditor.app_files:
                self.messages.put(("error", "No PE files (.exe, .dll, etc.) found in the selected application folder."))
                return
            rows = auditor.scan(lambda n, total, name: self.messages.put(("progress", n, total, name)))
            self.messages.put(("done", rows, auditor.errors, len(auditor.app_files)))
        except Exception as exc:
            self.messages.put(("error", str(exc)))

    def poll_messages(self):
        try:
            while True:
                item = self.messages.get_nowait()
                kind = item[0]
                if kind == "progress":
                    _, count, total, name = item
                    self.progress["value"] = count * 100 / total
                    self.status.set(f"Scanning {count}/{total}: {name}")
                elif kind == "done":
                    _, self.rows, self.errors, files_count = item
                    statuses = Counter(row.status for row in self.rows)
                    missing = sum(n for state, n in statuses.items() if state in MISSING_STATUSES)
                    unchecked = statuses.get("NOT CHECKED", 0)
                    self.stats.set(
                        f"{files_count:,} PE files  |  {len(self.rows):,} imports  |  "
                        f"{missing:,} missing  |  {unchecked:,} not checked"
                    )
                    self.working = False
                    self.scan_button.configure(state="normal")
                    self.export_button.configure(state="normal")
                    self.refresh_table()
                    self.status.set(
                        f"Scan completed. {len(self.errors)} files couldn't be parsed. "
                        "Export reports for the complete results."
                    )
                elif kind == "error":
                    self.working = False
                    self.scan_button.configure(state="normal")
                    self.stats.set("Scan failed")
                    self.status.set(item[1])
                    messagebox.showerror("Scan error", item[1])
        except queue.Empty:
            pass
        self.after(120, self.poll_messages)

    def toggle_sort(self, column: str):
        if self.sort_col == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_col = column
            self.sort_reverse = False
        self.refresh_table()

    def refresh_table(self):
        if self.working:
            return
        current_items = self.tree.get_children()
        if current_items:
            self.tree.delete(*current_items)
        filtered = [r for r in self.rows if not self.missing_only.get()
                    or r.status != "EXPORTED"]
        if self.sort_col:
            filtered.sort(key=lambda r: getattr(r, self.sort_col).casefold(),
                          reverse=self.sort_reverse)
        limit = 7000  # Treeview would get slow with tens of thousands of rows.
        for i, row in enumerate(filtered[:limit]):
            tag = ("missing" if row.status in MISSING_STATUSES
                   else "unchecked" if row.status == "NOT CHECKED" else "")
            self.tree.insert("", "end", iid=str(i), values=(
                row.binary, row.import_kind, row.requested_dll,
                row.symbol, row.status, row.resolved_dll,
            ), tags=(tag,) if tag else ())
        self.visible_rows = filtered[:limit]
        if len(filtered) > limit:
            self.status.set(f"Showing first {limit:,} of {len(filtered):,} rows. CSV exports contain all results.")

    def selected_row(self, _event):
        current = self.tree.selection()
        if not current:
            return
        index = int(current[0])
        row = self.visible_rows[index]
        self.detail.set(f"Provider: {row.provider_file or '(none)'}  |  {row.detail}")

    def export(self):
        folder = filedialog.askdirectory(parent=self, title="Choose output folder for CSV reports")
        if not folder:
            return
        target = Path(folder)
        try:
            with (target / "all_imports.csv").open("w", encoding="utf-8-sig", newline="") as fp:
                writer = csv.DictWriter(fp, fieldnames=FIELDS)
                writer.writeheader()
                writer.writerows(asdict(row) for row in self.rows)
            with (target / "missing_imports.csv").open("w", encoding="utf-8-sig", newline="") as fp:
                writer = csv.DictWriter(fp, fieldnames=FIELDS)
                writer.writeheader()
                writer.writerows(asdict(row) for row in self.rows if row.status != "EXPORTED")
            counts = Counter(row.requested_dll for row in self.rows)
            missing_counts = Counter(row.requested_dll for row in self.rows if row.status != "EXPORTED")
            with (target / "required_dlls.csv").open("w", encoding="utf-8-sig", newline="") as fp:
                writer = csv.writer(fp)
                writer.writerow(["requested_dll", "total_imports", "unresolved_or_not_checked"])
                for dll, n in sorted(counts.items(), key=lambda entry: (-entry[1], entry[0])):
                    writer.writerow([dll, n, missing_counts[dll]])
            summary = [
                "PE Import Inspector", "===================", "",
                f"Application folder: {self.scanned_app}",
                f"System DLL folder: {self.scanned_system or '(not selected)'}",
                f"PE imports inspected: {len(self.rows)}",
                "", "Statuses:",
            ]
            summary.extend(f"  {status}: {n}" for status, n in Counter(row.status for row in self.rows).most_common())
            summary.extend(["", "Most unavailable imports by DLL:"])
            summary.extend(f"  {name}: {n}" for name, n in missing_counts.most_common(30))
            summary.extend(["", "Files that could not be parsed:"])
            summary.extend(self.errors or ["  (none)"])
            summary.extend(["", "Caveats:",
                            "- EXPORTED means symbol exists, not that it works correctly.",
                            "- Runtime LoadLibrary/GetProcAddress calls are not included.",
                            "- API-set mappings and DLL search precedence are approximations.",
                            "- Missing means absent from directories supplied, not from all of Windows."])
            (target / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self.status.set(f"Reports exported to {target}")
        messagebox.showinfo("Export complete", f"Saved to {target}:\n\nall_imports.csv\nmissing_imports.csv\nrequired_dlls.csv\nsummary.txt")


def main():
    if pefile is None:
        # Show the dependency message even when the program is started by double-click.
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("PE Import Inspector", "pefile is required.\n\nInstall it using:\npython -m pip install pefile")
        root.destroy()
        return
    InspectorApp().mainloop()


if __name__ == "__main__":
    main()
