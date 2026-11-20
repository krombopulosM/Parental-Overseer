"""The Card Maker window (tkinter: part of Python, no extra installs)."""
from __future__ import annotations

import json
import os
import queue
import shlex
import subprocess
import sys
import tempfile
import threading

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cardmaker import core, drives

TITLE = "Parental Gateway Card Maker"
STAGES = {"download": "Downloading Parental Gateway", "check-download": "Checking the download",
          "prepare": "Getting ready", "write": "Writing the card", "verify": "Checking the card"}


def helper_cmd() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "__main__.py")]


def write_elevated(args: list[str], on_progress) -> dict:
    """Run the write as administrator in a separate process (macOS, Linux) and
    relay its progress. The password never goes on a command line: only its hash,
    in a file only this user can read."""
    pf = tempfile.NamedTemporaryFile("w", suffix=".progress", delete=False)
    pf.close()
    cmd = helper_cmd() + args + ["--progress-file", pf.name, "-y"]
    if sys.platform == "darwin":
        script = shlex.join(cmd).replace("\\", "\\\\").replace('"', '\\"')
        launch = ["osascript", "-e", f'do shell script "{script}" with administrator privileges']
    elif sys.platform == "win32":
        raise core.CardError("Please start the Card Maker as administrator (right-click > Run as administrator).")
    else:
        launch = ["pkexec", *cmd]
    proc = subprocess.Popen(launch, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    seen = 0
    result = None
    try:
        while True:
            done = proc.poll() is not None
            with open(pf.name) as fh:
                lines = fh.read().splitlines()
            for line in lines[seen:]:
                msg = json.loads(line)
                if "error" in msg:
                    raise core.CardError(msg["error"])
                if "result" in msg:
                    result = msg["result"]
                else:
                    on_progress(msg["stage"], msg["done"], msg["total"])
            seen = len(lines)
            if done:
                break
            threading.Event().wait(0.3)
        if result is None:
            err = (proc.stderr.read() or "").strip()
            if proc.returncode in (126, 127) or "cancel" in err.lower() or "-128" in err:
                raise core.CardError("Writing was cancelled (administrator permission is needed to write a card).")
            raise core.CardError(err or "The card couldn't be written.")
        return result
    finally:
        try:
            os.remove(pf.name)
        except OSError:
            pass


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(TITLE)
        root.minsize(560, 0)
        self.q: queue.Queue = queue.Queue()
        self.busy = False
        style = ttk.Style()
        if sys.platform.startswith("linux"):
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("TkDefaultFont", 15, "bold"))
        style.configure("Step.TLabel", font=("TkDefaultFont", 11, "bold"))
        style.configure("Muted.TLabel", foreground="#5d6a80")
        style.configure("Big.TButton", padding=(18, 8))

        outer = ttk.Frame(root, padding=18)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Parental Gateway", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text="Make a card that turns a Raspberry Pi into your family's internet gateway.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 12))
        nb = ttk.Notebook(outer)
        nb.pack(fill="both", expand=True)
        self.make = ttk.Frame(nb, padding=16)
        self.pw = ttk.Frame(nb, padding=16)
        nb.add(self.make, text="  Make a card  ")
        nb.add(self.pw, text="  Change a card's password  ")
        self._build_make()
        self._build_password()
        self.refresh_drives()
        root.after(150, self._poll)

    # ------------------------------------------------------------- make a card
    def _build_make(self):
        f = self.make
        f.columnconfigure(1, weight=1)
        r = 0
        ttk.Label(f, text="1   Card or USB drive", style="Step.TLabel").grid(row=r, column=0, columnspan=3, sticky="w")
        r += 1
        self.drive_var = tk.StringVar()
        self.drive_box = ttk.Combobox(f, textvariable=self.drive_var, state="readonly", width=44)
        self.drive_box.grid(row=r, column=0, columnspan=2, sticky="we", pady=4)
        ttk.Button(f, text="Refresh", command=self.refresh_drives).grid(row=r, column=2, padx=(8, 0))
        r += 1
        ttk.Label(f, text="Only SD cards and USB drives are listed. A 16 GB or larger card is plenty.",
                  style="Muted.TLabel").grid(row=r, column=0, columnspan=3, sticky="w")
        r += 1
        self.src_var = tk.StringVar(value="latest")
        self.file_var = tk.StringVar()
        src = ttk.Frame(f)
        src.grid(row=r, column=0, columnspan=3, sticky="w", pady=(6, 0))
        ttk.Radiobutton(src, text="Latest version (downloads about 500 MB)", value="latest",
                        variable=self.src_var).pack(side="left")
        ttk.Radiobutton(src, text="A file I downloaded…", value="file", variable=self.src_var,
                        command=self.pick_file).pack(side="left", padx=(12, 0))
        r += 1
        self.file_label = ttk.Label(f, textvariable=self.file_var, style="Muted.TLabel")
        self.file_label.grid(row=r, column=0, columnspan=3, sticky="w")

        r += 1
        ttk.Label(f, text="2   Dashboard password", style="Step.TLabel").grid(row=r, column=0, columnspan=3,
                                                                              sticky="w", pady=(14, 0))
        r += 1
        self.p1, self.p2 = tk.StringVar(), tk.StringVar()
        ttk.Label(f, text="Password").grid(row=r, column=0, sticky="w")
        ttk.Entry(f, textvariable=self.p1, show="•").grid(row=r, column=1, columnspan=2, sticky="we", pady=3)
        r += 1
        ttk.Label(f, text="Again").grid(row=r, column=0, sticky="w")
        ttk.Entry(f, textvariable=self.p2, show="•").grid(row=r, column=1, columnspan=2, sticky="we", pady=3)
        r += 1
        ttk.Label(f, text="You'll sign in to the dashboard with this. Keep it from the children.\n"
                         "Only a scrambled form of it goes on the card.", style="Muted.TLabel")\
            .grid(row=r, column=0, columnspan=3, sticky="w")
        r += 1
        self.name_var = tk.StringVar(value="family")
        ttk.Label(f, text="Dashboard name").grid(row=r, column=0, sticky="w", pady=(8, 0))
        ne = ttk.Entry(f, textvariable=self.name_var, width=18)
        ne.grid(row=r, column=1, sticky="w", pady=(8, 0))
        self.addr_label = ttk.Label(f, style="Muted.TLabel")
        self.addr_label.grid(row=r, column=2, sticky="w", pady=(8, 0))
        self.name_var.trace_add("write", lambda *a: self.addr_label.configure(
            text=f"→ http://{(self.name_var.get() or 'family').strip().lower()}.local"))
        self.name_var.set("family")

        r += 1
        self.adv = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Advanced: SSH key (for technical users)", variable=self.adv,
                        command=self._toggle_adv).grid(row=r, column=0, columnspan=3, sticky="w", pady=(8, 0))
        r += 1
        self.ssh_text = tk.Text(f, height=3, width=60, wrap="char")
        self.ssh_row = r

        r += 1
        ttk.Label(f, text="3   Write", style="Step.TLabel").grid(row=r, column=0, columnspan=3, sticky="w", pady=(14, 0))
        r += 1
        self.bar = ttk.Progressbar(f, maximum=1000)
        self.bar.grid(row=r, column=0, columnspan=3, sticky="we", pady=4)
        r += 1
        self.status = ttk.Label(f, text="", wraplength=520, justify="left")
        self.status.grid(row=r, column=0, columnspan=3, sticky="w")
        r += 1
        self.go = ttk.Button(f, text="Write card", style="Big.TButton", command=self.start)
        self.go.grid(row=r, column=0, columnspan=3, sticky="e", pady=(10, 0))

    def _toggle_adv(self):
        if self.adv.get():
            self.ssh_text.grid(row=self.ssh_row, column=0, columnspan=3, sticky="we", pady=4)
        else:
            self.ssh_text.grid_remove()

    def pick_file(self):
        p = filedialog.askopenfilename(title="Choose the Parental Gateway image",
                                       filetypes=[("Card images", "*.img.xz *.img"), ("All files", "*")])
        if p:
            self.file_var.set(p)
        elif not self.file_var.get():
            self.src_var.set("latest")

    def refresh_drives(self):
        try:
            self.drives = drives.list_drives()
        except Exception as e:                       # noqa: BLE001 - shown to the user
            self.drives = []
            self.status.configure(text=f"Couldn't list the drives: {e}")
        labels = [d.label for d in self.drives] or ["Insert an SD card or USB drive, then click Refresh"]
        self.drive_box["values"] = labels
        self.drive_box.current(0)

    def start(self):
        if self.busy:
            return
        if not self.drives:
            return messagebox.showinfo(TITLE, "Insert an SD card or USB drive first, then click Refresh.")
        drive = self.drives[self.drive_box.current()]
        p1, p2 = self.p1.get(), self.p2.get()
        if len(p1) < 8:
            return messagebox.showwarning(TITLE, "Choose a password of at least 8 characters.")
        if p1 != p2:
            return messagebox.showwarning(TITLE, "The two passwords don't match.")
        if self.src_var.get() == "file" and not self.file_var.get():
            return messagebox.showwarning(TITLE, "Choose the image file, or pick 'Latest version'.")
        try:
            settings = core.make_settings(p1, self.name_var.get(),
                                          self.ssh_text.get("1.0", "end").strip() if self.adv.get() else None)
        except (core.CardError, ValueError) as e:
            return messagebox.showwarning(TITLE, str(e))
        if not messagebox.askyesno(TITLE, f"Everything on\n\n    {drive.label}\n\nwill be erased. Continue?",
                                   icon="warning"):
            return
        self.busy = True
        self.go.state(["disabled"])
        image = self.file_var.get() if self.src_var.get() == "file" else None
        threading.Thread(target=self._work, args=(drive, image, settings), daemon=True).start()

    def _work(self, drive, image, settings):
        prog = lambda s, d, t: self.q.put(("progress", s, d, t))        # noqa: E731
        try:
            info = None
            if image is None:
                self.q.put(("status", "Finding the latest version…"))
                info = core.fetch_info()
                image = core.download(info, prog)
            if drives.is_admin():
                res = core.write_image(image, drives.open_target(drive), settings=settings,
                                       offset=(info or {}).get("settings_offset"),
                                       size=core.image_size(image, info), progress=prog)
            else:
                fd, sf = tempfile.mkstemp(suffix=".settings")
                with os.fdopen(fd, "wb") as fh:
                    fh.write(settings)
                extra = []
                if info:
                    fd2, inf = tempfile.mkstemp(suffix=".json")
                    with os.fdopen(fd2, "w") as fh:
                        json.dump(info, fh)
                    extra = ["--info-file", inf]
                try:
                    self.q.put(("status", "Asking for permission to write the card…"))
                    res = write_elevated(["write", "--drive", drive.id, "--image", image, "--settings-file", sf,
                                          *extra], prog)
                finally:
                    for p in [sf] + extra[1:]:
                        try:
                            os.remove(p)
                        except OSError:
                            pass
            self.q.put(("done", res))
        except Exception as e:                       # noqa: BLE001 - shown to the user
            self.q.put(("error", str(e)))

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "status":
                    self.status.configure(text=msg[1])
                elif kind == "progress":
                    _, stage, done, total = msg
                    frac = done / total if total else 0
                    self.bar["value"] = int(frac * 1000)
                    extra = f"  {done / 1e6:,.0f} of {total / 1e6:,.0f} MB" if total else ""
                    self.status.configure(text=f"{STAGES.get(stage, stage)}… {int(frac * 100)}%{extra}")
                elif kind == "done":
                    self.busy = False
                    self.go.state(["!disabled"])
                    self.bar["value"] = 1000
                    name = (self.name_var.get() or "family").strip().lower()
                    self.status.configure(text="Done - the card is ready.")
                    messagebox.showinfo(TITLE, "The card is ready.\n\n"
                                        "1. Put it in the Raspberry Pi.\n"
                                        "2. Plug one network cable into your internet router and the other into "
                                        "your Wi-Fi access point (either port - the Pi works out which is which).\n"
                                        "3. Plug in the power.\n\n"
                                        f"After about two minutes open  http://{name}.local  from a phone or "
                                        "computer at home and sign in with your password.")
                elif kind == "error":
                    self.busy = False
                    self.go.state(["!disabled"])
                    self.status.configure(text="Not finished: " + msg[1])
                    messagebox.showerror(TITLE, msg[1])
        except queue.Empty:
            pass
        self.root.after(150, self._poll)

    # ------------------------------------------------------------- change a card's password
    def _build_password(self):
        f = self.pw
        f.columnconfigure(1, weight=1)
        ttk.Label(f, text="Forgot the dashboard password? Take the card out of the Pi and put it in this computer.",
                  wraplength=520, justify="left").grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(f, text="Card").grid(row=1, column=0, sticky="w", pady=(12, 0))
        self.card_var = tk.StringVar()
        self.card_box = ttk.Combobox(f, textvariable=self.card_var, state="readonly")
        self.card_box.grid(row=1, column=1, sticky="we", pady=(12, 0))
        ttk.Button(f, text="Refresh", command=self.refresh_cards).grid(row=1, column=2, padx=(8, 0), pady=(12, 0))
        self.q1, self.q2 = tk.StringVar(), tk.StringVar()
        ttk.Label(f, text="New password").grid(row=2, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(f, textvariable=self.q1, show="•").grid(row=2, column=1, columnspan=2, sticky="we", pady=(10, 0))
        ttk.Label(f, text="Again").grid(row=3, column=0, sticky="w")
        ttk.Entry(f, textvariable=self.q2, show="•").grid(row=3, column=1, columnspan=2, sticky="we", pady=3)
        ttk.Button(f, text="Save on the card", command=self.save_password, style="Big.TButton")\
            .grid(row=4, column=0, columnspan=3, sticky="e", pady=(12, 0))
        ttk.Label(f, text="Then put the card back in the Pi and restart it (unplug the power for 10 seconds).",
                  style="Muted.TLabel").grid(row=5, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.refresh_cards()

    def refresh_cards(self):
        self.cards = core.card_volumes()
        self.card_box["values"] = self.cards or ["No card found - put it in and click Refresh"]
        self.card_box.current(0)

    def save_password(self):
        if not self.cards:
            return messagebox.showinfo(TITLE, "Put the card in this computer, wait for its 'bootfs' drive to "
                                              "appear, then click Refresh.")
        if len(self.q1.get()) < 8 or self.q1.get() != self.q2.get():
            return messagebox.showwarning(TITLE, "Enter the same password (8+ characters) twice.")
        try:
            core.update_card(self.cards[self.card_box.current()], password=self.q1.get())
        except (OSError, core.CardError) as e:
            return messagebox.showerror(TITLE, str(e))
        messagebox.showinfo(TITLE, "Saved. Eject the card, put it back in the Pi and restart the Pi.\n"
                                   "The new password works once it has started.")


def run() -> int:
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0
