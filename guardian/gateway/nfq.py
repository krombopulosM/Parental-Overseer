"""Bridges the kernel's NFQUEUE to the inspector: each queued packet gets a
verdict - accept, drop, or reset (marked 0xDEAD and re-injected so the
firewall answers with a TCP RST and the app fails fast instead of hanging)."""
from __future__ import annotations

import threading
import time
import traceback

from ..inspector import ACCEPT, RESET
from .nft import M_RESET


def _mac(hw) -> str | None:
    if not hw or len(hw) < 6:
        return None
    return ":".join(f"{b:02x}" for b in hw[:6])


class NfqRunner:
    def __init__(self, inspector, queue_num: int = 0, fail_open: bool = False):
        self.inspector = inspector
        self.queue_num = queue_num
        self.fail_open = fail_open
        self.handled = 0
        self.errors = 0
        self.error = None
        self.running = False

    def _cb(self, pkt):
        try:
            v = self.inspector.inspect(pkt.get_payload(), _mac(pkt.get_hw()))
        except Exception:
            self.errors += 1
            if self.errors < 20:
                traceback.print_exc()
            pkt.accept() if self.fail_open else pkt.drop()
            return
        self.handled += 1
        if v.action == ACCEPT:
            pkt.accept()
        elif v.action == RESET:
            pkt.set_mark(M_RESET)
            pkt.repeat()
        else:
            pkt.drop()

    def start(self):
        from netfilterqueue import NetfilterQueue   # Linux only; imported lazily

        def run():
            nfq = NetfilterQueue()
            for attempt in range(30):          # a restarting predecessor may still hold the queue
                try:
                    nfq.bind(self.queue_num, self._cb, max_len=8192)
                    break
                except OSError as e:
                    self.error = f"can't bind queue {self.queue_num}: {e}"
                    time.sleep(0.5)
            else:
                print(f"[nfq] {self.error} - children's connections wait (fail closed) until this is fixed")
                return
            self.error = None
            self.running = True
            try:
                nfq.run(block=True)
            except Exception as e:
                self.error = str(e)
                print(f"[nfq] stopped: {e}")
            finally:
                self.running = False
                nfq.unbind()
        threading.Thread(target=run, name="nfqueue", daemon=True).start()
