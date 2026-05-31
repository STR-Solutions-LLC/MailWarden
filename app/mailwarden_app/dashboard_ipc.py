# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Loopback RAISE channel for the Dashboard window.

Why this exists: the menu bar agent and the Dashboard are separate processes
(same bundle). When the Dashboard is MINIMIZED, another process can use
NSRunningApplication.activateWithOptions_ to raise an app's *visible* windows,
but it CANNOT un-minimize a window — only the window's OWN process can call
Tk's deiconify(). So "Open Dashboard" from the menu bar (or a Dock click that
another process handles) does nothing when the window is minimized.

The fix is a tiny in-process server: while the Dashboard runs, it listens on a
loopback TCP port and, on receiving "RAISE", marshals theme.bring_to_front()
(deiconify + lift + focus_force + topmost toggle) back onto the Tk thread.
Other processes connect to 127.0.0.1:<port> and send "RAISE" — see
dashboard_instance.raise_existing().

Safety properties:
  - Binds 127.0.0.1 only (never reachable off-box).
  - Port 0 → the OS picks a free port; we publish it to RUN_DIR/dashboard.port.
  - The accept loop runs on a DAEMON thread, so it can never keep the process
    alive after the Tk mainloop exits (the phantom-Dock-tile risk).
  - stop() closes the socket and removes the port file; it's called from both
    dashboard._on_close and the app_entrypoint finally block, mirroring how
    the pidfile is cleaned up.
"""
from __future__ import annotations

import socket
import threading

from . import paths
from . import startup_log


class DashboardRaiseServer:
    """A loopback socket server that raises (un-minimizes) the Dashboard on
    request. One instance per Dashboard process."""

    def __init__(self, dashboard, bring_to_front):
        # `dashboard` is the tk.Tk root; `bring_to_front` is theme.bring_to_front
        # (injected so this module doesn't import theme/tkinter and stays cheap).
        self._dashboard = dashboard
        self._bring_to_front = bring_to_front
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        """Bind 127.0.0.1:0, publish the port, and start the accept loop.
        Best-effort: a bind failure must not stop the Dashboard from opening."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(5)
            port = sock.getsockname()[1]
            self._sock = sock
            self._write_port(port)
            self._thread = threading.Thread(
                target=self._accept_loop, name="dashboard-raise", daemon=True)
            self._thread.start()
            startup_log.step(f"dashboard_ipc: RAISE server listening on 127.0.0.1:{port}")
        except OSError as e:
            startup_log.step(
                f"dashboard_ipc: could not start RAISE server (non-fatal): "
                f"{type(e).__name__}: {e}")
            self._sock = None

    def _write_port(self, port: int) -> None:
        try:
            paths.RUN_DIR.mkdir(parents=True, exist_ok=True)
            paths.DASHBOARD_PORT.write_text(str(port), encoding="utf-8")
        except OSError as e:
            startup_log.step(f"dashboard_ipc: could not write port file: {e}")

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()  # type: ignore[union-attr]
            except OSError:
                # Socket closed by stop(), or transient error — exit the loop.
                break
            try:
                conn.settimeout(2.0)
                data = conn.recv(64)
                if data and b"RAISE" in data:
                    self._do_raise()
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _do_raise(self) -> None:
        """Marshal the actual window-raise onto the Tk main thread. Calling Tk
        from this accept-loop thread directly is unsafe."""
        try:
            self._dashboard.after(
                0, lambda: self._bring_to_front(self._dashboard))
            startup_log.step("dashboard_ipc: RAISE received; bring_to_front scheduled")
        except Exception as e:  # noqa: BLE001
            startup_log.step(f"dashboard_ipc: RAISE handling failed: {e}")

    def stop(self) -> None:
        """Close the socket and remove the port file. Idempotent. Called from
        dashboard._on_close and the app_entrypoint finally block so no port
        file outlives the process."""
        self._stop.set()
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        try:
            # Only remove the port file if it still points at us is not
            # knowable here; the daemon thread + pidfile guard already prevent
            # cross-instance confusion, and a stale port file is harmless
            # (raise_existing fails the connect and falls through to spawn).
            paths.DASHBOARD_PORT.unlink()
        except (FileNotFoundError, OSError):
            pass
