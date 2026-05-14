from __future__ import annotations

from . import bridge as _bridge

globals().update({
    key: value
    for key, value in _bridge.__dict__.items()
    if key not in {"__builtins__", "__name__", "__package__", "__file__", "__cached__", "__doc__", "__spec__", "__loader__"}
})

class DebugLoggingConfigurator:
    """
    Self-contained logging configurator (Option A):
    - Console handler to STDOUT at --console-level (default INFO)  <-- keeps dashboard non-scrolling
    - Optional file handler (--log-file) at --file-level (default: --log)
    - Optional "route DEBUG to stderr" mirror (DebugToStderrHandler), default OFF
    """

    # ---- CLI integration -----------------------------------------------------------
    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        # Add only if not already present (safe if called multiple times)
        def _has(opt: str) -> bool:
            try:
                return any(opt in a.option_strings for a in p._actions)
            except Exception:
                return False

        if not _has('--log'):
            p.add_argument('--log', default='WARNING',
                           help='logging level (default WARNING; try INFO or DEBUG) be aware of --console-level and --file-level')
        if not _has('--log-file'):
            p.add_argument('--log-file', default=None,
                           help='file path to also write logs enabled by --log')
        if not _has('--log-file-max-bytes'):
            p.add_argument('--log-file-max-bytes', type=int, default=0,
                           help='maximum on-disk log file size in bytes before rotation; 0 disables rotation')
        if not _has('--log-file-backup-count'):
            p.add_argument('--log-file-backup-count', type=int, default=5,
                           help='number of rotated log files to keep when --log-file-max-bytes is enabled')

        # NEW: split console/file levels to avoid screen flooding at DEBUG
        if not _has('--console-level'):
            p.add_argument('--console-level', default='INFO',
                           help='console (stdout) logging level (default INFO)')
        if not _has('--file-level'):
            p.add_argument('--file-level', default='DEBUG',
                           help='file logging level (default: same as --log)')

        # Change default: DO NOT mirror DEBUG to stderr unless explicitly requested
        if not _has('--debug-stderr'):
            p.add_argument('--debug-stderr', action='store_true', default=False,
                           help='mirror DEBUG lines to stderr (default: off)')
        if not _has('--admin-web-log-max-lines'):
            p.add_argument('--admin-web-log-max-lines', type=int, default=DEFAULT_ADMIN_WEB_LOG_MAX_LINES,
                           help='maximum number of debug log lines kept in memory for the admin web log view')


    @staticmethod
    def from_args(args: argparse.Namespace) -> "DebugLoggingConfigurator":
        return DebugLoggingConfigurator(
            level_name=getattr(args, 'log', 'WARNING'),
            console_level_name=getattr(args, 'console_level', 'INFO'),
            file_level_name=getattr(args, 'file_level', None),
            file_path=getattr(args, 'log_file', None),
            file_max_bytes=getattr(args, 'log_file_max_bytes', 0),
            file_backup_count=getattr(args, 'log_file_backup_count', 5),
            debug_to_stderr=bool(getattr(args, 'debug_stderr', False)),
            admin_web_log_max_lines=getattr(args, 'admin_web_log_max_lines', DEFAULT_ADMIN_WEB_LOG_MAX_LINES),
        )
        # capture per-section log overrides into the object
        for k, v in vars(args).items():
            if k.startswith("log_"):
                setattr(obj, k, v)
        return obj
        
    @staticmethod
    def add_per_section_log_options(p: argparse.ArgumentParser, sections: list[str]):
        for sec in sections:
            opt = f"--log-{sec.replace('_', '-')}"
            p.add_argument(opt, default=None,
                help=f"Override log level for component '{sec}' (e.g. DEBUG, INFO, WARNING)")

    @staticmethod
    def debug_logger_status(lg: logging.Logger):
        """Emit diagnostics showing how logger activation behaved."""

        
        # Emit activation report (always via INFO to guarantee visibility)
        root = logging.getLogger()
        root.info(f"[LOGCFG]   Logger '{lg.name}' ")
        root.info(f"[LOGCFG]   Effective level: {logging.getLevelName(lg.getEffectiveLevel())}")
        root.info(f"[LOGCFG]   Explicit level:  {logging.getLevelName(lg.level)}")
        root.info(f"[LOGCFG]   Handlers:        {len(lg.handlers)} (root={len(root.handlers)})")
        root.info(f"[LOGCFG]   Propagate:       {lg.propagate}")


    # ---- lifecycle ----------------------------------------------------------------
    def __init__(self, level_name: str = 'WARNING',
                 console_level_name: str = 'INFO',
                 file_level_name: Optional[str] = None,
                 file_path: Optional[str] = None,
                 file_max_bytes: int = 0,
                 file_backup_count: int = 5,
                 debug_to_stderr: bool = False,
                 admin_web_log_max_lines: int = DEFAULT_ADMIN_WEB_LOG_MAX_LINES):
        self.level_name = (level_name or 'WARNING').upper()
        self.console_level_name = (console_level_name or 'INFO').upper()
        self.file_level_name = (file_level_name.upper() if file_level_name else None)
        self.file_path = file_path
        self.file_max_bytes = max(0, int(file_max_bytes))
        self.file_backup_count = max(0, int(file_backup_count))
        self.debug_to_stderr = debug_to_stderr
        self.admin_web_log_max_lines = max(1, int(admin_web_log_max_lines))

    def apply(self) -> logging.Logger:
        """
        Configure the root logger:
        - remove any preexisting handlers (to avoid duplicates)
        - add console (stdout) handler at --console-level
        - add optional file handler at --file-level (default --log)
        - add optional DebugToStderrHandler for DEBUG mirroring
        Returns the root logger.
        """
        root = logging.getLogger()

        # Clear any default handlers to avoid duplicates when embedding
        while root.handlers:
            try:
                root.handlers.pop()
            except Exception:
                break

        # Levels and format
        root_level = logging.DEBUG  # capture everything; handlers will filter
        console_level = getattr(logging, self.console_level_name, logging.INFO)
        file_level = getattr(logging, (self.file_level_name or self.level_name), logging.WARNING)
        root.setLevel(root_level)
        fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
        configure_debug_log_ring(self.admin_web_log_max_lines)


        # Optional file handler (can be DEBUG)
        if self.file_path:
            try:
                if self.file_max_bytes > 0:
                    fh = logging.handlers.RotatingFileHandler(
                        self.file_path,
                        maxBytes=self.file_max_bytes,
                        backupCount=max(1, self.file_backup_count),
                        encoding="utf-8",
                    )
                else:
                    fh = logging.FileHandler(self.file_path, encoding="utf-8")
                fh.setLevel(file_level)
                fh.setFormatter(fmt)
                root.addHandler(fh)
            except Exception as e:
                sys.stderr.write(f'Failed to open log file {self.file_path}: {e}\n')
                sys.stderr.flush()

        # Console handler -> STDOUT (quiet by default)
        ch = logging.StreamHandler(stream=sys.stdout)
        ch.setLevel(console_level)
        ch.setFormatter(fmt)
        root.addHandler(ch)

        # In-memory ring used by admin web /api/logs.
        mem = InMemoryDebugLogHandler()
        mem.setLevel(logging.DEBUG)
        mem.setFormatter(fmt)
        root.addHandler(mem)


        # Optional: route DEBUG to stderr without affecting global level
        if self.debug_to_stderr:
            try:
                dbg_handler = DebugToStderrHandler()
                dbg_handler.setLevel(logging.DEBUG)
                dbg_handler.setFormatter(logging.Formatter('%(message)s'))
                root.addHandler(dbg_handler)
            except Exception:
                pass

        # Parity with basicConfig (noop if handlers already exist)
        logging.basicConfig(
            level=root_level,
            format='%(asctime)s %(levelname)s %(message)s'
        )
        return root

# ============================ End Logging / Debug Config =============================


# ================================================================
# Protocol framing layer (MAGIC + PAYLOAD + PADDING)
# ================================================================
