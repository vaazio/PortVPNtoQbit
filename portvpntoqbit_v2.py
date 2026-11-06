"""
PortVPNtoQbit v2.0
Detecta a porta P2P da ProtonVPN e atualiza automaticamente o qBittorrent.
Funciona como ícone na bandeja do sistema (system tray) no Windows.

Melhorias v2:
  - Sem usuário/senha hardcoded (lê de .env ou variáveis de ambiente)
  - LOG_PATH auto-detectado via %LOCALAPPDATA% (funciona em qualquer PC/usuário)
  - Sessão qBittorrent reutilizada (sem login a cada evento)
  - Lock thread-safe em last_port
  - Leitura reversa eficiente do log (sem carregar arquivo inteiro na RAM)
  - Debounce no watchdog (evita disparos em rajada)
  - Tooltip dinâmico mostrando a porta ativa
  - Item "Status" no menu
  - Encerramento limpo do Observer ao sair
  - Retry automático se qBittorrent não estiver rodando ainda
  - Logging estruturado com módulo logging
  - ICON_PATH relativo ao script (compatível com PyInstaller)
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import logging
import threading
from pathlib import Path
from typing import Optional

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pystray import Icon, Menu, MenuItem
from PIL import Image

# ── Suporte a python-dotenv (opcional) ────────────────────────────────────────
try:
    from dotenv import load_dotenv
    _HAS_DOTENV = True
except ImportError:
    _HAS_DOTENV = False

# ── Suporte a notificações Toast ───────────────────────────────────────────────
# Tenta winotify primeiro (mais moderno), depois win10toast, senão só log
try:
    from winotify import Notification, audio as _wn_audio
    _NOTIF_BACKEND = "winotify"
except ImportError:
    try:
        from win10toast import ToastNotifier
        _toaster = ToastNotifier()
        _NOTIF_BACKEND = "win10toast"
    except ImportError:
        _NOTIF_BACKEND = "none"


# ═══════════════════════════════════════════════════════════════════════════════
#  LOGGING  (console + arquivo ao lado do .exe / script)
# ═══════════════════════════════════════════════════════════════════════════════
def _log_file_path() -> Path:
    """Arquivo de log sempre ao lado do .exe ou do script."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "PortVPNtoQbit.log"
    return Path(__file__).resolve().parent / "PortVPNtoQbit.log"

_log_path = _log_file_path()
_fmt = "[%(asctime)s] [%(levelname)-7s] %(message)s"
logging.basicConfig(
    level=logging.DEBUG,
    format=_fmt,
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),                          # console (visível só no .py)
        logging.FileHandler(_log_path, encoding="utf-8"), # arquivo sempre gravado
    ],
)
log = logging.getLogger("PortVPNtoQbit")
log.info(f"=== PortVPNtoQbit iniciando | log: {_log_path} ===")


# ═══════════════════════════════════════════════════════════════════════════════
#  CAMINHOS (compatível com PyInstaller e qualquer usuário)
# ═══════════════════════════════════════════════════════════════════════════════
def _base_dir() -> Path:
    """Diretório base: pasta do executável (PyInstaller) ou do script."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def resource_path(filename: str) -> Path:
    """Caminho para recursos empacotados no binário (ícone, etc.)."""
    return _base_dir() / filename


def config_path(filename: str) -> Path:
    """
    Caminho para arquivos de configuração editáveis pelo usuário (.env).
    Quando rodando como .exe, aponta para a pasta DO executável (não do temp do PyInstaller),
    permitindo que o usuário edite o .env ao lado do .exe.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / filename
    return Path(__file__).resolve().parent / filename


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURAÇÕES  (lidas de .env ou variáveis de ambiente)
# ═══════════════════════════════════════════════════════════════════════════════
_env_file = config_path(".env")
if _HAS_DOTENV and _env_file.exists():
    load_dotenv(_env_file)
    log.info(f"✅ .env carregado de: {_env_file}")
else:
    log.warning(f"⚠️  .env NÃO encontrado em: {_env_file}")
    log.warning("   Usando variáveis de ambiente do sistema (ou valores padrão).")

# LOG_PATH: usa %LOCALAPPDATA% — funciona em qualquer PC e usuário do Windows
_local_appdata = Path(
    os.environ.get("LOCALAPPDATA", "")
    or str(Path.home() / "AppData" / "Local")
)

LOG_PATH = Path(
    os.environ.get(
        "PROTON_LOG_PATH",
        str(_local_appdata / "Proton" / "Proton VPN" / "Logs" / "client-logs.txt"),
    )
)

QB_HOST     = os.environ.get("QB_HOST",     "http://127.0.0.1:8080")
QB_USERNAME = os.environ.get("QB_USERNAME", "admin")
QB_PASSWORD = os.environ.get("QB_PASSWORD", "")

ICON_PATH            = resource_path("portvpntoqbit.ico")
DEBOUNCE_SECONDS     = float(os.environ.get("DEBOUNCE_SECONDS",     "1.0"))
# IMPORTANTE: manter em 1 tentativa para NÃO triggar o ban automático do qBittorrent
# (qBit bane o IP após N logins falhos consecutivos — padrão: 5 falhas = ban de 1h)
LOGIN_RETRY_ATTEMPTS = int(  os.environ.get("LOGIN_RETRY_ATTEMPTS", "1"))
LOGIN_RETRY_DELAY    = float(os.environ.get("LOGIN_RETRY_DELAY",    "5.0"))

# Log das configurações ativas (sem expor senha)
log.info(f"QB_HOST     : {QB_HOST}")
log.info(f"QB_USERNAME : {QB_USERNAME}")
log.info(f"QB_PASSWORD : {'***' if QB_PASSWORD else '(VAZIO — .env não foi lido?)'}")
log.info(f"LOG_PATH    : {LOG_PATH}")


# ═══════════════════════════════════════════════════════════════════════════════
#  ESTADO GLOBAL  (thread-safe via _lock)
# ═══════════════════════════════════════════════════════════════════════════════
_lock:            threading.Lock          = threading.Lock()
_last_port:       Optional[int]           = None
_session:         Optional[requests.Session] = None
_tray_icon:       Optional[Icon]          = None
_observer:        Optional[Observer]      = None
_debounce_timer:  Optional[threading.Timer] = None


# ═══════════════════════════════════════════════════════════════════════════════
#  NOTIFICAÇÕES
# ═══════════════════════════════════════════════════════════════════════════════
def notify(title: str, message: str) -> None:
    """Envia notificação toast do Windows. Sempre faz log independente da UI."""
    log.info(f"🔔 {title} — {message}")
    try:
        if _NOTIF_BACKEND == "winotify":
            toast = Notification(
                app_id="PortVPNtoQbit",
                title=title,
                msg=message,
                duration="short",
                icon=str(ICON_PATH) if ICON_PATH.exists() else "",
            )
            toast.set_audio(_wn_audio.Default, loop=False)
            toast.show()
        elif _NOTIF_BACKEND == "win10toast":
            _toaster.show_toast(title, message, duration=5, threaded=True)
        # "none": somente log, sem toast
    except Exception as e:
        log.warning(f"Falha ao enviar notificação: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
#  LEITURA REVERSA EFICIENTE DO LOG
# ═══════════════════════════════════════════════════════════════════════════════
def _iter_lines_reversed(filepath: Path, chunk_size: int = 8192):
    """
    Itera as linhas do arquivo de trás para frente sem carregar tudo na RAM.
    Ideal para logs grandes onde a entrada mais recente está no final.
    """
    with open(filepath, "rb") as f:
        f.seek(0, 2)        # vai para o fim do arquivo
        remaining = f.tell()
        buffer = b""
        while remaining > 0:
            read_size = min(chunk_size, remaining)
            remaining -= read_size
            f.seek(remaining)
            chunk = f.read(read_size)
            buffer = chunk + buffer
            lines = buffer.split(b"\n")
            buffer = lines[0]           # linha incompleta fica para o próximo chunk
            for line in reversed(lines[1:]):
                yield line.decode("utf-8", errors="replace")
        if buffer:
            yield buffer.decode("utf-8", errors="replace")


def get_latest_forwarded_port() -> Optional[int]:
    """Extrai a porta P2P mais recente do log da ProtonVPN."""
    if not LOG_PATH.exists():
        log.warning(f"Log não encontrado: {LOG_PATH}")
        return None
    try:
        for line in _iter_lines_reversed(LOG_PATH):
            match = re.search(r'Port pair \d+->(\d+)', line)
            if match:
                port = int(match.group(1))
                log.debug(f"Porta VPN detectada no log: {port}")
                return port
    except Exception as e:
        log.error(f"Erro ao ler log: {e}")
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  SESSÃO QBITTORRENT  (reutilizada, com retry e renovação automática)
# ═══════════════════════════════════════════════════════════════════════════════
def _create_session() -> Optional[requests.Session]:
    """Cria e autentica uma nova sessão HTTP com o qBittorrent, com retry."""
    for attempt in range(1, LOGIN_RETRY_ATTEMPTS + 1):
        try:
            sess = requests.Session()
            resp = sess.post(
                f"{QB_HOST}/api/v2/auth/login",
                data={"username": QB_USERNAME, "password": QB_PASSWORD},
                timeout=5,
            )
            body = resp.text.strip()
            logged_in = (
                resp.status_code in (200, 204)
                and body != "Fails."
                and len(sess.cookies) > 0
            )
            if logged_in:
                log.info("✅ Sessão autenticada com qBittorrent.")
                return sess
            else:
                log.warning(
                    f"Falha no login (tentativa {attempt}/{LOGIN_RETRY_ATTEMPTS}): "
                    f"HTTP {resp.status_code} {body!r}"
                )
        except requests.exceptions.ConnectionError:
            log.warning(
                f"qBittorrent indisponível (tentativa {attempt}/{LOGIN_RETRY_ATTEMPTS}). "
                f"Próxima tentativa em {LOGIN_RETRY_DELAY}s..."
            )
        except Exception as e:
            log.error(f"Erro inesperado ao autenticar: {e}")

        if attempt < LOGIN_RETRY_ATTEMPTS:
            time.sleep(LOGIN_RETRY_DELAY)

    log.error("❌ Não foi possível autenticar no qBittorrent após todas as tentativas.")
    return None


def _get_session() -> Optional[requests.Session]:
    """Retorna a sessão ativa. Se inválida/nula, cria uma nova."""
    global _session
    with _lock:
        if _session is None:
            _session = _create_session()
        return _session


def _invalidate_session() -> None:
    """Marca a sessão como inválida para ser recriada na próxima chamada."""
    global _session
    with _lock:
        _session = None
        log.debug("Sessão invalidada — será recriada na próxima operação.")


# ═══════════════════════════════════════════════════════════════════════════════
#  API QBITTORRENT
# ═══════════════════════════════════════════════════════════════════════════════
def get_current_qbittorrent_port() -> Optional[int]:
    """Consulta a porta de escuta atual configurada no qBittorrent."""
    sess = _get_session()
    if not sess:
        return None
    try:
        resp = sess.get(f"{QB_HOST}/api/v2/app/preferences", timeout=5)
        if resp.status_code == 200:
            return resp.json().get("listen_port")
        if resp.status_code == 403:
            log.warning("Sessão expirada ao consultar porta.")
            _invalidate_session()
    except Exception as e:
        log.error(f"Erro ao consultar porta do qBittorrent: {e}")
        _invalidate_session()
    return None


def set_qbittorrent_port(port: int) -> bool:
    """Aplica a porta de escuta no qBittorrent. Retorna True se bem-sucedido."""
    sess = _get_session()
    if not sess:
        notify("Erro de Conexão", "Não foi possível conectar ao qBittorrent")
        return False
    try:
        payload = {"json": json.dumps({"listen_port": port})}
        resp = sess.post(
            f"{QB_HOST}/api/v2/app/setPreferences", data=payload, timeout=5
        )
        if resp.status_code == 200:
            log.info(f"✅ Porta atualizada → {port}")
            notify("Porta Atualizada ✅", f"Nova porta P2P: {port}")
            _update_tray_tooltip(port)
            return True
        if resp.status_code == 403:
            _invalidate_session()
            log.warning("Sessão expirada ao atualizar porta.")
        else:
            log.error(f"Falha ao atualizar porta: HTTP {resp.status_code} — {resp.text}")
            notify("Erro", f"Falha ao atualizar porta (HTTP {resp.status_code})")
    except Exception as e:
        log.error(f"Exceção ao atualizar porta: {e}")
        _invalidate_session()
    return False


# ═══════════════════════════════════════════════════════════════════════════════
#  LÓGICA DE SINCRONIZAÇÃO
# ═══════════════════════════════════════════════════════════════════════════════
def sync_port(manual: bool = False) -> None:
    """
    Lê a porta atual da VPN e sincroniza com o qBittorrent se necessário.
    'manual=True' quando disparado pelo botão do menu (fornece feedback mesmo
    se nada mudou).
    """
    global _last_port

    vpn_port = get_latest_forwarded_port()
    if not vpn_port:
        msg = "Porta VPN não encontrada no log"
        log.warning(msg)
        if manual:
            notify("⚠️ Porta não encontrada", msg)
        return

    qb_port = get_current_qbittorrent_port()

    with _lock:
        already_tracked = (vpn_port == _last_port)

    if vpn_port == qb_port:
        log.info(f"Porta já sincronizada: {vpn_port}")
        with _lock:
            _last_port = vpn_port
        _update_tray_tooltip(vpn_port)
        if manual:
            notify("Porta OK ✅", f"qBittorrent já usa a porta {vpn_port}")
        return

    # Porta mudou ou não estava sincronizada
    log.info(f"Sincronizando: qBit={qb_port} → VPN={vpn_port}")
    if set_qbittorrent_port(vpn_port):
        with _lock:
            _last_port = vpn_port


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOLTIP DINÂMICO
# ═══════════════════════════════════════════════════════════════════════════════
def _update_tray_tooltip(port: Optional[int] = None) -> None:
    """Atualiza o tooltip do ícone na bandeja com a porta ativa."""
    global _tray_icon
    if _tray_icon is None:
        return
    label = (
        f"Port VPN → qBittorrent  |  Porta: {port}"
        if port
        else "Port VPN → qBittorrent"
    )
    try:
        _tray_icon.title = label
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
#  WATCHDOG COM DEBOUNCE
# ═══════════════════════════════════════════════════════════════════════════════
class LogHandler(FileSystemEventHandler):
    """Monitora modificações no log da VPN e dispara a sincronização."""

    def on_modified(self, event):
        if Path(event.src_path).resolve() != LOG_PATH.resolve():
            return

        global _debounce_timer
        # Cancela timer anterior para agrupar eventos em rajada
        if _debounce_timer is not None:
            _debounce_timer.cancel()

        _debounce_timer = threading.Timer(DEBOUNCE_SECONDS, sync_port)
        _debounce_timer.daemon = True
        _debounce_timer.start()
        log.debug(f"Log modificado — debounce de {DEBOUNCE_SECONDS}s iniciado.")


# ═══════════════════════════════════════════════════════════════════════════════
#  MONITOR DE LOG
# ═══════════════════════════════════════════════════════════════════════════════
def start_monitor() -> None:
    """Inicia o watchdog e faz a sincronização inicial."""
    global _observer

    log.info(f"📂 Monitorando log: {LOG_PATH}")
    if not LOG_PATH.parent.exists():
        log.warning(
            f"Pasta do log não existe: {LOG_PATH.parent}\n"
            "Verifique se a ProtonVPN está instalada neste PC."
        )

    # Sincronização na inicialização
    sync_port()

    event_handler = LogHandler()
    _observer = Observer()
    _observer.schedule(event_handler, path=str(LOG_PATH.parent), recursive=False)
    _observer.start()
    log.info("👁️  Watchdog iniciado.")

    def _poll_loop(interval: float = 300.0):
        """Verifica o log periodicamente (o watchdog não é confiável no Windows
        para arquivos mantidos abertos por outro processo)."""
        while True:
            time.sleep(interval)
            try:
                port = get_latest_forwarded_port()
                with _lock:
                    changed = port is not None and port != _last_port
                if changed:
                    log.info(f"🔄 Mudança de porta detectada no log: {port}")
                    sync_port()
            except Exception as e:
                log.error(f"Erro no polling: {e}")

    threading.Thread(target=_poll_loop, daemon=True).start()
    log.info("⏱️  Polling iniciado (10s).")


# ═══════════════════════════════════════════════════════════════════════════════
#  MENU DO SYSTEM TRAY
# ═══════════════════════════════════════════════════════════════════════════════
def _action_verificar(icon, item):
    """Menu: Verificar Agora — força sincronização manual."""
    threading.Thread(
        target=sync_port, kwargs={"manual": True}, daemon=True
    ).start()


def _action_status(icon, item):
    """Menu: Status — exibe as portas atuais da VPN e do qBittorrent."""
    def _fetch():
        vpn_port = get_latest_forwarded_port()
        qb_port  = get_current_qbittorrent_port()
        notify(
            "Status das Portas 📊",
            f"VPN: {vpn_port or 'N/A'}     qBittorrent: {qb_port or 'N/A'}",
        )
    threading.Thread(target=_fetch, daemon=True).start()


def _action_sair(icon, item):
    """Menu: Sair — encerra watchdog e remove ícone da bandeja."""
    global _observer
    log.info("Encerrando PortVPNtoQbit...")
    if _observer and _observer.is_alive():
        _observer.stop()
        _observer.join(timeout=3)
        log.info("Watchdog encerrado.")
    icon.stop()


# ═══════════════════════════════════════════════════════════════════════════════
#  INICIALIZAÇÃO
# ═══════════════════════════════════════════════════════════════════════════════
def run() -> None:
    global _tray_icon

    # Carrega ícone (cria placeholder se não encontrar)
    if ICON_PATH.exists():
        image = Image.open(ICON_PATH)
    else:
        log.warning(f"Ícone não encontrado: {ICON_PATH} — usando placeholder.")
        image = Image.new("RGB", (64, 64), color=(30, 144, 255))

    menu = Menu(
        MenuItem("Verificar Agora",   _action_verificar),
        MenuItem("Status das Portas", _action_status),
        Menu.SEPARATOR,
        MenuItem("Sair",              _action_sair),
    )

    _tray_icon = Icon(
        name="PortVPNtoQbit",
        icon=image,
        title="Port VPN → qBittorrent",
        menu=menu,
    )

    # Inicia monitor em thread daemon
    threading.Thread(target=start_monitor, daemon=True).start()

    log.info("🚀 PortVPNtoQbit iniciado. Ícone na bandeja do sistema.")
    _tray_icon.run()


if __name__ == "__main__":
    run()
