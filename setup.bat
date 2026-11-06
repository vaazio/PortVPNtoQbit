@echo off
:: Setup inicial do PortVPNtoQbit v2
:: Execute como Administrador na primeira vez

echo ========================================
echo  PortVPNtoQbit v2 - Setup
echo ========================================

:: Instala dependências
echo.
echo [1/3] Instalando dependencias Python...
pip install -r requirements.txt

:: Cria .env se não existir
echo.
echo [2/3] Configurando arquivo .env...
if not exist ".env" (
    copy .env.example .env
    echo ATENCAO: Edite o arquivo .env com sua senha do qBittorrent antes de rodar!
) else (
    echo Arquivo .env ja existe. Pulando.
)

:: Instrucoes finais
echo.
echo [3/3] Pronto!
echo.
echo Para iniciar: python portvpntoqbit_v2.py
echo Para compilar em .exe: pyinstaller --onefile --windowed --icon=portvpntoqbit.ico --add-data ".env;." --add-data "portvpntoqbit.ico;." portvpntoqbit_v2.py
echo.
pause
