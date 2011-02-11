import os, sys
from wb import system, config, home_fn, cd_home, cd_service_win32

os.environ['PATH'] += ";%s\\VC" % (os.path.normpath(config['MSVC']),)

def build_vc(cmd):
    """Make sure environment variables are setup before build"""
    system('cmd /c "vcvarsall.bat x86 && %s"' % (cmd,))

def main():
    """Build openvpn.exe and openvpnserv.exe"""
    cd_home()
    build_vc("nmake /f %s" % (home_fn('msvc.mak'),))
    cd_service_win32()
    build_vc("nmake /f %s" % ('msvc.mak'))

def clean():
    """Clean up after openvpn.exe and openvpnserv.exe build"""
    cd_home()
    build_vc("nmake /f %s clean" % (home_fn('msvc.mak'),))
    os.chdir("service-win32")
    build_vc("nmake /f %s clean" % ('msvc.mak'))

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == 'clean':
        clean()
    else:
        main()
