import os
from wb import system, home_fn, choose_arch

def build_ddk(config, dir, x64):
    ddk_path = config['DDK_PATH']
    ddk_major = int(config['DDKVER_MAJOR'])
    debug = 'PRODUCT_TAP_DEBUG' in config
    return build_tap(ddk_path, ddk_major, debug, dir, x64)

def build_tap(ddk_path, ddk_major, debug, dir, x64):
    """Build drivers using WinDDK tools"""
    setenv_bat = os.path.realpath(os.path.join(ddk_path, 'bin/setenv.bat'))
    target = 'chk' if debug else 'fre'
    if x64:
        target += ' x64'
    else:
        target += ' x86'
    if ddk_major >= 7600:
        if x64:
            target += ' wlh'  # vista
        else:
            target += ' wnet' # server 2003
    else:
        if x64:
            target += ' wnet' # server 2003
        else:
            target += ' w2k'  # 2000

    system('cmd /c "%s %s %s && cd %s && build -cef"' % (
           setenv_bat,
           os.path.realpath(ddk_path),
           target,
           dir
           ))

def main(config, proj, arch):
    if proj == 'tap':
        dir = home_fn('tap-win32')
    elif proj == 'tapinstall':
        dir = home_fn('tapinstall')
    else:
        raise ValueError("unknown project: %s" % (proj,))

    for x64 in choose_arch(arch):
        build_ddk(config, dir, x64)

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    import sys
    from wb import config
    if len(sys.argv) >= 3:
        main(config, sys.argv[1], sys.argv[2])
    else:
        print "usage: build <tap|tapinstall> <x64|x86|all>"
        sys.exit(2)
