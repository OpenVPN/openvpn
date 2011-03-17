import os
from wb import home_fn, rm_rf, mkdir, cp_a, cp

def main(config, tap=True):
    dist = config['DIST']
    assert dist
    dist = home_fn(dist)
    bin = os.path.join(dist, 'bin')
    i386 = os.path.join(dist, 'i386')
    amd64 = os.path.join(dist, 'amd64')

    # build dist and subdirectories
    rm_rf(dist)
    mkdir(dist)
    mkdir(bin)
    if tap:
        mkdir(i386)
        mkdir(amd64)

    # copy openvpn.exe and manifest
    cp(home_fn('openvpn.exe'), bin)
    cp(home_fn('openvpn.exe.manifest'), bin)

    # copy DLL dependencies
    cp(home_fn(config['LZO_DIR']+'/bin/lzo2.dll'), bin)
    cp(home_fn(config['OPENSSL_DIR']+'/bin/libeay32.dll'), bin)
    cp(home_fn(config['OPENSSL_DIR']+'/bin/ssleay32.dll'), bin)

    # copy MSVC CRT
    cp_a(home_fn(config['MSVC_CRT']), bin)

    if tap:
        # copy TAP drivers
        for dir_name, dest in (('amd64', amd64), ('i386', i386)):
            dir = home_fn(os.path.join('tap-win32', dir_name))
            for dirpath, dirnames, filenames in os.walk(dir):
                for f in filenames:
                    root, ext = os.path.splitext(f)
                    if ext in ('.inf', '.cat', '.sys'):
                        cp(os.path.join(dir, f), dest)
                break

        # copy tapinstall
        dest = {'amd64' : amd64, 'i386' : i386}
        for dirpath, dirnames, filenames in os.walk(home_fn('tapinstall')):
            for f in filenames:
                if f == 'tapinstall.exe':
                    dir_name = os.path.basename(dirpath)
                    src = os.path.join(dirpath, f)
                    if dir_name in dest:
                        cp(src, dest[dir_name])

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    from wb import config
    main(config)
