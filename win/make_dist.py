import os
from wb import home_fn, rm_rf, mkdir, cp_a, cp, rename

def main(config, tap=True):
    dist = config['DIST']
    assert dist
    dist = home_fn(dist)
    bin = os.path.join(dist, 'bin')
    i386 = os.path.join(dist, 'i386')
    amd64 = os.path.join(dist, 'amd64')
    samples = os.path.join(dist, 'samples')

    # build dist and subdirectories
    rm_rf(dist)
    mkdir(dist)
    mkdir(bin)
    if tap:
        mkdir(i386)
        mkdir(amd64)
    mkdir(samples)

    # copy openvpn.exe, openvpnserv.exe and their manifests
    cp(home_fn('openvpn.exe'), bin)
    cp(home_fn('openvpn.exe.manifest'), bin)
    cp(home_fn('service-win32/openvpnserv.exe'), bin)
    cp(home_fn('service-win32/openvpnserv.exe.manifest'), bin)

    # copy openvpn-gui
    cp(home_fn(config['OPENVPN_GUI_DIR']+"/"+config['OPENVPN_GUI']), bin)

    # copy DLL dependencies
    cp(home_fn(config['LZO_DIR']+'/bin/lzo2.dll'), bin)
    cp(home_fn(config['LZO_DIR']+'/bin/lzo2.dll.manifest'), bin)
    cp(home_fn(config['OPENSSL_DIR']+'/bin/libeay32.dll'), bin)
    cp(home_fn(config['OPENSSL_DIR']+'/bin/ssleay32.dll'), bin)
    cp(home_fn(config['PKCS11_HELPER_DIR']+'/lib/libpkcs11-helper-1.dll'), bin)
    cp(home_fn(config['PKCS11_HELPER_DIR']+'/lib/libpkcs11-helper-1.dll.manifest'), bin)

    # copy OpenSSL utilities (=openvpn.exe)
    cp(home_fn(config['OPENSSL_DIR']+'/bin/openssl.exe'), bin)

    # copy sample config files; renaming is necessary due to openvpn.nsi script
    cp(home_fn('install-win32/sample.ovpn'), samples)
    cp(home_fn('sample-config-files/client.conf'), samples)
    cp(home_fn('sample-config-files/server.conf'), samples)
    rename(os.path.join(samples,'client.conf'), os.path.join(samples, 'client.ovpn'))
    rename(os.path.join(samples,'server.conf'), os.path.join(samples, 'server.ovpn'))

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

        # Copy tapinstall.exe (usually known as devcon.exe)
        dest = {'amd64' : amd64, 'i386' : i386}
        for dirpath, dirnames, filenames in os.walk(home_fn('tapinstall')):
            for f in filenames:
                if f == 'tapinstall.exe':
		    # dir_name is either i386 or amd64
                    dir_name = os.path.basename(dirpath)
                    src = os.path.join(dirpath, f)
                    if dir_name in dest:
                        cp(src, dest[dir_name])


# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    from wb import config
    main(config)
