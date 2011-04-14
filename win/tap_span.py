import sys, os, shutil
from wb import config, home_fn, mod_fn, preprocess, autogen, dict_def, build_autodefs, rm_rf, mkdir_silent, cp
if 'SIGNTOOL' in config:
    sys.path.append(home_fn(config['SIGNTOOL']))
from signtool import SignTool
from build_ddk import build_tap

ti_dir = "c:/src/tapinstall"
hi = ("c:/winddk/7600.16385.1", 7600, 7600, ("i386", "amd64"))
low = ("c:/winddk/6001.18002", 6001, 5600, ("win2k",))
dest_top = home_fn('tap_build')
dist = home_fn(config['TAP_DIST'])

def copy_tap(src, dest, x64):
    dir = os.path.join(src, { False : 'i386', True: 'amd64' }[x64])
    mkdir_silent(dest)
    for dirpath, dirnames, filenames in os.walk(dir):
        for f in filenames:
            root, ext = os.path.splitext(f)
            if ext in ('.inf', '.cat', '.sys'):
                cp(os.path.join(dir, f), dest)
        break

def copy_tapinstall(src, dest, x64):
    base = { False : 'i386', True: 'amd64' }[x64]
    mkdir_silent(dest)
    for dirpath, dirnames, filenames in os.walk(home_fn(src)):
        for f in filenames:
            if f == 'devcon.exe':
                dir_name = os.path.basename(dirpath)
                s = os.path.join(dirpath, f)
                if dir_name == base:
                    cp(s, dest)

def main():
    rm_rf(dest_top)
    os.mkdir(dest_top)

    rm_rf(dist)
    os.mkdir(dist)

    for ver in hi, low:
        top = os.path.join(dest_top, str(ver[1]))
        os.mkdir(top)
        tap_dest = os.path.join(top, "tap-win32")
        ti_dest = os.path.join(top, "tapinstall")
        ti_src = os.path.join(ti_dir, str(ver[2]))
        shutil.copytree(home_fn("tap-win32"), tap_dest)
        shutil.copytree(ti_src, ti_dest)

        i386 = os.path.join(tap_dest, "i386")
        amd64 = os.path.join(tap_dest, "amd64")

        build_amd64 = (len(ver[3]) >= 2)

        build_autodefs(config, mod_fn('autodefs.h.in'), os.path.join(top, 'autodefs.h'))

        st = SignTool(config, tap_dest)

        preprocess(config,
                   in_fn=os.path.join(tap_dest, 'SOURCES.in'),
                   out_fn=os.path.join(tap_dest, 'SOURCES'),
                   quote_begin='@@',
                   quote_end='@@',
                   head_comment='# %s\n\n' % autogen)

        preprocess(config,
                   in_fn=os.path.join(i386, 'OemWin2k.inf.in'),
                   out_fn=os.path.join(i386, 'OemWin2k.inf'),
                   quote_begin='@@',
                   quote_end='@@',
                   if_prefix='!',
                   head_comment='; %s\n\n' % autogen)

        preprocess(config,
                   in_fn=os.path.join(ti_dest, 'sources.in'),
                   out_fn=os.path.join(ti_dest, 'sources'),
                   if_prefix='!',
                   head_comment='# %s\n\n' % autogen)

        build_tap(ddk_path=ver[0],
                  ddk_major=ver[1],
                  debug=False,
                  dir=tap_dest,
                  x64=False)

        st.sign_verify(x64=False)

        build_tap(ddk_path=ver[0],
                  ddk_major=ver[1],
                  debug=False,
                  dir=ti_dest,
                  x64=False)

        tap_dist = os.path.join(dist, ver[3][0])

        copy_tap(tap_dest, tap_dist, x64=False)
        copy_tapinstall(ti_dest, tap_dist, x64=False)

        if build_amd64:
            os.mkdir(amd64)
            preprocess(dict_def(config, [('AMD64', '1')]),
                       in_fn=os.path.join(i386, 'OemWin2k.inf.in'),
                       out_fn=os.path.join(amd64, 'OemWin2k.inf'),
                       quote_begin='@@',
                       quote_end='@@',
                       if_prefix='!',
                       head_comment='; %s\n\n' % autogen)

            build_tap(ddk_path=ver[0],
                      ddk_major=ver[1],
                      debug=False,
                      dir=tap_dest,
                      x64=True)

            build_tap(ddk_path=ver[0],
                      ddk_major=ver[1],
                      debug=False,
                      dir=ti_dest,
                      x64=True)

            st.sign_verify(x64=True)

            tap_dist_x64 = os.path.join(dist, ver[3][1])

            copy_tap(tap_dest, tap_dist_x64, x64=True)
            copy_tapinstall(ti_dest, tap_dist_x64, x64=True)

main()
