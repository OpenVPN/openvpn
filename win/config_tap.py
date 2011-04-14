import os
from wb import preprocess, home_fn, autogen, dict_def

def main(config):
    preprocess(config,
               in_fn=home_fn('tap-win32/SOURCES.in'),
               out_fn=home_fn('tap-win32/SOURCES'),
               quote_begin='@@',
               quote_end='@@',
               head_comment='# %s\n\n' % autogen)

    preprocess(config,
               in_fn=home_fn('tap-win32/i386/OemWin2k.inf.in'),
               out_fn=home_fn('tap-win32/i386/OemWin2k.inf'),
               quote_begin='@@',
               quote_end='@@',
               if_prefix='!',
               head_comment='; %s\n\n' % autogen)

    try:
        os.mkdir(home_fn('tap-win32/amd64'))
    except:
        pass
    preprocess(dict_def(config, [('AMD64', '1')]),
               in_fn=home_fn('tap-win32/i386/OemWin2k.inf.in'),
               out_fn=home_fn('tap-win32/amd64/OemWin2k.inf'),
               quote_begin='@@',
               quote_end='@@',
               if_prefix='!',
               head_comment='; %s\n\n' % autogen)

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    from wb import config
    main(config)
