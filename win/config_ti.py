import os, shutil
from wb import preprocess, home_fn, autogen

def main(config):
    src = os.path.join(home_fn(config['TISRC']), config['DDKVER_MAJOR'])
    dest = home_fn('tapinstall')
    shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(src, dest)
    preprocess(config,
               in_fn=os.path.join(src, 'sources'),
               out_fn=os.path.join(dest, 'sources'),
               if_prefix='!',
               head_comment='# %s\n\n' % autogen)

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    from wb import config
    main(config)
