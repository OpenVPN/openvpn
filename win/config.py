from wb import preprocess, autogen, mod_fn, home_fn, build_autodefs, make_headers_objs, dict_def

def main(config):
    build_autodefs(config, mod_fn('autodefs.h.in'), home_fn('autodefs.h'))
    ho = make_headers_objs(home_fn('Makefile.am'))

    preprocess(dict_def(config, [('HEADERS_OBJS', ho)]),
               in_fn=mod_fn('msvc.mak.in'),
               out_fn=home_fn('msvc.mak'),
               quote_begin='@',
               quote_end='@',
               if_prefix='!',
               head_comment='# %s\n\n' % autogen)

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    from wb import config
    main(config)
