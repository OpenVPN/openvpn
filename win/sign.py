import sys
from wb import config, choose_arch, home_fn

if 'SIGNTOOL' in config:
    sys.path.append(home_fn(config['SIGNTOOL']))

def main(conf, arch):
    from signtool import SignTool
    st = SignTool(conf)
    for x64 in choose_arch(arch):
        st.sign_verify(x64=x64)

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    if len(sys.argv) >= 2:
        main(config, sys.argv[1])
    else:
        print "usage: sign <x64|x86|all>"
        sys.exit(2)
