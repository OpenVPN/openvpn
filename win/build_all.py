from config_all import main as config_all
from build import main as build_openvpn
from build_ddk import main as build_ddk
from sign import main as sign
from make_dist import main as make_dist

def main(config):
    config_all(config)
    build_openvpn()
    build_ddk(config, 'tap', 'all')
    build_ddk(config, 'tapinstall', 'all')
    sign(config, 'all')
    make_dist(config)

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    from wb import config
    main(config)
