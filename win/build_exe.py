from config import main as config_main
from build import main as build_openvpn
from build_ddk import main as build_ddk
from sign import main as sign
from make_dist import main as make_dist

def main(config):
    config_main(config)
    build_openvpn()
    make_dist(config, tap=False)

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    from wb import config
    main(config)
