from config import main as config_main
from config_tap import main as config_tap
from config_ti import main as config_ti

def main(config):
    config_main(config)
    config_tap(config)
    config_ti(config)

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    from wb import config
    main(config)
