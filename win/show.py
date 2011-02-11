from wb import get_config, get_build_params
from js import JSON

def main():
    print JSON().encode(get_config())
    print JSON().encode(get_build_params())

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    main()
