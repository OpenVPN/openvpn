from wb import get_config
from js import JSON

def main():
    print JSON().encode(get_config())

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    main()
