from wb import get_config
from js import JSON

def main():
    kv = get_config()
    print JSON().encode(kv)

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    main()
