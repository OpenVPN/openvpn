import getopt, sys
from config_all import main as config_all
from build import main as build_openvpn
from build_ddk import main as build_ddk
from make_dist import main as make_dist

def Usage():
    '''Show usage information'''
    print "Usage: build_all.py [OPTIONS]..."
    print "Build OpenVPN using Visual Studio tools"
    print
    print " -h, --help		Show this help"
    print " -u, --unsigned	Do not sign the TAP drivers"
    print " -n, --notap		Don't build the TAP driver"
    sys.exit(1)

def main(config):

    # Do a signed build by default
    signedBuild=True

    # Build the TAP driver by default
    tap=True

    # Parse the command line argument(s)
    try:
       opts, args = getopt.getopt(sys.argv[1:], "hun", ["help", "unsigned", "notap"])
    except getopt.GetoptError:
       Usage()

    for o, a in opts:
       if o in ("-h","--help"):
          Usage()
       if o in ("-u", "--unsigned"):
          signedBuild=False
       if o in ("-n", "--notap"):
          tap=False

    # Check if the SignTool module is present. This avoids ImportErrors popping
    # up annoyingly _after_ the build.
    if signedBuild:
       try:
          from signtool import SignTool
       except (ImportError):
          print "ERROR: SignTool python module not found! Can't do a signed build."
          sys.exit(1)
    else:
       print "Doing an unsigned build as requested"

    # Start the build
    config_all(config)
    build_openvpn()

    if tap:
       build_ddk(config, 'tap', 'all')
       build_ddk(config, 'tapinstall', 'all')
       if signedBuild:
          sign(config, 'all')
       make_dist(config,tap=True)

    else:
       if 'TAP_PREBUILT' in config:
          print "Using prebuilt TAP driver"
          make_dist(config,tap=False)

# if we are run directly, and not loaded as a module
if __name__ == "__main__":
    from wb import config
    main(config)
