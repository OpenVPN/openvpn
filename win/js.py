import json

# usage:
#   print JSON().encode(kv)

class JSON(json.JSONEncoder):
    def __init__(self, **kwargs):
        args = dict(sort_keys=True, indent=2)
        args.update(kwargs)
        json.JSONEncoder.__init__(self, **args)
