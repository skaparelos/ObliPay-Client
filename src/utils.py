from petlib.ec import EcPt, EcGroup
from petlib.bn import Bn
import msgpack

""" Code taken from: http://petlib.readthedocs.io/en/latest/_modules/petlib/pack.html """

def default(obj):
    # Serialize Bn objects
    if isinstance(obj, Bn):
        if obj < 0:
            neg = b"-"
            data = (-obj).binary()
        else:
            neg = b"+"
            data = obj.binary()
        return msgpack.ExtType(0, neg + data)

    # Serialize EcGroup objects
    elif isinstance(obj, EcGroup):
        nid = obj.nid()
        packed_nid = msgpack.packb(nid)
        return msgpack.ExtType(1, packed_nid)

    # Serialize EcPt objects
    elif isinstance(obj, EcPt):
        nid = obj.group.nid()
        data = obj.export()
        packed_nid = msgpack.packb((nid, data))
        return msgpack.ExtType(2, packed_nid)

    raise TypeError("Unknown type: %r" % (obj,))


def ext_hook(code, data):

    # Decode Bn types
    if code == 0:
        num = Bn.from_binary(data[1:])
        # Accomodate both Python 2 and Python 3
        if data[0] == ord("-") or data[0] == "-":
            return -num
        return num

    # Decode EcGroup
    elif code == 1:
        nid = msgpack.unpackb(data)
        return EcGroup(nid)

    # Decode EcPt
    elif code == 2:
        nid, ptdata = msgpack.unpackb(data)
        return EcPt.from_binary(ptdata, EcGroup(nid))

    # Other
    return msgpack.ExtType(code, data)