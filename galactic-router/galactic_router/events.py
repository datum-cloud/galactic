from bubus import BaseEvent

from .proto import remote_pb2 as pb


class RegisterEvent(BaseEvent[bool]):
    worker: str
    envelope: pb.Register


class DeregisterEvent(BaseEvent[bool]):
    worker: str
    envelope: pb.Deregister


class RouteEvent(BaseEvent[bool]):
    worker: str
    envelope: pb.Route
