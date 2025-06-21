"""
Author: Petr Kalabis (kalabpe4)
File: src/protocol_analysis/protocols/protocol.py

Defines the abstract base class for protocol analyzers in the packet analysis framework.
Each subclass must implement identification, summary, and detail extraction logic.
"""

from abc import ABC, abstractmethod

from scapy.all import Packet


class Protocol(ABC):
    """
    Abstract base class for protocol analyzers.

    Args:
        packet (Packet): The Scapy packet object being analyzed.
    """

    def __init__(self, packet: Packet) -> None:
        self.packet = packet

    @abstractmethod
    def identify(self) -> bool:
        """
        Check whether this protocol matches the current packet.

        Return:
            bool: True if protocol is present in packet, False otherwise.
        """

    @abstractmethod
    def parse_layer_details(self) -> dict:
        """
        Extract detailed protocol-specific information from the current layer.

        Return:
            dict: Dictionary of parsed fields and values.
        """

    @abstractmethod
    def get_summary(self) -> dict:
        """
        Generate a high-level summary of this protocol layer.

        Return:
            dict: Summary fields such as protocol, src, dst, ports, etc.
        """

    def next_protocol(self):
        """
        Optionally return the next protocol analyzer for encapsulated data.

        Return:
            Protocol | None: Next protocol instance if applicable, else None.
        """
        return None

    def descend(self, inherited_summary: dict = None) -> dict:
        """
        Recursively analyze protocol layers and build complete summary and details.

        Args:
            inherited_summary (dict, optional): Summary from outer protocol layers.

        Return:
            dict: A dictionary with two keys:
                - 'summary': dict with consolidated summary info.
                - 'details': nested dict of parsed layer details.
        """
        details = {}
        if inherited_summary is None:
            inherited_summary = {}

        current_details = self.parse_layer_details()
        if current_details:
            protocol_name = self.__class__.__name__.replace("Protocol", "")
            details[protocol_name] = current_details

        current_summary = self.get_summary()

        combined_summary = {
            **inherited_summary,
            **{k: v for k, v in current_summary.items() if v is not None}
        }

        next_proto = self.next_protocol()
        if next_proto:
            result = next_proto.descend(inherited_summary=combined_summary)
            details.update(result["details"])
            return {
                "summary": result["summary"],
                "details": details
            }

        return {
            "summary": combined_summary,
            "details": details
        }
