import re, os
from packaging import version
from pyshark.tshark.output_parser.base_parser import BaseTsharkOutputParser

def re_search(search_string:str, data:str):
    if isinstance(data, bytes):
        data = data.decode("UTF-8")
    res = re.search(search_string, data)
    if res:
        return res.start()
    else:
        return -1

class TsharkTextParser(BaseTsharkOutputParser):

    def __init__(self, tshark_version=None):
        super().__init__()
        self._tshark_version = tshark_version

    def _parse_single_packet(self, packet: tuple[str, bytes]):
        hex_data = None
        add_hex_header = False
        frame_bytes = "XX"
        hex_start = re_search("Frame \(\d* bytes", packet)
        if hex_start == -1:
            hex_start = re_search("\d\d\d\d  ([\d,a-f]{2} {0,1}){16}", packet)
            add_hex_header = True
        if hex_start != -1:
            hex_data = packet[hex_start:]

        packet_data = packet[:hex_start]
        if add_hex_header:
            res = re.search("Frame \d*: ", packet_data)
            if res:
                frame_bytes = packet_data[res.end() : packet_data.find(" bytes on wire")]
        start = packet_data.find('Epoch Time')
        packet_data = packet_data[start:]
        end = packet_data.find('seconds')
        timestamp = packet_data[:end].strip().split()[-1]
        timestamp = float(timestamp)
        start = packet_data.find('Payload:')
        packet_data = packet_data[start:]
        end = packet_data.find('\n')
        packet_data = packet_data[end+1:]

        if hex_data:
            lines = hex_data.splitlines()
            if not add_hex_header:
                hex_arr = [lines[0]]
            else:
                hex_arr = ["Frame (%s bytes)" % frame_bytes]
            for line in lines[1:]:
                if re.match("^\d\d\d\d  [\d,a-f]{2} {0,1}", line):
                    hex_arr.append(line)
                else:
                    break
            hex_data = "\n".join(hex_arr)

        return {
            "timestamp": timestamp,
            "packet": packet_data,
            "hex": hex_data
        }

    def _extract_packet_from_data(self, data: bytes, got_first_packet=True):
        """Returns a packet's data and any remaining data after reading that first packet"""
        packet_start = 0
        # if not got_first_packet:
        # packet_start = re_search("Frame \d*: \d* bytes", data)

        # if packet_start == -1:
            # return None, data

        packet_separator = b'=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/='
        found_separator = None

        tag_end = data.find(packet_separator)
        if tag_end == -1:
            # Not end of packet, maybe it has end of entire file?
            tag_end = len(data)-2
        else:
            # Found a single packet, just add the separator without extras
            found_separator = packet_separator


        if found_separator:
            data_packet = data[packet_start:tag_end].decode('UTF-8').strip() #.strip(",")
            return data_packet, data[tag_end + 1:]
        return None, data

    def _get_json_separators(self):
        """"Returns the separators between packets in a JSON output

        Returns a tuple of (packet_separator, end_of_file_separator, characters_to_disregard).
        The latter variable being the number of characters to ignore in order to pass the packet (i.e. extra newlines,
        commas, parenthesis).
        """
        if not self._tshark_version or self._tshark_version >= version.parse("3.0.0"):
            return f"{os.linesep}  }},{os.linesep}".encode(), f"}}{os.linesep}]".encode(), 1 + len(os.linesep)
        else:
            return f"}}{os.linesep}{os.linesep}  ,".encode(), f"}}{os.linesep}{os.linesep}]".encode(), 1


def duplicate_object_hook(ordered_pairs):
    """Make lists out of duplicate keys."""
    json_dict = {}
    for key, val in ordered_pairs:
        existing_val = json_dict.get(key)
        if not existing_val:
            json_dict[key] = val
        else:
            if isinstance(existing_val, list):
                existing_val.append(val)
            else:
                json_dict[key] = [existing_val, val]

    return json_dict
