from pyshark import FileCapture

pcap = FileCapture("/Users/brainey6/git/srsoam/test_data/gnb_ngap.pcap", use_text=True)

# packet_ = pcap.next()

for packet in pcap:
    with open ("test file %s" % packet["timestamp"], "w") as outfile:
        outfile.write(packet["hex"])
        outfile.write("\n" + "="*72 + "\n")
        outfile.write(packet["packet"])
