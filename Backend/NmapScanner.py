import asyncio
import nmap
import re

from PyQt5 import QtCore


class NmapScanner(QtCore.QObject):
    resultReceived = QtCore.pyqtSignal(str)
    progressUpdated = QtCore.pyqtSignal(int)

    def __init__(self, targets, nmap_commands, cl, s):
        super().__init__()
        self.targets = targets
        self.nmap_commands = nmap_commands
        self.total_progress = len(targets)
        self.results = ""
        self.cl = cl
        self.s = s

    async def scan(self, target, nmap_command):
        nm = nmap.PortScanner()
        scan_command = f"{nmap_command} {target}"
        start_time = QtCore.QTime.currentTime()

        nm.scan(hosts=target, arguments=scan_command)


        result = self.parse_nmap_output(nm.csv())
        self.results += result + "\n"

    def parse_nmap_output(self, raw_output):
        parsed_output = ""
        for line in raw_output.splitlines():
            if line.startswith("host;hostname;hostname_type;protocol;name;state;reason;"):
                continue
            parsed_output += line.replace(";", "\t") + "\n"
        return parsed_output

    def get_open_ports(self, target):
        open_ports = re.findall(r"(\d+)/open", target)
        return [int(port) for port in open_ports]

    def start_scan(self):
        tasks = []

        for target, nmap_command in zip(self.targets, self.nmap_commands):
            tasks.append(self.scan(target, nmap_command))

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(asyncio.gather(*tasks))
        loop.close()

        self.resultReceived.emit(self.results)

        open_ports = self.get_open_ports(self.targets[-1]) if self.targets else []
        self.s.plot_open_ports(open_ports)
        post_scan_dialog = self.cl(self.s)
        post_scan_dialog.results = "\n".join(map(str, open_ports))
        post_scan_dialog.exec_()


if __name__ == "__main__":

    pass
