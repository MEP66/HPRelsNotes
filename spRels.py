import requests
import re
from datetime import datetime

def get_cva_val(s, h, text):
    """Function to find the line starting with given text."""

    firstline, lastline = get_cva_block(h, text)
    if firstline != -1:
        for index, line in enumerate(text[firstline:lastline + 1]):
            if line.startswith(s):
                return line[len(s):]
                break
        else:
            return -1
    else:
        return -1


def get_cva_block(h, text):
    """Function to get line number with given text.
    startline returns first line of block
    endline returns last line of block or file.
    """

    for index, line in enumerate(text):
        if line.find(h) != -1:
            startline = index + 1
            for index, line in enumerate(text[startline:]):
                if line.startswith('['):
                    endline = startline + index - 1  # Found next header. Point to previous line.
                    break
            else:
                endline = startline + index  # No header found. Point to last line of file.
            break

    else:  # No Break
        startline = -1
        endline = -1

    return startline, endline


def process_cve(text):
    """Function to find all CVE entries between two given lines. Ensure no duplicate entries."""

    first_line, last_line = get_cva_block('[US.Enhancements]', text)

    match = []
    if first_line != -1:
        for index, line in enumerate(text[first_line:last_line + 1]):
            match = match + re.findall(r'CVE-\d+-\d+', line)

        match = list(dict.fromkeys(match))  # Eliminate duplicate entries.

    return match


def process_sysid(text):
    """Function to find all SysID entries in the [System Information] block."""

    first_line, last_line = get_cva_block('[System Information]', text)

    sys_ids = []
    for index, line in enumerate(text[first_line:last_line + 1]):
        sys_ids = sys_ids + re.findall(r'0x....', line)  # Look for all baseboard IDs.
    sys_ids = list(map(lambda i: i[2:], sys_ids))  # Strip off the 0x prefix from all entries

    return sys_ids


def get_cva_next_line(s, text):
    """Function to find the line starting with given text."""

    for index, line in enumerate(text):
        if line.startswith(s):
            return text[index + 1]
            break
    else:
        return ''


class spRels:
    """Class to define a softpaq release."""

    def __init__(self, spNum):
        self.number = spNum
        
        # Get Release Notes path based on softpaq number. Examples:
        # http://ftp.hp.com/pub/softpaq/sp107001-107500/sp107449.cva
        # http://ftp.hp.com/pub/softpaq/sp103501-104000/sp103685.cva

        begpath = str(((int(spNum[2:]) // 500) * 500) + 1)
        endpath = str(((int(spNum[2:]) // 500) + 1) * 500)
        self.path = f'http://ftp.hp.com/pub/softpaq/sp{begpath}-{endpath}/{spNum}.cva'

        # Fetch the release notes file from HP's site.

        rels_notes = requests.get(self.path)

        # If status_code is not 200, there was a problem fetching the file from HP.

        if rels_notes.status_code == 200:
            self.available = True

            # Get the contents of the release notes file.
            self.contents = str.splitlines(rels_notes.text)

            # Get the release date.
            date_string = str(get_cva_val('CVATimeStamp=', str('[CVA File Information]'), self.contents))[:8]
            self.rels_date = datetime(int(date_string[0:4]), int(date_string[4:6]), int(date_string[6:8]))
           
            # Get the type of softpaq release.
            self.category = get_cva_val('Category=', '[General]', self.contents)
            
            # If this is a BIOS release, get the BIOS family and release version.
            if self.category.upper() == 'BIOS':
                self.bios_family = str(get_cva_next_line('[DetailFileInformation]', self.contents))[:4]
                if len(self.bios_family) >= 4 and self.bios_family[3] == '_':
                    self.bios_family = self.bios_family[:3]
                else:
                    self.bios_family = ''
                self.rels_version = get_cva_val('Version=', '[General]', self.contents)
            else:
                self.bios_family = ''
                self.rels_version = ''

            # Get the Superseded softpaqs for this release.
            self.superseded_sp = re.findall(r'sp\d+', str.lower(get_cva_val('SupersededSoftpaqNumber=', '[Softpaq]', self.contents)))

            # Get the hardware system IDs supported by this release.
            self.cur_sys_ids = process_sysid(self.contents)

            # Get the CVEs resolved by this release.
            self.cur_cves = process_cve(self.contents)
            self.cves_resolved = len(self.cur_cves)

        else:
            self.available = False
            self.category = 'Unknown'
            self.rels_date = datetime(1900, 1, 1, 0, 0, 0)
            self.rels_version = ''
            self.bios_family = ''
            self.superseded_sp = []
            self.cur_sys_ids = []
            self.cur_cves = []
            self.cves_resolved = 0