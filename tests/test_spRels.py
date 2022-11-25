import sys
import os
current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)
from sp_ops import spRels
import datetime


def test_withCVEs_spRels():
    """Test a normal softpaq, sp139830, where there are CVEs to report."""

    assert spRels('sp139830')=={
        'avail': True, 
        'filepath': 'http://ftp.hp.com/pub/softpaq/sp139501-140000/sp139830.cva', 
        'cat': 'BIOS', 
        'reldate': datetime.datetime(2022, 5, 10, 0, 0), 
        'relver': '01.20.00', 
        'biosfam': 'Q81', 
        'supersp': ['sp139226'], 
        'sysids': ['83DA', '83D5'], 
        'cves': ['CVE-2022-23924', 'CVE-2022-23925', 'CVE-2022-23926', 'CVE-2022-23927', 'CVE-2022-23928', 'CVE-2022-23929', 'CVE-2022-23930', 'CVE-2022-23931', 'CVE-2022-23932', 'CVE-2022-23933', 'CVE-2022-23934', 'CVE-2022-23953', 'CVE-2022-23954', 'CVE-2022-23955', 'CVE-2022-23956', 'CVE-2022-23957', 'CVE-2022-23958', 'CVE-2020-12944', 'CVE-2020-12951', 'CVE-2021-26312', 'CVE-2021-26361', 'CVE-2021-26362', 'CVE-2021-26366', 'CVE-2021-26367', 'CVE-2021-26368', 'CVE-2021-26369', 'CVE-2021-26373', 'CVE-2021-26381', 'CVE-2021-26386', 'CVE-2021-26388', 'CVE-2021-26390', 'CVE-2021-39298'], 
        'numresolvd': 32
        }

def test_MissingBIOS_spRels():
    """Test previously problematic sp111205, where"""
    """the [DetailFileInformation] has duplicate keys."""

    assert spRels('sp111205')=={
        'avail': True, 
        'filepath': 'http://ftp.hp.com/pub/softpaq/sp111001-111500/sp111205.cva', 
        'cat': 'Firmware', 
        'reldate': datetime.datetime(2020, 11, 24, 0, 0), 
        'relver': '1.0.2.1', 
        'biosfam': '', 
        'supersp': [], 
        'sysids': ['82CA', '82DE', '8417', '828C', '827D', '823C', '823E', '8234', '822C', '8301', '8231', '822E', '828B', '82AA', '82AB', '823A', '8238', '8236', '82EB', '8292', '8780', '86CF', '86D0', '815A', '860C', '80D6', '842D', '8521', '8524', '8637', '80FA', '8470', '80FB', '857F', '8438', '8079', '8723', '8724', '846F', '854A', '83D2', '8416', '844A', '80FD', '8125', '856D', '882C', '856E', '882D', '83B2', '8549', '8418', '824C', '818F', '8300', '861F', '8170', '845D', '876D', '85AF', '8084', '8760', '8589', '83DA', '8414', '80FC', '85B9', '8736', '8548', '8725', '853D', '80EF', '80F0', '8730', '85AD', '836E', '8370', '85D9', '8735', '877D', '8537', '83FD', '8471', '82EF', '837B', '837F', '869D', '86A0', '8536', '8101', '85A3', '85A5', '85AA', '8538', '8100', '869B', '8377', '8102', '837D', '80FF', '83D0', '84D8', '807C', '83B3', '86A5', '86A8', '876B', '8584', '83DD', '8620', '807E', '8401', '80FE', '83D5', '8783', '80D5', '860F', '842A', '84E9', '8270', '8275', '826B', '8427', '844F', '80D4'], 
        'cves': [], 
        'numresolvd': 0
        }

def test_NoDetailFileInfo_spRels():
    """Test previously problematic sp142737, where the [DetailFileInformation]"""
    """section is present but blank. Therefore the BIOS family is retrieved"""
    """from the Software Title section."""

    assert spRels('sp142737')=={
        'avail': True, 
        'filepath': 'http://ftp.hp.com/pub/softpaq/sp142501-143000/sp142737.cva', 
        'cat': 'BIOS', 
        'reldate': datetime.datetime(2022, 9, 28, 0, 0), 
        'relver': '01.21.10', 
        'biosfam': 'R91', 
        'supersp': ['sp141549'], 
        'sysids': ['85B9'], 
        'cves': ['CVE-2022-31644', 'CVE-2022-31645', 'CVE-2022-31646', 'CVE-2022-27537'], 
        'numresolvd': 4
        }

def test_NoUSEnhancements_spRels():
    """Test previously problematic sp99639, where the [US.Enhancements]"""
    """section is not present."""

    assert spRels('sp99639')=={
        'avail': True, 
        'filepath': 'http://ftp.hp.com/pub/softpaq/sp99501-100000/sp99639.cva', 
        'cat': 'Firmware', 
        'reldate': datetime.datetime(2020, 5, 28, 0, 0), 
        'relver': '', 
        'biosfam': '', 
        'supersp': [], 
        'sysids': ['857F'], 
        'cves': [], 
        'numresolvd': 0
        }

def test_NoUSEnhancements_spRels():
    """Test previously problematic sp101974, which has foreign characters"""
    """in the release notes."""

    assert spRels('sp101974')=={
        'avail': True, 
        'filepath': 'http://ftp.hp.com/pub/softpaq/sp101501-102000/sp101974.cva', 
        'cat': 'Operating System-Enhancements and QFEs', 
        'reldate': datetime.datetime(2022, 11, 7, 0, 0), 
        'relver': '11.4', 
        'biosfam': '', 
        'supersp': ['sp97064'], 
        'sysids': ['82CA', '82DE', '8417', '828C', '827D', '823C', '823E', '8234', '822C', '8301', '8231', '822E', '828B', '82AA', '82AB', '823A', '8238', '8236', '8292', '86CF', '86D0', '8521', '8524', '8637', '80FA', '8266', '8470', '80FB', '857F', '8079', '846F', '854A', '2216', '83D2', '8416', '844A', '80FD', '8125', '8055', '856D', '856E', '83B2', '82B4', '82A2', '829B', '829C', '8549', '8418', '824C', '818F', '8300', '861F', '8170', '845D', '876D', '221B', '8084', '83DA', '80FC', '85B9', '83EE', '83F2', '8548', '8725', '853D', '22FB', '80EF', '80F0', '8101', '8100', '80FF', '807C', '8655', '83B3', '83E8', '8462', '8463', '807E', '8401', '80FE', '83D5', '82EE', '8334', '8427', '844F'],
        'cves': [], 
        'numresolvd': 0
        }

def test_IndentedLine_spRels():
    """Test previously problematic sp90199, which has an indented line under the"""
    """[Private_SoftpaqInstall] section."""

    assert spRels('sp90199')=={
        'avail': True, 
        'filepath': 'http://ftp.hp.com/pub/softpaq/sp90001-90500/sp90199.cva', 
        'cat': 'Software - System Management', 
        'reldate': datetime.datetime(2020, 11, 22, 0, 0), 
        'relver': '3.5.18.1', 
        'biosfam': '', 
        'supersp': ['sp88406'], 
        'sysids': ['8266', '80D4'],
        'cves': [], 
        'numresolvd': 0
        }

def test_NoCVATimestamp_spRels():
    """Test previously problematic sp61453, which had no CVATimeStamp key."""

    assert spRels('sp61453')=={
        'avail': True, 
        'filepath': 'http://ftp.hp.com/pub/softpaq/sp61001-61500/sp61453.cva', 
        'cat': 'Software - Multimedia', 
        'reldate': datetime.datetime(1900, 1, 1, 0, 0), 
        'relver': '3.5.41.0', 
        'biosfam': '', 
        'supersp': ['sp60873'], 
        'sysids': ['194B', '194D', '1949', '1948', '17F0', '17F1', '17F3', '17F4', '17F6', '1846'],
        'cves': [], 
        'numresolvd': 0
        }