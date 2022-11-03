# HPRelsNotes
This program will process Hewlett Packard release notes, scraping the text files for release and vulnerability (CVE) information.
It issues an HP Command Management Scrip Library (CMSL) command to get the lastest softpaq releases for the models, OS, and Categories of interest.
The release notes for each softpaq are scrapped for release information, supported model information, and CVEs resolved in each. The
results are stored in a database. Superseded softpaqs are also processed in a similar fashion.

<b>INPUT</b>: There are three database tables that provide the input for the program. These tables are manually updated/maintained.
<ul>
  <li><b>supportedCategory</b> - The supported categories of interest for the CMSL command. Any of: Bios, Firmware, Driver, Software, Manageability, Dock.</li> 
  <li><b>supportedOS</b> - The supported OS of interest for the CMSL command: Any of: win10, win11.</li>
  <li><b>supportedOSVer</b> - The supported OS of interest for the CMSL command: Any of: 1809, 1909, 2009, 21H1, 21H2.</li>
  <li><b>supportedBBID</b> - The supported Baseboard ID, or model identifier, for the CMSL command. Each entry is a four digit hex value in string format. For example:</li>
    <li>    8056 = HP EliteDesk 800 SFF</li>
    <li>    8414 = HP ELITE X2 1013 G3</li>
  <li><b>HP Release notes</b> - Release ntoes are accessed through the web, and the path depends on the softpaq number. For example:</li>
  <li>    http://ftp.hp.com/pub/softpaq/sp107001-107500/sp107449.cva</li>
  <li>    http://ftp.hp.com/pub/softpaq/sp103501-104000/sp103685.cva</li>
</ul>
  
<b>OUTPUT</b>: The output of the program results in the following three database tables being updated:  
<ul>
  <li><b>spReleases</b> - Each softpaq release is recorded, along with other relevant information.  
  <li><b>spToBBID</b> - A list of baseboard IDs that each softpaq is released against per the release notes. One row per sp/BBID pair.
  <li><b>spToCVE</b> - A list of CVEs that each softpaq resolves per the release notes. One row per sp/CVE pair.
</ul>