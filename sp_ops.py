import re
import requests
import configparser
from datetime import datetime
import logging
logger = logging.getLogger(__name__)
import os
import io
from db_ops import db_write

def process_sp(sp, rl, processed_this, processed_previous):
    """Function to process the release notes for a given HP Softpaq."""

    rl += 1
    if not sp in processed_this:

        logger.info(f'{" " * rl * 3}Starting to process: {sp}')

        # Continue if this sp has not already been processed during this execution.

        processed_this.add(sp)
        sp_info = spRels(sp)

        if sp in processed_previous:
            sp_new = False

            if sp_info['reldate'] > processed_previous[sp]:
                
                # If this softpaq was processed in a previous execution, and the release notes have a newer release date,
                # process it again to provide any updates.

                sp_updated = True
                logger.info(f'{" " * rl * 3}Updating previously processed: {sp}')
                
            else:
                sp_updated = False
        else:

            # Otherwise, if this softpaq was not processed previously during this execution, or during a previous execution,
            # this is a new softpaq. So process it.
            
            sp_new = True
            logger.info(f"{' ' * rl * 3}Processing new: {sp_info['filepath']}")

        if sp_new or sp_updated:

            # Whether this is a new softpaq, or we are updating a previous softpaq, process as normal from here.
            # Save the BBID information to the database, avoiding duplicate entries.

            for bbid in sp_info['sysids']:
                sql = (
                    f"INSERT OR IGNORE INTO spToBBID (Softpaq, BBID) "
                    f"VALUES ('{sp}', '{bbid}');"
                    )
                db_write(sql)

            # Save the CVE information to the database, avoiding duplicate entries.
            
            for cve in sp_info['cves']:
                sql = (
                    f"INSERT OR IGNORE INTO spToCVE (Softpaq, CVE) "
                    f"VALUES ('{sp}', '{cve}');"
                    )
                db_write(sql)

            # If this was a new sp, write the new database record out to the spReleases table.
            # Otherwise it must have been an update, so update the existing record. Write to
            # this table last, so that if anything fails above, this won't get recorded, and it will
            # be re-processed on the next execution.

            if sp_new:

            # Save the new softpaq release information to the database.

                sql = (
                    f"INSERT INTO spReleases (Softpaq, Category, ReleaseDate, ReleaseVersion, BIOSFamily, CVEsResolved) "
                    f"VALUES ('{sp}', "
                    f"'{sp_info['cat']}', "
                    f"'{str(sp_info['reldate'])}', "
                    f"'{sp_info['relver']}', "
                    f"'{sp_info['biosfam']}', "
                    f"{sp_info['numresolvd']});"
                    )
                db_write(sql)
           
            else:
                # Update the new softpaq release information in the existing record.

                sql = (
                    f"UPDATE spReleases SET "
                    f"Category='{sp_info['cat']}', "
                    f"ReleaseDate='{str(sp_info['reldate'])}', "
                    f"ReleaseVersion='{sp_info['relver']}', "
                    f"BIOSFamily='{sp_info['biosfam']}', "
                    f"CVEsResolved={sp_info['numresolvd']} "
                    f"WHERE Softpaq='{sp}';"
                    )
                db_write(sql)

            # Just log that we are done with this softpaq. Note if release notes were not found.

            if sp_info['avail']:
                logger.info(f"{' ' * rl * 3}Completed: {sp_info['filepath']} : CVEs found: {str(sp_info['numresolvd'])}")
            else:
                logger.info(f"{' ' * rl * 3}No release file found for: {sp}")


            # Finally, recurse to process the superseded softpaqs found in the release notes.

            for sp_sup in sp_info['supersp']:
                process_sp(sp_sup, rl, processed_this, processed_previous)

        else:
                # Softpaq was processed in a previous execution, and release notes have not been updated. Skip it.
                
                logger.info(f"{' ' * rl * 3}Skipping previously processed in past execution: {sp}")
    else:
        # Softpaq was already processed in this execution, so skip it.
        
        logger.info(f"{' ' * rl * 3}Skipping already processed in this execution: {sp}")


def spRels(spNum):
    """Function to process a softpaq release."""
        
    # Get Release Notes (.cva) path based on softpaq number. Examples:
    # http://ftp.hp.com/pub/softpaq/sp107001-107500/sp107449.cva
    # http://ftp.hp.com/pub/softpaq/sp103501-104000/sp103685.cva

    begpath = str(((int(spNum[2:]) // 500) * 500) + 1)
    endpath = str(((int(spNum[2:]) // 500) + 1) * 500)
    ftp_path = f'http://ftp.hp.com/pub/softpaq/sp{begpath}-{endpath}/{spNum}.cva'

    # Fetch the release notes file from HP's site.

    try:
        rels_notes = requests.get(ftp_path)
        
        # If the status of the get is between 200 and 400, the response will evaluate to True, and False otherwise.
        if rels_notes:
            rels_found = True
        else:
            rels_found = False
    except ConnectTimeoutError:
        logger.error(f"{' ' * rl * 3}HP Site connection timeout for: {sp}")
        rels_found = False

    if rels_found:
        available = True

        # Get the contents of the release notes file.
        # configparser options:
        #    allow_no_value=True - allows sections like [US. Enhancements] without keys to be read without failing.
        #    strict=False - Keeps from failing on duplicate keys such as the 'BatteryHealthManager.exe=' under [DetailFaileInformation] in sp111205.
        #    empty_lines_in_values - Keeps from failing due to indented line under [Private_SoftpaqInstall] section for sp90199.


        # with io.open('RelsNotes.txt', 'w', encoding='utf8') as fd:
        #     fd.write(str(rels_notes))
        TEMPLOCALFILE = 'RelsNotes.txt'
        with open(TEMPLOCALFILE, 'w', encoding='utf-8') as fd:
            fd.write(rels_notes.text)
        rn_config = configparser.ConfigParser(allow_no_value=True, strict=False, empty_lines_in_values=False)
        rn_config.read(TEMPLOCALFILE, encoding='utf-8')
        os.remove(TEMPLOCALFILE)
        
        # Get the release date, and convert to Python format. Default to 1900/01/01 if not found.
        date_string = rn_config['CVA File Information'].get('CVATimeStamp', '19000101')[0:8]
        rels_date = datetime(int(date_string[0:4]), int(date_string[4:6]), int(date_string[6:8]))
        
        # Get the category of softpaq release.
        category = rn_config['General']['Category']
        
        # If this is a BIOS release, get the BIOS family and release version.
        # Check to see if DetailFileInforation is empty. (eg. sp142737). If so,
        # retrieve the BIOS Family info from the Software Title.
        if category.upper() == 'BIOS':
            if rn_config['DetailFileInformation']:
                bios_family = next(iter(rn_config['DetailFileInformation'].items()))[1]
                bios_family = bios_family.split(',')[1]
            else:
                value = list(rn_config['Software Title'].items())[0][1]
                bios_family = re.search(r'\(\w+\)', value.upper())[0][1:-1]
                if bios_family == None:
                    bios_family = ''
        else:
            bios_family = ''
        
        rels_version = rn_config['General']['Version']

        # Get the Superseded softpaqs for this release.
        superseded_sp = re.findall(r'sp\d+', str.lower(rn_config['Softpaq'].get('SupersededSoftpaqNumber', fallback='')))

        # Get the hardware system IDs supported by this release.
        cur_sys_ids = []
        for key, value in rn_config['System Information'].items():
            if key[:5].lower() == 'sysid':
                cur_sys_ids.append(value[2:].upper())

        # Get the CVEs resolved by this release.
        cur_cves = []
        if 'US.Enhancements' in rn_config:
            for line in rn_config['US.Enhancements']:
                cur_cves = cur_cves + re.findall(r'CVE-\d+-\d+', line.upper())
            cur_cves = list(dict.fromkeys(cur_cves))  # Eliminate duplicate entries.
        num_cves_resolved = len(cur_cves)

    else:
        # Couldn't find release notes for this softpaq, but let's still write it to 
        # the database with default info so we know we at least tried to process it.
        
        available = False
        ftp_path = ''
        category = 'Unknown'
        rels_date = datetime(1900, 1, 1, 0, 0, 0)
        rels_version = ''
        bios_family = ''
        superseded_sp = []
        cur_sys_ids = []
        cur_cves = []
        num_cves_resolved = 0
    
    return {
        'avail': available,
        'filepath': ftp_path,
        'cat': category,
        'reldate': rels_date,
        'relver': rels_version,
        'biosfam': bios_family,
        'supersp': superseded_sp,
        'sysids': cur_sys_ids,
        'cves': cur_cves,
        'numresolvd': num_cves_resolved
    }