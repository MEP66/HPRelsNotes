from datetime import datetime
import sqlite3
import subprocess
import re
import logging
import threading
import requests
import configparser
from itertools import product
from queue import Queue

HPDATABASE = 'HPRelsNotesDb.db'

def issue_cmsl(q, result):
    """Function to retrieve softpaq numbers via the HP CMSL get-softpaqlist powershell command.
    More information about this command can be found here: https://developers.hp.com/hp-client-management/doc/get-softpaqlist
    This PowerShell command gives the latest softpaq(s) released for each BBID/OS/OSVer/Category combination. Only the
    information in the "Id :" line(s) is saved from the output.
    Example request/output:

        PS> get-softpaqlist -platform 82CA -os win10 -osver 1909 -Category Bios 
        Id           : sp141633
        Name         : HP Notebook System BIOS Update (P87)
        category     : BIOS
        Version      : 1.43
        Vendor       : HP Inc.
        releaseType  : Critical
        SSM          : true
        DPB          : false
        Url          : ftp.hp.com/pub/softpaq/sp141501-142000/sp141633.exe
        ReleaseNotes : ftp.hp.com/pub/softpaq/sp141501-142000/sp141633.html
        Metadata     : ftp.hp.com/pub/softpaq/sp141501-142000/sp141633.cva
        MD5          : 5e301f75d60be82dedb0cbaae93b4073
        Size         : 12896520
        ReleaseDate  : 2022-08-15
        UWP          : False

        Id           : sp82360
        Name         : HP Notebook System BIOS Update
        category     : BIOS
        Version      : 1.02
        Vendor       : Inventec
        releaseType  : Routine
        SSM          : true
        DPB          : false
        Url          : ftp.hp.com/pub/softpaq/sp82001-82500/sp82360.exe
        ReleaseNotes : ftp.hp.com/pub/softpaq/sp82001-82500/sp82360.html
        Metadata     : ftp.hp.com/pub/softpaq/sp82001-82500/sp82360.cva
        MD5          : 102d56f0fd27647b3c50de655000dbdd
        Size         : 13757768
        ReleaseDate  : 2017-10-30
        UWP          : False
        """

    while not q.empty():
        work = q.get()

        logger.info(f'Queue {str(work[0])}: {str(work[1])} requested')

        bbid, hp_os, hp_osver, hp_category = work[1]
        psCommand = f'powershell.exe get-softpaqlist -platform {bbid} -os {hp_os} -osver {hp_osver} -Category {hp_category}'
        process = subprocess.Popen(psCommand, stdout=subprocess.PIPE)
        comm_result = process.communicate()[0]
        sp_list = re.findall(r'Id.*: sp\d+', comm_result.decode('utf-8'))  # Get all sp Id entries. Can be more than one.
        sp_list = list(map(lambda i: re.search(r'sp\d+', i).group(0), sp_list))  # Make these into a list.

        logger.info(f'Queue {str(work[0])}: {str(work[1])} returned: {str(sp_list)}')

        result[work[0]] = sp_list

        q.task_done()

    return True


def process_sp(sp, rl, processed_this, processed_previous):
    """Function to process the release notes for a given HP Softpaq."""

    rl += 1
    if not sp in processed_this:

        logger.info(f'{" " * rl * 3}Starting to process: {sp}')

        # Continue if this sp has not already been processed during this execution.

        processed_this.append(sp)
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

    rels_notes = requests.get(ftp_path)

    # If the status of the get is between 200 and 400, the response will evaluate to True, and False otherwise.

    if rels_notes:
        available = True

        # Get the contents of the release notes file.
        # configparser options:
        #    allow_no_value=True - allows sections like [US. Enhancements] to be read without failing.
        #    strict=False - Keeps from failing on duplicate keys such as the 'BatteryHealthManager.exe=' under [DetailFaileInformation] in sp111205.
        with open('RelsNotes.txt', 'w') as fd:
            fd.write(rels_notes.text)
        rn_config = configparser.ConfigParser(allow_no_value=True, strict=False)
        rn_config.read('RelsNotes.txt')

        # Get the release date, and convert to Python format.
        date_string = rn_config['CVA File Information']['CVATimeStamp'][:8]
        rels_date = datetime(int(date_string[0:4]), int(date_string[4:6]), int(date_string[6:8]))
        
        # Get the category of softpaq release.
        category = rn_config['General']['Category']
        
        # If this is a BIOS release, get the BIOS family and release version.
        # Check to see if DdtailFileInforation is empty. (eg. sp142737)
        if category.upper() == 'BIOS':
            if not rn_config['DetailFileInformation']:
                bios_family = next(iter(rn_config['DetailFileInformation'].items()))[1]
                bios_family = bios_family.split(',')[1]
            else:
                bios_family = ''
            rels_version = rn_config['General']['Version']
        else:
            bios_family = ''
            rels_version = ''

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
                cur_cves = cur_cves + re.findall(r'CVE-\d+-\d+', line)
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


def db_read_onecol(read_command):
    """Function to read one column from a HPRelsNotesDb table."""

    con = sqlite3.connect(HPDATABASE)
    cursorObj = con.cursor()

    result = []

    cursorObj.execute(read_command)
    rows = cursorObj.fetchall()
    for row in rows:
       result.append(row[0])

    cursorObj.close()

    return result

def db_read_twocol(read_command):
    """Function to read two columns from a HPRelsNotesDb table."""

    con = sqlite3.connect(HPDATABASE)
    cursorObj = con.cursor()

    result = []

    cursorObj.execute(read_command)
    rows = cursorObj.fetchall()
    for row in rows:
       result.append([row[0], row[1]])

    cursorObj.close()

    return result

def db_write(write_command):
    """Function to write to HPRelsNotesDb table."""

    con = sqlite3.connect(HPDATABASE)
    cursorObj = con.cursor()

    cursorObj.execute(write_command)
    con.commit()
    cursorObj.close()

    return None


# Main code starts here.
# Initialize logging.
if __name__ == '__main__':

    logging.basicConfig(level=logging.INFO, filename=f'hpRelsLog-{datetime.now().strftime("%Y%m%d%H%M")}.log', format='%(asctime)s %(message)s', filemode='w')
    logger = logging.getLogger()

    logger.info('Execution Start.')
    print('Execution start.')

    # Get all supported baseboard IDs, OSs, OS verions, and categories we have to iterate over
    # for the HP CMSL 'get-softpaqlist' PowerShell command.

    supported_bbids = db_read_onecol('SELECT BBID FROM supportedBBID;')
    supported_oss = db_read_onecol('SELECT OS from supportedOS;')
    supported_osvers = db_read_onecol('SELECT OSVer from supportedOSVer;')
    supported_categories = db_read_onecol('SELECT Category from supportedCategory;')

    # Setup input queue and result list for multithreading the HP Command Management Script Library (CMSL) PowerShell commands.
    # Found help from this site: https://www.shanelynn.ie/using-python-threading-for-multiple-results-queue/

    cmsl_queue = Queue(maxsize=0)
    for i, (bb, os, osv, ct) in enumerate (product(supported_bbids, supported_oss, supported_osvers, supported_categories)):
        cmsl_queue.put((i, [bb, os, osv, ct]))

    max_input = len(supported_categories) * len(supported_oss) * len(supported_osvers) * len(supported_bbids)
    cmsl_results = [[] for x in range(max_input)]

    del supported_bbids
    del supported_oss
    del supported_osvers
    del supported_categories

    logging.debug('Number of CMSL commands to process: {max_input}')

    # Start multiple threads to process HP CMSL Powershell commands.

    num_threads = min(5, max_input)

    for i in range(num_threads):
        logging.info(f'Starting thread {i}')
        worker = threading.Thread(target=issue_cmsl, args=(cmsl_queue, cmsl_results))
        worker.daemon = True
        worker.start()

    # Wait here until the queue has been processed

    cmsl_queue.join()
    logging.info('Queue processing complete.')

    # Combine the results into a single list and get rid of duplicates.

    sp_to_process = []
    for item in cmsl_results:
        for sp in item:
            sp_to_process.append(sp)
    sp_to_process = list(dict.fromkeys(sp_to_process))
    del cmsl_results

    logging.info(f'Total of {str(len(sp_to_process))} unique softpaqs to process.')

    # Get a list of softpaqs already processes from previous executions.
    # Only need the sp number and the date. Put these into a dictonary for easy lookup.

    rows = db_read_twocol('SELECT Softpaq, ReleaseDate FROM spReleases;')

    SQL_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    sp_processed_previous = {}
    for row in rows:
        sp_processed_previous[row[0]] = datetime.strptime(row[1], SQL_DATE_FORMAT)
    del rows

    # Process all of the softpaqs returned from the CMSL PowerShell command.

    recurse_level = 0
    sp_processed_this = []

    for sp in sp_to_process:
        process_sp(sp, recurse_level, sp_processed_this, sp_processed_previous)

    logger.info('Execution complete.')
    print('Execution complete.')