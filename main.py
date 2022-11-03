from datetime import datetime
import sqlite3
import subprocess
import re
import logging
import threading
from queue import Queue
from spRels import spRels


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


def process_sp(sp, rl):
    """Function to process the release notes for a given HP Softpaq."""
    
    global sp_processed_this
    global sp_processed_previous
    global con, cursorObj

    rl += 1
    if not sp in sp_processed_this:

        # Continue if this sp has not already been processed during this execution.

        sp_processed_this.append(sp)
        sp_obj = spRels(sp)

        sp_new_or_updated = False
        if sp in sp_processed_previous:
            if sp_obj.rels_date > sp_processed_previous[sp]:
                
                # If this softpaq was processed in a previous execution, and the release notes have a newer release date,
                # process it again to provide any updates.

                sp_new_or_updated = True

                logger.info(f'{" " * rl * 3}Updating previously processed: {sp}')
                
                # Update the softpaq release information in the database.

                sql = (
                    f"UPDATE spReleases SET Category='{sp_obj.category}', ReleaseDate='{str(sp_obj.rels_date)}', ReleaseVersion='{sp_obj.rels_version}', "
                    f"BIOSFamily='{sp_obj.bios_family}', CVEsResolved={sp_obj.cves_resolved} WHERE Softpaq='{sp_obj.number}';"
                    )
                cursorObj.execute(sql)
                con.commit()
        else:

            # Otherwise, if this softpaq was not processed previously during this execution, or during a previous execution,
            # this is a new softpaq. So process it.
            
            sp_new_or_updated = True

            logger.info(f'{" " * rl * 3}Processing new: {sp_obj.path}')

            # Save the new softpaq release information to the database.

            sql = (
                f"INSERT INTO spReleases (Softpaq, Category, ReleaseDate, ReleaseVersion, BIOSFamily, CVEsResolved) "
                f"VALUES ('{sp_obj.number}', '{sp_obj.category}', '{str(sp_obj.rels_date)}', '{sp_obj.rels_version}', '{sp_obj.bios_family}', {sp_obj.cves_resolved});"
                )
            cursorObj.execute(sql)
            con.commit()

        if sp_new_or_updated:

            # Whether this is a new softpaq, or we are updating a previous softpaq, process as normal from here.
            # Save the BBID information to the database, avoiding duplicate entries.

            for bbid in sp_obj.CurSysIds:
                sql = (
                    f"INSERT OR IGNORE INTO spToBBID (Softpaq, BBID) "
                    f"VALUES ('{sp_obj.number}', '{bbid}');"
                    )
                cursorObj.execute(sql)
            con.commit()

            # Save the CVE information to the database, avoiding duplicate entries.
            
            for cve in sp_obj.CurCVEs:
                sql = (
                    f"INSERT OR IGNORE INTO spToCVE (Softpaq, CVE) "
                    f"VALUES ('{sp_obj.number}', '{cve}');"
                    )
                cursorObj.execute(sql)
            con.commit

            # Just log that we are done with this softpaq. Note if release notes were not found.

            if sp_obj.available:
                logger.info(f'{" " * rl * 3}Completed: {sp_obj.path} : CVEs found: {str(sp_obj.cves_resolved)}')
            else:
                logger.info(f'{" " * rl * 3}No release file found for: {sp}')

            # Finally, process the superseded softpaqs found in the release notes.

            superseded = sp_obj.superseded_sp
            del sp_obj  # No longer need our original sp object. Delete it before recurse.
            for sp_sup in superseded:
                process_sp(sp_sup, rl)
   
        else:
                # Softpaq was processed in a previous execution, and release notes have not been updated. Skip it.
                
                logger.info(f'{" " * rl * 3}Skipping previously processed in past execution: {sp}')
    else:
        # Softpaq was already processed in this execution, so skip it.
        
        logger.info(f'{" " * rl * 3}Skipping already processed in this execution: {sp}')



# Main code starts here.
# Initialize logging.
if __name__ == '__main__':

    logging.basicConfig(level=logging.INFO, filename=f'hpRelsLog-{datetime.now().strftime("%Y%m%d%H%M")}.log', format='%(asctime)s %(message)s', filemode='w')
    logger = logging.getLogger()

    logger.info('Execution Start.')
    print('Execution start.')

    # Connect to the database. Using SQLite3 for now.

    con = sqlite3.connect('HPRelsNotesDb.db')
    cursorObj = con.cursor()

    # Get all supported baseboard IDs, OSs, OS verions, and categories we have to iterate over
    # for the HP CMSL 'get-softpaqlist' command.

    supported_bbids = []
    cursorObj.execute('SELECT BBID FROM supportedBBID;')
    rows = cursorObj.fetchall()
    for row in rows:
        supported_bbids.append(row[0])

    supported_oss = []
    cursorObj.execute('SELECT OS from supportedOS;')
    rows = cursorObj.fetchall()
    for row in rows:
        supported_oss.append(row[0])

    supported_osvers = []
    cursorObj.execute('SELECT OSVer from supportedOSVer;')
    rows = cursorObj.fetchall()
    for row in rows:
        supported_osvers.append(row[0])

    supported_categories = []
    cursorObj.execute('SELECT Category from supportedCategory;')
    rows = cursorObj.fetchall()
    for row in rows:
        supported_categories.append(row[0])

    # Setup input queue and result list for multithreading.
    # Found help from this site: https://www.shanelynn.ie/using-python-threading-for-multiple-results-queue/

    cmsl_queue = Queue(maxsize=0)
    i = 0
    for bb in supported_bbids:
        for os in supported_oss:
            for osv in supported_osvers:
                for ct in supported_categories:
                    cmsl_queue.put((i, [bb, os, osv, ct]))
                    i += 1

    max_input = len(supported_categories) * len(supported_oss) * len(supported_osvers) * len(supported_bbids)
    cmsl_results = [[] for x in range(max_input)]

    logging.debug('Number of CMSL commands to process: {max_input}')

    # Start multiple threads to process HP CMSL Powershell command.

    num_threads = min(5, max_input)

    for i in range(num_threads):
        logging.debug(f'Starting thread {i}')
        worker = threading.Thread(target=issue_cmsl, args=(cmsl_queue, cmsl_results))
        worker.setDaemon(True)
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

    logging.info(f'Total of {str(len(sp_to_process))} unique softpaqs to process.')

    # Get a list of softpaqs already processes from previous executions.
    # Only need the sp number and the date. Put these into a dictonary for easy lookup.

    SQL_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    sp_processed_previous = {}
    cursorObj.execute('SELECT Softpaq, ReleaseDate FROM spReleases;')
    rows = cursorObj.fetchall()
    for row in rows:
        sp_processed_previous[row[0]] = datetime.strptime(row[1], SQL_DATE_FORMAT)

    # Process all of the softpaqs returned from the CMSL PowerShell command.

    recurse_level = 0
    sp_processed_this = []

    for sp in sp_to_process:
        process_sp(sp, recurse_level)

    cursorObj.close()  # Close the database connection.
    logger.info('Execution complete.')
    print('Execution complete.')