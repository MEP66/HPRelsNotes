from datetime import datetime
import subprocess
import re
import logging
import threading
from itertools import product
from queue import Queue
from db_ops import db_read_onecol, db_read_twocol
from sp_ops import process_sp

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
        Size         : 12896520d
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

    logger = logging.getLogger(__name__)
    
    while not q.empty():
        work = q.get()

        logger.info(f'Queue {str(work[0])}: {str(work[1])} requested')

        bbid, hp_os, hp_osver, hp_category = work[1]
        psCommand = f'powershell.exe get-softpaqlist -platform {bbid} -os {hp_os} -osver {hp_osver} -Category {hp_category} -Overwrite yes'
        process = subprocess.Popen(psCommand, stdout=subprocess.PIPE)
        comm_result = process.communicate()[0]
        sp_list = re.findall(r'Id.*: sp\d+', comm_result.decode('utf-8'))  # Get all sp Id entries. Can be more than one.
        sp_list = list(map(lambda i: re.search(r'sp\d+', i).group(0), sp_list))  # Make these into a list.

        logger.info(f'Queue {str(work[0])}: {str(work[1])} returned: {str(sp_list)}')

        result[work[0]] = sp_list

        q.task_done()

    return True


# Main code starts here.
if __name__ == '__main__':

    # Initialize logging.
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

    num_threads = min(10, max_input)

    for i in range(num_threads):
        logging.info(f'Starting thread {i}')
        worker = threading.Thread(target=issue_cmsl, args=(cmsl_queue, cmsl_results))
        worker.daemon = True
        worker.start()

    # Wait here until the queue has been processed

    cmsl_queue.join()
    logging.info('Queue processing complete.')

    # Combine the results into a single list and get rid of duplicates.

    sp_to_process = [sp for item in cmsl_results
                        for sp in item]
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
    sp_processed_this = set()

    for sp in sp_to_process:
        process_sp(sp, recurse_level, sp_processed_this, sp_processed_previous)

    logger.info('Execution complete.')
    print('Execution complete.')