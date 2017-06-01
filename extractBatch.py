import sys
import argparse
import configparser
import extract

parser = argparse.ArgumentParser(description='Extract events from AWS audit trails')
parser.add_argument('-a', '--all', help='List all events', action='store_true')
parser.add_argument('recordsDir', help='Directory of AWS audit trails')
parser.add_argument('csvFile', help='CSV file in which to store events')
parser.add_argument('eventsFile', help='Events specification file')
args = parser.parse_args()

recordsDir = args.recordsDir
csvFile = args.csvFile
showAll = args.all
eventsFile = args.eventsFile

confParser = configparser.SafeConfigParser({'Reported':'', 'Ignored':''})
confParser.read(eventsFile)
eventsReported = confParser.get('Events', 'Reported').split()
eventsIgnored = confParser.get('Events', 'Ignored').split()

ok, messages = extract.calculate(recordsDir, csvFile, eventsReported, eventsIgnored, showAll)
if not ok:
    print('\n'.join(messages))
    exit(1)
    
exit(0)
