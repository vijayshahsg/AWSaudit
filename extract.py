# extract from JSON to CSV a directory full of AWS audit trails

import os, json, csv, gzip

def getUser (userRec):
    recType = userRec.get('type', '')
    if recType == 'IAMUser':
        return userRec.get('userName', '')
    elif recType == 'AssumedRole':
        return userRec.get('sessionContext', {}).get('sessionIssuer', {}).get('userName', '')
    elif recType == 'Root':
        userName = userRec.get('userName')
        if userName is None:
            return 'Root'
        else:
            return userName
    else:
        return recType

def calculate (recordsDir, csvFile, eventsReported, eventsIgnored, reportAll = False):
    messages = []
    ok = True
    # check input parameters
    if not os.path.isdir(recordsDir):
        ok = False
        messages.append('{} is not a directory'.format(recordsDir))
    if not ok:
        return ok, messages

    with open(csvFile, 'w', newline='') as outH:
        # create CSV writer and write header
        writer = csv.writer(outH)
        writer.writerow(['User Name', 'Source IP', 'Event Time', 'Event Name', 'Parameters', 'Error Code', 'Error Message', 'AWS region', 'Raw record'])

        for inFile in os.listdir(recordsDir):
            fullpath = os.path.join(recordsDir, inFile)
            if os.path.isfile(fullpath):
                with gzip.open(fullpath) as inp:
                    inRec = json.load(inp)
                    for rec in inRec['Records']:
                        if reportAll:
                            fields = [getUser(rec.get('userIdentity', {})),
                                      rec.get('sourceIPAddress'),
                                      rec.get('eventTime'), rec.get('eventName'),
                                      rec.get('requestParameters'), rec.get('errorCode'),
                                      rec.get('errorMessage'), rec.get('awsRegion'), rec]
                            writer.writerow(fields)
                        else:
                            event = rec.get('eventName')
                            if event in eventsReported:
                                fields = [getUser(rec.get('userIdentity', {})),
                                          rec.get('sourceIPAddress'),
                                          rec.get('eventTime'), event,
                                          rec.get('requestParameters'), rec.get('errorCode'),
                                          rec.get('errorMessage'), rec.get('awsRegion'), rec]
                                writer.writerow(fields)
                            elif event not in eventsIgnored:
                                fields = [getUser(rec.get('userIdentity', {})),
                                          rec.get('sourceIPAddress'),
                                          rec.get('eventTime'), '*' + event,
                                          rec.get('requestParameters'), rec.get('errorCode'),
                                          rec.get('errorMessage'), rec.get('awsRegion'), rec]
                                writer.writerow(fields)
        
    return ok, messages
