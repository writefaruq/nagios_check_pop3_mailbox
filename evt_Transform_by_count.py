# This transform converts POP3Check warning to critical

import re

if device: 
    evt.device = device.titleOrId()
    
match = re.search("POP3", evt.summary)

if match:
    evt.Remediation = '''Follow the OTRS wiki page to clear the mailbox jam'''
    #import pdb; pdb.set_trace()
    zep = getFacade('zep')      
    event_class_filter = ['/Cmd/POP3Check']
    evt_filter = zep.createEventFilter(status=(0,1,2),       event_class=event_class_filter)

    events = [x for x in zep.getEventSummariesGenerator( filter=evt_filter)]
    if events:
        existing_count = events[0]['count']


    if existing_count >= 3:
        evt.severity = 5