# This transform converts POP3Check warning to critical

import re

TIME_WINDOW = 540

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
        first_time = events[0]['first_seen_time'] / 1000.0
 
        # Close the existing event if it was first seen more than X sec ago.
        if first_time < time.time() - TIME_WINDOW:
     
            # We close based on what amounts to the auto-clear fingerprint so that
            # the escalated and non-escalated events all get cleared.
            zep.closeEventSummaries(
                eventFilter=zep.createEventFilter(
                    element_identifier=evt.device,
                    element_sub_identifier=evt.component,
                    event_class=evt.eventClass,
                    event_key=evt.eventKey))


        if existing_count >= 3:
            evt.severity = 5