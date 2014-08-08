# This transform converts POP3Check warning to critical
import re
if device: evt.device = device.titleOrId()
match = re.search("POP3", evt.summary)
if match:
    dedupfields = [evt.device, evt.component, evt.eventClass]
     
    if getattr(evt, 'eventKey', False):
        dedupfields += [evt.eventKey, evt.severity]
    else:
        dedupfields += [evt.severity, evt.summary]
     
    zep = getFacade('zep')
    evt_filter = zep.createEventFilter(
        status=(0,1,2),
        fingerprint='|'.join(map(str, dedupfields)))
     
    summaries = zep.getEventSummaries(0, limit=1, filter=evt_filter)
     
    # Turn the events generator into a list. This consumes the generator so
    # summaries['events'] will be empty after this.
    events = list(summaries['events'])
     
    if summaries['total']:
        import time
             
        existing_count = events[0]['count']
        first_time = events[0]['first_seen_time'] / 1000.0
     
        # Close the existing event if it was first seen more than X sec ago.
        if first_time < time.time() - 540:
     
            # We close based on what amounts to the auto-clear fingerprint so that
            # the escalated and non-escalated events all get cleared.
            zep.closeEventSummaries(
                eventFilter=zep.createEventFilter(
                    element_identifier=evt.device,
                    element_sub_identifier=evt.component,
                    event_class=evt.eventClass,
                    event_key=evt.eventKey))
     
        # Otherwise, increase the severity to CRITICAL if the count is > 3
        elif existing_count > 3:
            evt.severity = 5
            evt.Remediation = '''Follow the OTRS wiki page to clear the mailbox jam''' 