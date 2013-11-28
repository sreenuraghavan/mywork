import logging

enabled = 0
text_suppression = 0

if text_suppression == 1:
    if evt.count > 1:
        # Suppress anything under 2 counts
        evt.eventState = 0
    else:
        evt.eventState = 2

if enabled == 1:
    # This is an example Zenoss event transform that will escalate an event's
    # severity to critical if it has occurred more than three (3) times in a row
    # without clearing.
    #
    # It is compatible with all existing Zenoss versions which includes up to 4.1
    # at the time this was written.


    log = logging.getLogger("zen.Events")

    # Initialize existing_count.
    existing_count = 0

    # Prefix for fingerprint (dedupid).
    dedupfields = [evt.device, evt.component, evt.eventClass]

    if 'getFacade' in globals() and getFacade('zep'):
        # Zenoss >=4 method.
        if getattr(evt, 'eventKey', False):
            dedupfields += [evt.eventKey, evt.severity]
        else:
            dedupfields += [evt.severity, evt.summary]

        zep = getFacade('zep')
        evt_filter = zep.createEventFilter(
            status=(0,1,2),
            fingerprint='|'.join(map(str, dedupfields)))

        summaries = zep.getEventSummaries(0, 1, filter=evt_filter)
        if summaries['total']:
            existing_count = list(summaries['events'])[0]['count']
    else:
        # Zenoss <4 method.
        if getattr(evt, 'eventKey', False):
            dedupfields += [evt.eventKey, evt.severity]
        else:
            dedupfields += [evt.eventKey, evt.severity, evt.summary]

        em = dmd.Events.getEventManager()
        em.cleanCache()
        try:
            db_evt = em.getEventDetail(dedupid='|'.join(map(str, dedupfields)))
            existing_count = db_evt.count
        except Exception:
            pass

    # Do what you like with the count and event;
    # In this example we up the severity to CRITICAL if the count is > 3
    if existing_count > 1:
        # evt.severity = 5
        log.error("%s >1 = %s, unsuppressed" % (evt.component, existing_count))
        evt.eventState = 0
    else:
        log.error("%s is 1 or 0 = %s, suppressing" % (evt.component, existing_count))
        evt.eventState = 2

# Suppress any non-ping, non-clear events from devices that have outstanding
# ping down events.
#
# This transform is sensitive to the event cache timeout. If the ping down
# event comes in less than "timeout" seconds before the subsequent events, the
# subsequent events will not be suppressed. You can find the event cache
# timeout setting on the Event Manager page in the web interface.
if getattr(evt, 'severity', 0) > 0 \
   and getattr(evt, 'eventClass', '/Unknown') != '/Status/Ping' \
   and device and device.getPingStatus() > 0:
   evt.eventState = 2
