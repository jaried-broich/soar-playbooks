"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'compose_report' block
    compose_report(container=container)

    return

@phantom.playbook_block()
def compose_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("compose_report() called")

    template = """{2}{3}{4}{5}{6}A file has been detected that has been determined to be potentially malicious. The event has\nbeen escalated.\n- **Incident link**: {0}\n- **Event Name**: {1}\n- **Description**: {2}\n- **Source domain**: {3}\n- **Target Server IP**: {4}\n- **Suspicious File Path**: {5} (*{7}*)\n- **Reason for promotion**: {6}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
        "container:name",
        "container:description",
        "artifact:*.cef.sourceDnsDomain",
        "artifact:*.cef.destinationAddress",
        "artifact:*.cef.filePath",
        "playbook_input:escalation_reason",
        "playbook_input:hash_history"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="compose_report", drop_none=True)

    set_severity_add_comment_add_note_1(container=container)

    return


@phantom.playbook_block()
def set_severity_add_comment_add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_add_comment_add_note_1() called")

    compose_report = phantom.get_format_data(name="compose_report")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Escalated to high severity")
    phantom.add_note(container=container, content=compose_report, note_format="markdown", note_type="general", title="\"Incident Report\"")
    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return
