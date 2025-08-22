"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'playbook_log_file_hashes_1' block
    playbook_log_file_hashes_1(container=container)

    return

@phantom.playbook_block()
def locate_source(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("locate_source() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'locate_source' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="locate_source", assets=["maxmind"], callback=join_check_reports)

    return


@phantom.playbook_block()
def source_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("source_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceDnsDomain","artifact:*.id"])

    parameters = []

    # build parameters list for 'source_reputation' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "domain": container_artifact_item[0],
            "context": {'artifact_id': container_artifact_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="source_reputation", assets=["virustotal"], callback=join_check_reports)

    return


@phantom.playbook_block()
def virus_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("virus_search() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.fileHash","artifact:*.id"])

    parameters = []

    # build parameters list for 'virus_search' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "hash": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="virus_search", assets=["virustotal"], callback=join_check_reports)

    return


@phantom.playbook_block()
def join_check_reports(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_check_reports() called")

    if phantom.completed(action_names=["locate_source", "source_reputation", "virus_search"]):
        # call connected block "check_reports"
        check_reports(container=container, handle=handle)

    return


@phantom.playbook_block()
def check_reports(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_reports() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["virus_search:action_result.summary.malicious", ">", 0],
            ["source_reputation:action_result.summary.malicious", ">", 0]
        ],
        conditions_dps=[
            ["virus_search:action_result.summary.malicious", ">", 0],
            ["source_reputation:action_result.summary.malicious", ">", 0]
        ],
        name="check_reports:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        source_country_filter(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_set_status_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def notify_soc_management(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("notify_soc_management() called")

    # set approver and message variables for phantom.prompt call

    user = None
    role = "Automation Engineer"
    message = """ A potentially malicious file download has been detected on a local server with IP\naddress {0}.{0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress"
    ]

    # responses
    response_types = [
        {
            "prompt": "Notify SOC management?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "Reason for decision",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="notify_soc_management", parameters=parameters, response_types=response_types, callback=evaluate_prompt, drop_none=True)

    return


@phantom.playbook_block()
def evaluate_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("evaluate_prompt() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["notify_soc_management:action_result.status", "!=", "success"]
        ],
        conditions_dps=[
            ["notify_soc_management:action_result.status", "!=", "success"]
        ],
        name="evaluate_prompt:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        pin_add_comment_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["notify_soc_management:action_result.summary.responses.0", "==", "Yes"]
        ],
        conditions_dps=[
            ["notify_soc_management:action_result.summary.responses.0", "==", "Yes"]
        ],
        name="evaluate_prompt:condition_2",
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        playbook_event_escalation_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 3
    add_comment_set_status_set_owner_3(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_comment_set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_set_status_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="No malicious reports found, event closed")
    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def pin_add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_add_comment_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, message="Awaiting Action", pin_style="crimson", pin_type="card")
    phantom.comment(container=container, comment="User failed to escalate event within time limit.")

    return


@phantom.playbook_block()
def add_comment_set_status_set_owner_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_set_status_set_owner_3() called")

    notify_soc_management_result_data = phantom.collect2(container=container, datapath=["notify_soc_management:action_result.summary.responses.1"], action_results=results)

    notify_soc_management_summary_responses_1 = [item[0] for item in notify_soc_management_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=notify_soc_management_summary_responses_1)
    phantom.set_owner(container=container, role="Incident Commander")
    phantom.set_status(container=container, status="open")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def playbook_event_escalation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_event_escalation_1() called")

    playbook_log_file_hashes_1_output_hash_status = phantom.collect2(container=container, datapath=["playbook_log_file_hashes_1:playbook_output:hash_status"])
    notify_soc_management_result_data = phantom.collect2(container=container, datapath=["notify_soc_management:action_result.summary.responses.1"], action_results=results)

    playbook_log_file_hashes_1_output_hash_status_values = [item[0] for item in playbook_log_file_hashes_1_output_hash_status]
    notify_soc_management_summary_responses_1 = [item[0] for item in notify_soc_management_result_data]

    inputs = {
        "hash_history": playbook_log_file_hashes_1_output_hash_status_values,
        "escalation_reason": notify_soc_management_summary_responses_1,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Event Escalation", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Event Escalation", container=container, name="playbook_event_escalation_1", callback=playbook_event_escalation_1_callback, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_event_escalation_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_event_escalation_1_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


@phantom.playbook_block()
def source_country_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("source_country_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["locate_source:action_result.data.*.country_name", "in", "custom_list:Banned Countries"]
        ],
        conditions_dps=[
            ["locate_source:action_result.data.*.country_name", "in", "custom_list:Banned Countries"]
        ],
        name="source_country_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        notify_soc_management(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["locate_source:action_result.data.*.country_name", "not in", "custom_list:Banned Countries"]
        ],
        conditions_dps=[
            ["locate_source:action_result.data.*.country_name", "not in", "custom_list:Banned Countries"]
        ],
        name="source_country_filter:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        add_comment_set_severity_set_owner_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def add_comment_set_severity_set_owner_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_set_severity_set_owner_4() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Malicious content found from low risk source")
    phantom.set_owner(container=container, role="Incident Commander")
    phantom.set_severity(container=container, severity="low")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def playbook_log_file_hashes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_log_file_hashes_1() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.fileHash"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "hash": container_artifact_cef_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Log File Hashes", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Log File Hashes", container=container, name="playbook_log_file_hashes_1", callback=playbook_log_file_hashes_1_callback, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_log_file_hashes_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_log_file_hashes_1_callback() called")

    
    source_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    locate_source(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    virus_search(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


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
