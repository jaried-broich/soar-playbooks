"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'decision_1' block
    decision_1(container=container)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_input:hash", "in", "custom_list:Prior Hashes"]
        ],
        conditions_dps=[
            ["playbook_input:hash", "in", "custom_list:Prior Hashes"]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_comment_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_input:hash", "not in", "custom_list:Prior Hashes"]
        ],
        conditions_dps=[
            ["playbook_input:hash", "not in", "custom_list:Prior Hashes"]
        ],
        name="decision_1:condition_2",
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        add_comment_add_to_list_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def add_comment_add_to_list_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_add_to_list_1() called")

    playbook_input_hash = phantom.collect2(container=container, datapath=["playbook_input:hash"])

    playbook_input_hash_values = [item[0] for item in playbook_input_hash]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="File has not been observed before.")
    phantom.add_list(list_name="Prior Hashes", values=playbook_input_hash_values)

    new_hash_content(container=container)

    return


@phantom.playbook_block()
def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="File has been observed before.")

    old_hash_content(container=container)

    return


@phantom.playbook_block()
def old_hash_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("old_hash_content() called")

    template = """This file has been observed before """

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="old_hash_content")

    join_concatenate_hash_status(container=container)

    return


@phantom.playbook_block()
def new_hash_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("new_hash_content() called")

    template = """This file has not been observed before"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="new_hash_content")

    join_concatenate_hash_status(container=container)

    return


@phantom.playbook_block()
def join_concatenate_hash_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_concatenate_hash_status() called")

    # call connected block "concatenate_hash_status"
    concatenate_hash_status(container=container, handle=handle)

    return


@phantom.playbook_block()
def concatenate_hash_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("concatenate_hash_status() called")

    template = """{0}\n{1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "new_hash_content:formatted_data",
        "old_hash_content:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="concatenate_hash_status")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    concatenate_hash_status = phantom.get_format_data(name="concatenate_hash_status")

    output = {
        "hash_status": concatenate_hash_status,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return