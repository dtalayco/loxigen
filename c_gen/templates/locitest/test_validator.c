:: # Copyright 2013, Big Switch Networks, Inc.
:: #
:: # LoxiGen is licensed under the Eclipse Public License, version 1.0 (EPL), with
:: # the following special exception:
:: #
:: # LOXI Exception
:: #
:: # As a special exception to the terms of the EPL, you may distribute libraries
:: # generated by LoxiGen (LoxiGen Libraries) under the terms of your choice, provided
:: # that copyright and licensing notices generated by LoxiGen are not altered or removed
:: # from the LoxiGen Libraries and the notice provided below is (i) included in
:: # the LoxiGen Libraries, if distributed in source code form and (ii) included in any
:: # documentation for the LoxiGen Libraries, if distributed in binary form.
:: #
:: # Notice: "Copyright 2013, Big Switch Networks, Inc. This library was generated by the LoxiGen Compiler."
:: #
:: # You may not use this file except in compliance with the EPL or LOXI Exception. You may obtain
:: # a copy of the EPL at:
:: #
:: # http://www.eclipse.org/legal/epl-v10.html
:: #
:: # Unless required by applicable law or agreed to in writing, software
:: # distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
:: # WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
:: # EPL for the specific language governing permissions and limitations
:: # under the EPL.
::
:: include('_copyright.c')
:: import of_g
:: from loxi_utils import loxi_utils
:: from loxi_front_end import type_maps

/**
 * Test message validator
 *
 * Run the message validator on corrupt messages to ensure it catches them.
 */

#include "loci_log.h"

#include <locitest/test_common.h>
#include <loci/loci_validator.h>

static int
test_validate_fixed_length(void)
{
    of_table_stats_request_t *obj = of_table_stats_request_new(OF_VERSION_1_0);
    of_message_t msg = OF_OBJECT_TO_MESSAGE(obj);

    TEST_ASSERT(of_validate_message(msg, of_message_length_get(msg)) == 0);

    of_message_length_set(msg, of_message_length_get(msg) - 1);
    TEST_ASSERT(of_validate_message(msg, of_message_length_get(msg)) == -1);

    of_table_stats_request_delete(obj);
    return TEST_PASS;
}

static int
test_validate_fixed_length_list(void)
{
    of_table_stats_reply_t *obj = of_table_stats_reply_new(OF_VERSION_1_0);
    of_list_table_stats_entry_t list;
    of_table_stats_entry_t element;
    of_message_t msg; 
    of_table_stats_reply_entries_bind(obj, &list);
    of_table_stats_entry_init(&element, OF_VERSION_1_0, -1, 1);
    of_list_table_stats_entry_append_bind(&list, &element);
    of_list_table_stats_entry_append_bind(&list, &element);
    msg = OF_OBJECT_TO_MESSAGE(obj);

    TEST_ASSERT(of_validate_message(msg, of_message_length_get(msg)) == 0);

    of_message_length_set(msg, of_message_length_get(msg) - 1);
    TEST_ASSERT(of_validate_message(msg, of_message_length_get(msg)) == -1);

    of_table_stats_reply_delete(obj);
    return TEST_PASS;
}

static int
test_validate_tlv16_list(void)
{
    of_flow_modify_t *obj = of_flow_modify_new(OF_VERSION_1_0);
    of_list_action_t list;
    of_action_set_tp_dst_t element1;
    of_action_output_t element2;
    of_message_t msg; 
    of_flow_modify_actions_bind(obj, &list);
    of_action_set_tp_dst_init(&element1, OF_VERSION_1_0, -1, 1);
    of_list_action_append_bind(&list, (of_action_t *)&element1);
    of_action_output_init(&element2, OF_VERSION_1_0, -1, 1);
    of_list_action_append_bind(&list, (of_action_t *)&element2);
    msg = OF_OBJECT_TO_MESSAGE(obj);

    TEST_ASSERT(of_validate_message(msg, of_message_length_get(msg)) == 0);

    of_message_length_set(msg, of_message_length_get(msg) - 1);
    TEST_ASSERT(of_validate_message(msg, of_message_length_get(msg)) == -1);

    of_message_length_set(msg, of_message_length_get(msg) + 2);
    TEST_ASSERT(of_validate_message(msg, of_message_length_get(msg)) == -1);

    of_flow_modify_delete(obj);
    return TEST_PASS;
}

/*
 * Create an instance of every message and run it through the validator.
 */
static int
test_validate_all(void)
{
::    for version in of_g.of_version_range:
::        ver_name = loxi_utils.version_to_name(version)
::
::        for cls in reversed(of_g.standard_class_order):
::            if not loxi_utils.class_in_version(cls, version):
::                continue
::            elif type_maps.class_is_virtual(cls):
::                continue
::            elif not loxi_utils.class_is_message(cls):
::                continue
::            #endif
    {
        ${cls}_t *obj = ${cls}_new(${ver_name});
        of_message_t msg;
        ${cls}_${ver_name}_populate(obj, 1);
        msg = OF_OBJECT_TO_MESSAGE(obj);
        TEST_ASSERT(of_validate_message(msg, of_message_length_get(msg)) == 0);
        ${cls}_delete(obj);
    }

::        #endfor
::    #endfor

    return TEST_PASS;
}

int
run_validator_tests(void)
{
    RUN_TEST(validate_fixed_length);
    RUN_TEST(validate_fixed_length_list);
    RUN_TEST(validate_tlv16_list);
    RUN_TEST(validate_all);

    return TEST_PASS;
}
