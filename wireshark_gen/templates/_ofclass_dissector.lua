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
:: from loxi_ir import *
:: from wireshark_gen import make_field_name
:: attrs = []
:: if ofclass.virtual: attrs.append("virtual")
:: if ofclass.superclass: attrs.append("child")
:: if not ofclass.superclass: attrs.append("top-level")
-- ${' '.join(attrs)} class ${ofclass.name}
:: if ofclass.superclass:
-- Child of ${ofclass.superclass}
:: #endif
:: if ofclass.virtual:
-- Discriminator is ${ofclass.discriminator.name}
:: #endif
function ${name}(reader, subtree)
:: for m in ofclass.members:
:: if isinstance(m, OFPadMember):
    reader.skip(${m.length})
:: continue
:: #endif
:: field_name = make_field_name(version, ofclass.name, m.name)
:: reader_name = "read_" + m.oftype.replace(')', '').replace('(', '_')
    ${reader_name}(reader, ${version}, subtree, '${field_name}')
:: #endfor
    return '${ofclass.name}'
end
