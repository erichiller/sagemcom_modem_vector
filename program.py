import asyncio
import json
import os
from sagemcom_api.client import SagemcomClient
from sagemcom_api.enums import EncryptionMethod
from sagemcom_api.exceptions import NonWritableParameterException
from typing import Any, Dict, List, Optional


HOST = os.environ['SAGEMCOM_HOST']
PASSWORD = os.environ['SAGEMCOM_PASSWORD']
USERNAME = "admin"
ENCRYPTION_METHOD = EncryptionMethod.SHA512  # or EncryptionMethod.MD5


# def export(obj: Any) -> Dict[str, Any]:
#     dict: Dict[str, Any] = {}
#     for x in dataclasses.fields(obj):
#         dict[x.name] = obj.__getattribute__(x.name)
#     return dict


# def emitVectorMetric_NestedDict(keys: List[str], value: Dict[str, str], **tags: Optional[Dict[str, str]]):
#     # if not isinstance(tags, dict):
#     #     tags = { }
#     # if 'host' not in tags.keys():
#     #     tags['host'] = HOST
#     # if isinstance(value, dict) and isinstance(name, List):
#     #     keys = name
#     #     for key in keys:
#     #         value = value[key]
#     for key in keys:
#         value = value[key]
#     name = '_'.join(keys)
#     emitVectorMetric(name, value)


# https://prometheus.io/docs/practices/naming/
# https://github.com/vectordotdev/vector/blob/master/lib/codecs/tests/data/native_encoding/schema.cue
# def emitVectorMetric(name: str, value: Any, *tags_dict_array: List[Dict[str, str]], **tags: Optional[Dict[str, str]]):
#     emitVectorMetric(name, value, "gauge", tags_dict_array, tags)

# def emitVectorCounterMetric(name: str, value: Any, *tags_dict_array: List[Dict[str, str]], **tags: Optional[Dict[str, str]]):
#     emitVectorMetric(name, value, 'counter', tags_dict_array, tags)

# value_kind should be either counter or gauge
def emitVectorMetric(name: str, value: Any, value_kind: str, *tags_dict_array: List[Dict[str, str]], **tags: Optional[Dict[str, str]]):
    if not isinstance(tags, dict):
        # print(f'tags was not dict. tags={tags}')
        tags = { }
    for tagsDict in tags_dict_array:
        if isinstance(tagsDict, dict):
            tags = tags | tagsDict
    # print(f'tags={tags}')
    # tags = tags | tagsDict
    if 'host' not in tags.keys():
        tags['host'] = HOST
    if isinstance(value, dict) and isinstance(name, List):
        keys = name
        for key in keys:
            value = value[key]
        name = '_'.join(keys)
    for key in tags.keys():
        tags[key] = str(tags[key])
    # normalize value
    if isinstance(value, str):
        value = float(value)
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    print(json.dumps({'metric': {
        'name':       name,
        # namespace?: string
        'namespace': 'sagemcom',
        # tags?: {[string]: #TagValueSet}
        'tags': tags,
        # timestamp?:   #Timestamp
        # interval_ms?: int
        'kind': 'absolute',  # "incremental" | "absolute"
        f"{value_kind}": {
            'value': value
        }
        # {counter: value: number} |
        # {gauge: value: number} |
    }}))


def firstOrDefault( list: List[Any] ):
    if (len(list) == 1):
        return list[0]
    return None


async def main() -> None:
    async with SagemcomClient(HOST, USERNAME, PASSWORD, ENCRYPTION_METHOD) as client:
        try:
            await client.login()
        except Exception as exception:  # pylint: disable=broad-except
            print(exception)
            exit(1)
            return

        # print(f"Uptime={device_info.up_time}")
        all_data = {}

        test_xpath = "Device/DeviceInfo"
        custom_command_output = await client.get_value_by_xpath(test_xpath)
        all_data['device_deviceinfo'] = custom_command_output
        # print(f"""
        # === {test_xpath} ===
        # {custom_command_output}
        # """)

        # custom_command_output['device_info']['up_time']
        emitVectorMetric(
            ['device_info', 'up_time'],
            custom_command_output,
            'counter'
        )

        # TODO: should add as tag?
        custom_command_output['device_info']['external_firmware_version']
        # TODO: should add as tag?
        custom_command_output['device_info']['internal_firmware_version']

        # custom_command_output['device_info']['memory_status']['total']
        emitVectorMetric(
            ['device_info', 'memory_status', 'total'],
            custom_command_output,
            "gauge"
        )
        # custom_command_output['device_info']['memory_status']['free']
        emitVectorMetric(
            ['device_info', 'memory_status', 'free'],
            custom_command_output,
            "gauge"
        )
        # custom_command_output['device_info']['memory_status']['free_memory_percentage']
        emitVectorMetric(
            ['device_info', 'memory_status', 'free_memory_percentage'],
            custom_command_output,
            "gauge"
        )

        # cpu_usage only ever reports 0
        # custom_command_output['device_info']['process_status']['cpu_usage']
        # emitVectorMetric(
        #     ['device_info', 'process_status', 'cpu_usage'],
        #     custom_command_output,
        #     "gauge"
        # )
        # custom_command_output['device_info']['process_status']['load_average']['load1']
        emitVectorMetric(
            ['device_info', 'process_status', 'load_average', 'load1'],
            custom_command_output,
            "gauge"
        )
        # custom_command_output['device_info']['process_status']['load_average']['load5']
        emitVectorMetric(
            ['device_info', 'process_status', 'load_average', 'load5'],
            custom_command_output,
            "gauge"
        )
        # custom_command_output['device_info']['process_status']['load_average']['load15']
        emitVectorMetric(
            ['device_info', 'process_status', 'load_average', 'load15'],
            custom_command_output,
            "gauge"
        )

        # TO-DO: REQUIRES TESTING; I've seen mainSensor change. Not blvSensor1 or blvSensor2, so far I've only seen '25' on them
        tempSensor0 = custom_command_output['device_info']['temperature_status']['temperature_sensors'][0]
        emitVectorMetric(
            'device_info_temperature_status_temperature_sensors_0',
            tempSensor0['value'],
            "gauge",
            alias=tempSensor0['alias']
        )


        # ####################
        # WiFi
        # ####################

        test_xpath = "Device/Hosts/Hosts"
        custom_command_output = await client.get_value_by_xpath(test_xpath)
        all_data['hosts'] = custom_command_output
        hosts = custom_command_output

        # active_hosts = {host['phys_address']: host for host in hosts if host['active']}
        # active_hosts = {host['phys_address']: host['user_friendly_name'] for host in hosts if host['active']}
        active_hosts = {host['phys_address']: {
            'phys_address': host['phys_address'],
            'active': host['active'],
            'name': host['user_friendly_name'] if host['user_friendly_name'] != host['phys_address'] else host['host_name'],
            'host_name': host['host_name'],
            'user_host_name': host['user_host_name'],
            'user_friendly_name': host['user_friendly_name'],
            'ipv4_lease_time_remaining': host['lease_time_remaining'],
            'ipv4_address': host['ip_address'],
            'ipv6_lease_time_remaining': host['i_pv6_lease_time_remaining'] if firstOrDefault([ip_entry['ip_address'] for ip_entry in host['i_pv6_addresses'] if ip_entry['type'] == "DHCPv6" ]) is not None else None,
            'ipv6_address': firstOrDefault([ip_entry['ip_address'] for ip_entry in host['i_pv6_addresses'] if ip_entry['type'] == "DHCPv6" ]),
        } for host in hosts if host['active']}

        # print(json.dumps( active_hosts, indent=4))
        # exit(0)

        # Radios
        test_xpath = "Device/WiFi/Radios"
        custom_command_output = await client.get_value_by_xpath(test_xpath)
        all_data['device_wifi_radios'] = custom_command_output
        wifi_radios = custom_command_output

        # SSIDs
        test_xpath = "Device/WiFi/SSIDs"
        custom_command_output = await client.get_value_by_xpath(test_xpath)
        all_data['device_wifi_ssids'] = custom_command_output
        ssid_infos = custom_command_output
        for ssid_info in custom_command_output:
            if ssid_info['enable'] is False or ssid_info['uid'] > 2:
                continue
            wifi_radio = [r for r in wifi_radios if r['name'] == ssid_info['lower_layers']][0]
            tags = {
                'ssid': ssid_info['SSID'],
                'mac_address': ssid_info['mac_address'],
                'interface_name': ssid_info['ifc_name'],
                'operating_frequency_band': wifi_radio['operating_frequency_band'],
                'channel': wifi_radio['channel'],
                'channel_bandwith': wifi_radio['current_operating_channel_bandwidth']
            }
            emitVectorMetric(
                'wifi_ssid_sent_bytes_total',
                ssid_info['stats']['bytes_sent'],
                "counter",
                tags
            )
            emitVectorMetric(
                'wifi_ssid_received_bytes_total',
                ssid_info['stats']['bytes_received'],
                "counter",
                tags
            )
            emitVectorMetric(
                'wifi_ssid_sent_packets_total',
                ssid_info['stats']['packets_sent'],
                "counter",
                tags
            )
            emitVectorMetric(
                'wifi_ssid_received_packets_total',
                ssid_info['stats']['packets_received'],
                "counter",
                tags
            )
            emitVectorMetric(
                'wifi_ssid_errors_sent_total',
                ssid_info['stats']['errors_sent'],
                "counter",
                tags
            )
            emitVectorMetric(
                'wifi_ssid_errors_received_total',
                ssid_info['stats']['errors_received'],
                "counter",
                tags
            )


        test_xpath = "Device/WiFi/AccessPoints"
        custom_command_output = await client.get_value_by_xpath(test_xpath)
        all_data['device_wifi_accesspoints'] = custom_command_output
        for ap_data in custom_command_output:
            # print(json.dumps( ap_data, indent=4))
            # exit(0)
            if ap_data['uid'] > 2:
                continue
            for ssid_info in ssid_infos:
                if ssid_info['name'] == ap_data['ssid_reference']:
                    ap_ssid = ssid_info['SSID']
                    ap_mac_address = ssid_info['mac_address']
                    ap_interface_name = ssid_info['ifc_name']
                    break
            # print(json.dumps( ap_data, indent=4))
            # exit(0)
            for client_data in [x for x in ap_data['associated_devices'] if x['active'] is True]:
                tags = {
                    'mac_address': client_data['mac_address'],
                    'ap_uid': ap_data['uid'],
                    'operating_standard': client_data['operating_standard'],  # TODO: should this be a value?
                    'channel': client_data['stats']['channel'],  # TODO: should this be a value?
                    'ssid': ap_ssid,
                    'ap_mac_address': ap_mac_address,
                    'ap_interface_name': ap_interface_name
                }
                if client_data['mac_address'] in active_hosts:
                    host = active_hosts[client_data['mac_address']]
                    tags['name'] = host['name']
                    tags['host_name'] = host['host_name']
                    tags['ipv4_address'] = host['ipv4_address']
                    if host['ipv6_address'] is not None:
                        tags['ipv6_address'] = host['ipv6_address']

                emitVectorMetric(
                    'wifi_device_disassociations_total',
                    client_data['disassociations_number'],
                    "counter",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_sent_bytes_total',
                    client_data['stats']['bytes_sent'],
                    "counter",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_received_bytes_total',
                    client_data['stats']['bytes_received'],
                    "counter",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_sent_packets_total',
                    client_data['stats']['packets_sent'],
                    "counter",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_received_packets_total',
                    client_data['stats']['packets_received'],
                    "counter",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_errors_sent_total',
                    client_data['stats']['errors_sent'],
                    "counter",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_retrans_count_total',
                    client_data['stats']['retrans_count'],
                    "counter",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_failed_retrans_count_total',
                    client_data['stats']['failed_retrans_count'],
                    "counter",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_retry_count_total',
                    client_data['stats']['retry_count'],
                    "counter",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_tx_retries_total',
                    client_data['stats']['tx_retries'],
                    "counter",
                    tags
                )
                # gauges
                emitVectorMetric(
                    'wifi_device_rx_rate',
                    client_data['stats']['rx_rate'],
                    "gauge",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_tx_rate',
                    client_data['stats']['tx_rate'],
                    "gauge",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_rssi_avg_db',
                    client_data['stats']['rssi_sum'],
                    "gauge",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_signal_strength_db',
                    client_data['signal_strength'],
                    "gauge",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_signal_noise_db',
                    client_data['noise'],
                    "gauge",
                    tags
                )
                emitVectorMetric(
                    'wifi_device_up_time_seconds',
                    client_data['stats']['uptime'],
                    "gauge",
                    tags
                )


        # ####################
        # Interfaces
        # ####################
        # test_xpath = "Device/IP/Interfaces/Interface[@uid='2']/Stats"
        test_xpath = "Device/IP/Interfaces"
        custom_command_output = await client.get_value_by_xpath(test_xpath)
        all_data['device_ip_interfaces'] = custom_command_output
        for interface_data in custom_command_output:
            if interface_data['uid'] > 2:
                continue
            tags = {
                'interface_name': interface_data['ifc_name'],
                # 'status': interface_data['status'],
                # 'enable': interface_data['enable']
                # maybe? (possibly static values?)
                # device_ip_interfaces[0].i_pv6_addresses[1].ip_address
                # device_ip_interfaces[0].i_pv6_prefixes[2].prefix
            }
            emitVectorMetric(
                'ip_interfaces_sent_bytes_total',
                interface_data['stats']['bytes_sent'],
                "counter",
                tags
            )
            emitVectorMetric(
                'ip_interfaces_received_bytes_total',
                interface_data['stats']['bytes_received'],
                "counter",
                tags
            )
            emitVectorMetric(
                'ip_interfaces_sent_packets_total',
                interface_data['stats']['packets_sent'],
                "counter",
                tags
            )
            emitVectorMetric(
                'ip_interfaces_received_packets_total',
                interface_data['stats']['packets_received'],
                "counter",
                tags
            )


        # ####################
        # Downstreams
        # ####################

        docsis_downstream_xpath = "Device/Docsis/CableModem/Downstreams"
        custom_command_output = await client.get_value_by_xpath(docsis_downstream_xpath)

        all_data['docsis_cablemodem_downstreams'] = custom_command_output
        # print(f"""
        # docsis_downstream_xpath:
        # {json.dumps(custom_command_output, indent=2)}
        # """)
        # exit(0)

        for channel_data in custom_command_output:
            tags = {
                'channel_id': str(channel_data['channel_id']),
                'lock_status': str(channel_data['lock_status']),  # TODO: not sure if this should be a tag, does the value ever change?
                'frequency': str(channel_data['frequency']),
                'modulation': str(channel_data['modulation']),    # TODO: not sure if this should be a tag, does the value ever change?
                'band_width': channel_data['band_width'],    # TODO: not sure if this should be a tag, does the value ever change?
                'symbol_rate': channel_data['symbol_rate'],   # TODO: not sure if this should be a tag, does the value ever change?
            }
            emitVectorMetric(
                'docsis_cablemodem_downstreams_snr',
                channel_data['SNR'],
                "gauge",
                tags
            )
            emitVectorMetric(
                'docsis_cablemodem_downstreams_power_level',
                channel_data['power_level'],
                "gauge",
                tags
            )
            emitVectorMetric(
                'docsis_cablemodem_downstreams_unerrored_codewords_total',
                channel_data['unerrored_codewords'],
                'counter',
                tags
            )
            emitVectorMetric(
                'docsis_cablemodem_downstreams_correctable_codewords_total',
                channel_data['correctable_codewords'],
                'counter',
                tags
            )
            emitVectorMetric(
                'docsis_cablemodem_downstreams_uncorrectable_codewords_total',
                channel_data['uncorrectable_codewords'],
                'counter',
                tags
            )



        # ######################
        # Upstreams
        # ######################
        docsis_upstream_xpath = "Device/Docsis/CableModem/Upstreams"
        custom_command_output = await client.get_value_by_xpath(docsis_upstream_xpath)

        all_data['docsis_cablemodem_upstreams'] = custom_command_output
        for channel_data in custom_command_output:
            tags = {
                'channel_id': channel_data['channel_id'],
                'lock_status': channel_data['lock_status'],  # TODO: not sure if this should be a tag, does the value ever change?
                'frequency': channel_data['frequency'],
                'symbol_rate': channel_data['symbol_rate'],   # TODO: not sure if this should be a tag, does the value ever change?
                'modulation': channel_data['modulation'],    # TODO: not sure if this should be a tag, does the value ever change?
            }
            emitVectorMetric(
                'docsis_cablemodem_upstreams_power_level',
                channel_data['power_level'],
                "gauge",
                tags
            )
        # print(f"""
        # docsis_upstream_xpath:
        # {json.dumps(custom_command_output, indent=2)}
        # """)

asyncio.run(main())
