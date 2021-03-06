# NSX Edge Content pack
Graylog extractor for VMWare Firewall NSXedge

VMware NSX firewall can ship its log  via syslog protocol.
A linux rsyslog server acts as gateway and sends logdata json formated to kafka message queue system.[look here for an  example](https://github.com/broerman/rsyslog-kafkagelf-gateway) 

graylog fetch logs and extracts data, which are embedded in an JSON document.

The contents_pack consists of the input with parameters for 

#### Content_pack parameters

| parameter    | default_value  |
| ------------ | -------------- |
| title        | nsxedge        |
| zookeeper    | localhost:2181 |
| topic_search | ^nsxedge$      |

You can use extractor export below to upload in your environment.  Then you have to adjust the "source_field" in extractor "nsxedge_get_json".

In this setup graylog expects the whole NSX-Edge log in field : **message**, which is a JSON dokument.



#### Extracted fields

- reason
- action
- direction
- protocol
- srcIP
- srcPort
- dstIP
- dstPort
- flag

#### Sample message
    {"sddc_id":"037c42e3-c198-47c1-956c-1e5867210c02","text":"<99>2020-05-15T09:08:27.965Z ip-10-23-254-72.ap-southeast-1.compute.internal FIREWALL_PKTLOG: f2c65dd5 INET TERM 24642815 IN UDP 10.23.150.100\/53408->10.123.70.101\/53 1\/1 72\/103","timestamp":1.589533710199E12}

#### Steps to extract

1. nsxedge_get_json 

nsxedge_text fields:

    <99>1 2020-05-03T16:55:50.820Z edge NSX 1681 FIREWALL [nsx@6876 comp="nsx-edge" subcomp="datapathd.firewallpkt" level="INFO"] <1 596be8c6421d4422:9f49ede698645afa> INET TERM PASS 17115424 OUT TCP 10.23.150.120/54585->10.10.160.171/443
    <99>2020-05-16T08:08:12.974Z ip-10-23-254-72.ap-southeast-1.compute.internal FIREWALL_PKTLOG: f2c65dd5 INET match PASS 24414552 IN 71 UDP 10.123.13.171/61422->10.123.70.101/53

2. nsxegde_text_grok
3. timestamp_from_iso
4. nsxedge_message_grok

##### Extractor to upload


```
{
  "extractors": [
    {
      "title": "nsxedge_get_json",
      "extractor_type": "json",
      "converters": [],
      "order": 0,
      "cursor_strategy": "copy",
      "source_field": "message",
      "target_field": "",
      "extractor_config": {
        "list_separator": ", ",
        "kv_separator": "=",
        "key_prefix": "nsxedge_",
        "key_separator": "_",
        "replace_key_whitespace": false,
        "key_whitespace_replacement": "_"
      },
      "condition_type": "none",
      "condition_value": ""
    },
    {
      "title": "nsxegde_text_grok",
      "extractor_type": "grok",
      "converters": [],
      "order": 1,
      "cursor_strategy": "copy",
      "source_field": "nsxedge_text",
      "target_field": "",
      "extractor_config": {
        "grok_pattern": "\\<\\d*\\>1 (?<nsxedge_timestamp_iso>%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND}))Z %{WORD} %{WORD} %{WORD} %{WORD} \\[.*\\] \\<\\d \\w*:\\w*\\>\\s*%{GREEDYDATA:nsxedge_message}",
        "named_captures_only": true
      },
      "condition_type": "none",
      "condition_value": ""
    },
    {
      "title": "timestamp_from_iso",
      "extractor_type": "copy_input",
      "converters": [
        {
          "type": "date",
          "config": {
            "date_format": "yyyy-MM-dd'T'HH:mm:ss.SSS",
            "time_zone": "UTC",
            "locale": "und"
          }
        }
      ],
      "order": 2,
      "cursor_strategy": "copy",
      "source_field": "nsxedge_timestamp_iso",
      "target_field": "timestamp",
      "extractor_config": {},
      "condition_type": "none",
      "condition_value": ""
    },
    {
      "title": "nsxedge_message_grok",
      "extractor_type": "grok",
      "converters": [],
      "order": 9,
      "cursor_strategy": "copy",
      "source_field": "nsxedge_message",
      "target_field": "",
      "extractor_config": {
        "grok_pattern": "INET %{NOTSPACE:reason} %{WORD:action} %{POSINT} %{WORD:direction}(?: %{POSINT})? (?<protocol>(TCP|UDP|PROTO \\d+)) %{IP:srcIP}(?:/%{POSINT:srcPort})?->%{IP:dstIP}(?:/%{POSINT:dstPort})?(?: %{WORD:flag})?",
        "named_captures_only": true
      },
      "condition_type": "none",
      "condition_value": ""
    }
  ]
}
```

