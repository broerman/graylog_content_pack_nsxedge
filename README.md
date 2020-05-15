# NSX Edge graylog_content
Graylog extractor for VMWare Firewall NSXedge
The VMware firewall can log to syslog , where the real one message is capsuled in an JSON document as key : "text" 

Extracted fields
- reason
- action
- direction
- protocol
- srcIP
- srcPort
- dstIP
- dstPort
- flag


**message** field  to parse:

    {"sddc_id":"037c42e3-c198-47c1-956c-1e5867210c02","text":"<99>2020-05-15T09:08:27.965Z ip-10-23-254-72.ap-southeast-1.compute.internal FIREWALL_PKTLOG: f2c65dd5 INET TERM 24642815 IN UDP 10.23.150.100\/53408->10.123.70.101\/53 1\/1 72\/103","timestamp":1.589533710199E12}

##### Steps to extract


- nsxedge_get_json
- nsxegde_text_grok
- timestamp_from_iso
- nsxedge_message_grok

### Extractor


```
{
  "extractors": [
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
    }
  ],
  "version": "3.1.3"
}
```

