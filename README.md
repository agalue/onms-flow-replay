# onms-flow-replay

A tool inspired by `tcpreplay` designed for sending data from a Netflow 9 packet capture files to OpenNMS or Sentinel via Kafka, emulating an existing Minion, replacing the timestamps within the flow packets for `first-switched` and `last-switched` to be current.

It can bypass a Minion and send telemetry-flow data to the Sink Topics in Kafka or generate enriched flow-documents ready for Nephron to avoid requiring OpenNMS or Sentinel.

