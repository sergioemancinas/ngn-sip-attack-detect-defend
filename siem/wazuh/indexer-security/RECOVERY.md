# Recovery: restore lab-admin full admin on a fresh stack

If the indexer data volume is recreated, the role mappings revert to defaults. Re-apply via REST (no file permissions needed):

```bash
WI_PASS=$(grep "^WAZUH_INDEXER_PASSWORD" .env | cut -d= -f2)
for role in kibana_user alerting_full_access anomaly_full_access \
            index_management_full_access notebooks_full_access notifications_full_access \
            observability_full_access reports_full_access ml_full_access \
            asynchronous_search_full_access security_analytics_full_access knn_full_access \
            ppl_full_access point_in_time_full_access; do
  docker exec ngn-sip-wazuh-wazuh-indexer-1 curl -sk -u "admin:${WI_PASS}" \
    -X PUT -H "Content-Type: application/json" \
    -d '{"backend_roles":["admin","wazuh-admin","all_access","lab-admin"]}' \
    "https://localhost:9200/_plugins/_security/api/rolesmapping/${role}"
done
```

For the reserved `all_access` role, edit via the Wazuh dashboard:
Settings → Roles mapping → all_access → add backend_role `lab-admin`. (Container caps prevent REST PATCH of reserved roles.)

If the Kamailio decoder isn't loading:

```bash
docker cp siem/wazuh/decoders/kamailio.xml ngn-sip-wazuh-wazuh-manager-1:/tmp/k.xml
docker cp siem/wazuh/decoders/asterisk.xml ngn-sip-wazuh-wazuh-manager-1:/tmp/a.xml
docker cp siem/wazuh/rules/sip_rules.xml   ngn-sip-wazuh-wazuh-manager-1:/tmp/s.xml
docker exec -u 0 ngn-sip-wazuh-wazuh-manager-1 sh -c '
  cp /tmp/k.xml /var/ossec/etc/decoders/kamailio.xml
  cp /tmp/a.xml /var/ossec/etc/decoders/asterisk.xml
  cp /tmp/s.xml /var/ossec/etc/rules/sip_rules.xml
  chown wazuh:wazuh /var/ossec/etc/decoders/kamailio.xml /var/ossec/etc/decoders/asterisk.xml /var/ossec/etc/rules/sip_rules.xml
  /var/ossec/bin/wazuh-control restart
'
```
