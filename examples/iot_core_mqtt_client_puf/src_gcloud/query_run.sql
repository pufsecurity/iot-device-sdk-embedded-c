SELECT JSON_VALUE(json_text.data, "$.hostname") AS hostname,
        CAST(JSON_VALUE(json_text.data, "$.interval") AS INT64) AS interval_,
        JSON_VALUE(json_text.data, "$.timestamp") AS timestamp,
        JSON_VALUE(json_text.data, "$.CPU") AS CPU,
        CAST(JSON_VALUE(json_text.data, "$.user") AS FLOAT64) AS user,
        CAST(JSON_VALUE(json_text.data, "$.nice") AS FLOAT64) AS nice,
        CAST(JSON_VALUE(json_text.data, "$.system") AS FLOAT64) AS system,
        CAST(JSON_VALUE(json_text.data, "$.iowait") AS FLOAT64) AS iowait,
        CAST(JSON_VALUE(json_text.data, "$.steal") AS FLOAT64) AS steal,
        CAST(JSON_VALUE(json_text.data, "$.idle") AS FLOAT64) AS idle,
        CAST(JSON_VALUE(json_text.data, "$.kbmemfree") AS INT64) AS kbmemfree,
        CAST(JSON_VALUE(json_text.data, "$.kbavail") AS INT64) AS kbavail,
        CAST(JSON_VALUE(json_text.data, "$.kbmemused") AS INT64) AS kbmemused,
        CAST(JSON_VALUE(json_text.data, "$.memused") AS FLOAT64) AS memused,
        CAST(JSON_VALUE(json_text.data, "$.kbbuffers") AS INT64) AS kbbuffers,
        CAST(JSON_VALUE(json_text.data, "$.kbcached") AS INT64) AS kbcached,
        CAST(JSON_VALUE(json_text.data, "$.kbcommit") AS INT64) AS kbcommit,
        CAST(JSON_VALUE(json_text.data, "$.commit") AS FLOAT64) AS commit,
        CAST(JSON_VALUE(json_text.data, "$.kbactive") AS INT64) AS kbactive,
        CAST(JSON_VALUE(json_text.data, "$.kbinact") AS INT64) AS kbinact,
        CAST(JSON_VALUE(json_text.data, "$.kbdirty") AS INT64) AS kbdirty,
        JSON_VALUE(json_text.data, "$.IFACE") AS IFACE,
        CAST(JSON_VALUE(json_text.data, "$.rxpck") AS FLOAT64) AS rxpck,
        CAST(JSON_VALUE(json_text.data, "$.txpck") AS FLOAT64) AS txpck,
        CAST(JSON_VALUE(json_text.data, "$.rxkB") AS FLOAT64) AS rxkB,
        CAST(JSON_VALUE(json_text.data, "$.txkB") AS FLOAT64) AS txkB,
        CAST(JSON_VALUE(json_text.data, "$.rxcmp") AS FLOAT64) AS rxcmp,
        CAST(JSON_VALUE(json_text.data, "$.txcmp") AS FLOAT64) AS txcmp,
        CAST(JSON_VALUE(json_text.data, "$.rxmcst") AS FLOAT64) AS rxmcst,
        CAST(JSON_VALUE(json_text.data, "$.ifutil") AS FLOAT64) AS ifutil,
        JSON_VALUE(json_text.data, "$.reboot") AS Last_reboot_time

FROM `a-plus-project.test.test3` AS json_text;

