# Yandex Cloud DNS for [`libdns`](https://github.com/libdns/libdns)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [Yandex Cloud API](https://yandex.cloud/en/docs/dns/api-ref/) allowing you to manage DNS records.


## Authenticate

To authenticate API you need to supply a Yandex Cloud IAM token. It will automatically ensure from Service Account authorization keys.

More info: <https://yandex.cloud/en/docs/dns/api-ref/authentication>


## Usage

```go
package main

import (
    "context"
    "fmt"
    "os"
    "time"

    yandex_cloud "github.com/profcomff/libdns-yandex-cloud"
)

func main() {
    p := &yandex_cloud.Provider{ServiceAccountConfigPath: "./authorized_keys.json"}
    // File structure
    // {
    //     "id": "...",
    //     "service_account_id": "...",
    //     "created_at": "2024-08-04T14:00:38.626813184Z",
    //     "key_algorithm": "RSA_2048",
    //     "public_key": "-----BEGIN PUBLIC KEY-----\n ... \n-----END PUBLIC KEY-----\n",
    //     "private_key": "PLEASE DO NOT REMOVE THIS LINE! Yandex.Cloud SA Key ID <...>\n-----BEGIN PRIVATE KEY-----\n ... \n-----END PRIVATE KEY-----\n",
    //     "dns_zone_id": "..."
    // }


    records, err := p.GetRecords(context.WithTimeout(context.Background(), time.Duration(15*time.Second)), "")
    if err != nil {
        fmt.Printf("Error: %s", err.Error())
        return
    }

    fmt.Println(records)
}
```
