package libdns_yandex_cloud

import (
    "context"
    "strings"
    "github.com/libdns/libdns"
)

type Provider struct {
    ServiceAccountConfigPath string
    ServiceConfigParsed serviceConfig
    AuthAPIToken string `json:"auth_api_token"`
}

func (p *Provider) UpdateApiToken() (error) {
    if p.ServiceConfigParsed == (serviceConfig{}) {
        parseServiceConfig(p.ServiceAccountConfigPath, &p.ServiceConfigParsed)
    }
    token, err := getIAMToken(p.ServiceConfigParsed)
    if err != nil {
        return err
    }
    p.AuthAPIToken = token
    return nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
    p.UpdateApiToken()
    records, err := getAllRecords(ctx, p.AuthAPIToken, p.ServiceConfigParsed.DnsZoneId)
    if err != nil {
        return nil, err
    }

    return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
    p.UpdateApiToken()
    newRecords, err := updateRecords(ctx, p.AuthAPIToken, p.ServiceConfigParsed.DnsZoneId, records, "ADD")
    if err != nil {
        return nil, err
    }

    return newRecords, nil
}

// DeleteRecords deletes the records from the zone.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
    p.UpdateApiToken()
    _, err := updateRecords(ctx, p.AuthAPIToken, p.ServiceConfigParsed.DnsZoneId, records, "DELETE")
    if err != nil {
        return nil, err
    }

    return records, nil
}

// SetRecords sets the records in the zone, either by updating existing records
// or creating new ones. It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
    p.UpdateApiToken()
    setRecords, err := upsertRecords(ctx, p.AuthAPIToken, p.ServiceConfigParsed.DnsZoneId, records, "MERGE")
    if err != nil {
        return setRecords, err
    }
    return records, nil
}

// unFQDN trims any trailing "." from fqdn. Hetzner's API does not use FQDNs.
func unFQDN(fqdn string) string {
    return strings.TrimSuffix(fqdn, ".")
}

// Interface guards
var (
    _ libdns.RecordGetter   = (*Provider)(nil)
    _ libdns.RecordAppender = (*Provider)(nil)
    _ libdns.RecordSetter   = (*Provider)(nil)
    _ libdns.RecordDeleter  = (*Provider)(nil)
)
