/**
 * Coverage tests for the 1.1 expanded rule set.
 *
 * Each rule gets a positive case (does fire on a real shape) and a negative case
 * (does NOT fire on a tempting-but-safe shape). New rules added in this expansion:
 * PII (name/DoB/address), account info (bank-account/sort/SWIFT), UAE documents
 * (driving license/visa/TRN/national-ID), card info (expiry/cardholder), balance,
 * IPs (public/IPv6/internal), OAuth (client_id/client_secret/refresh), session,
 * CSRF, SSH key, Azure SAS, GCP service-account, public/API token, generic
 * high-entropy secrets.
 */
import {
  ruleLogCustomerName,
  ruleLogDateOfBirth,
  ruleLogAddress,
  ruleLogBankAccountNumber,
  ruleLogSortRoutingCode,
  ruleLogSwiftBic,
  ruleLogUaeDrivingLicense,
  ruleLogUaeVisaPermit,
  ruleLogUaeTrn,
  ruleLogGenericNationalId,
  ruleLogCardExpiry,
  ruleLogCardholderName,
  ruleLogAccountBalance,
  ruleLogCustomerIPv4,
  ruleLogIPv6,
  ruleLogInternalIp,
  ruleLogOAuthCreds,
  ruleLogSessionToken,
  ruleLogCsrfToken,
  ruleLogSshKey,
  ruleLogAzureSas,
  ruleLogGcpServiceAccount,
  ruleLogPublicOrApiToken,
  ruleLogGenericHighEntropySecret,
} from '../src/logs/logRules';

describe('PII expansion', () => {
  test('customer name fires on labelled multi-word value', () => {
    expect(ruleLogCustomerName('customerName="Ali Hassan Ahmed" verified').length).toBe(1);
    expect(ruleLogCustomerName('firstName=Aisha lastName=Al-Mansouri').length).toBeGreaterThan(0);
  });
  test('customer name does NOT fire on placeholders', () => {
    expect(ruleLogCustomerName('customerName=null').length).toBe(0);
    expect(ruleLogCustomerName('customerName="[REDACTED]"').length).toBe(0);
  });

  test('DoB fires on labelled date value', () => {
    expect(ruleLogDateOfBirth('dob=1990-05-12 registered').length).toBe(1);
    expect(ruleLogDateOfBirth('"dateOfBirth": "12/05/1990"').length).toBe(1);
  });
  test('DoB does NOT fire on dates outside DoB context', () => {
    expect(ruleLogDateOfBirth('createdAt=2026-05-29').length).toBe(0);
  });

  test('address fires only on labelled multi-word values with digits', () => {
    expect(ruleLogAddress('address="123 Sheikh Zayed Rd, Dubai"').length).toBe(1);
  });
  test('address does NOT fire on a single short word', () => {
    expect(ruleLogAddress('address="Dubai"').length).toBe(0);
  });
});

describe('Account / financial identifiers', () => {
  test('bank account number fires on 8+ digit labelled value', () => {
    expect(ruleLogBankAccountNumber('account_number=12345678 reconciled').length).toBe(1);
    expect(ruleLogBankAccountNumber('"accountId": "987654321012"').length).toBe(1);
  });
  test('bank account number does NOT fire on order ID', () => {
    expect(ruleLogBankAccountNumber('order_id=12345678').length).toBe(0);
  });

  test('sort/routing code fires on labelled value', () => {
    expect(ruleLogSortRoutingCode('sort_code=12-34-56 cleared').length).toBe(1);
    expect(ruleLogSortRoutingCode('routing_number=011000015').length).toBe(1);
  });

  test('SWIFT/BIC fires on labelled valid format', () => {
    expect(ruleLogSwiftBic('swift=BARCAE2X primary bank').length).toBe(1);
    expect(ruleLogSwiftBic('bic="ENBAAEAA12X"').length).toBe(1);
  });
  test('SWIFT/BIC does NOT fire on invalid format', () => {
    expect(ruleLogSwiftBic('swift=BAD123 placeholder').length).toBe(0);
  });
});

describe('UAE documents', () => {
  test('UAE driving license fires on labelled value', () => {
    expect(ruleLogUaeDrivingLicense('driving_license=DXB12345678 valid').length).toBe(1);
  });

  test('UAE visa fires on labelled value', () => {
    expect(ruleLogUaeVisaPermit('visa=101/2020/3000234 issued').length).toBe(1);
  });

  test('TRN fires on labelled 15-digit value', () => {
    expect(ruleLogUaeTrn('trn=100474723500003 registered').length).toBe(1);
  });
  test('TRN does NOT fire on 14-digit values', () => {
    expect(ruleLogUaeTrn('trn=12345678901234').length).toBe(0);
  });

  test('generic national ID fires on labelled value (non-Emirates-ID shape)', () => {
    expect(ruleLogGenericNationalId('national_id=ABC123456789 verified').length).toBe(1);
  });
  test('generic national ID does NOT collide with UAE Emirates ID', () => {
    expect(ruleLogGenericNationalId('national_id=78419901234567 verified').length).toBe(0);
  });
});

describe('Card information (expanded)', () => {
  test('card expiry fires on MM/YY and MM/YYYY', () => {
    expect(ruleLogCardExpiry('cardExpiry=12/26 amount=99').length).toBe(1);
    expect(ruleLogCardExpiry('"exp": "07/2028"').length).toBe(1);
  });
  test('card expiry does NOT fire on invalid month', () => {
    expect(ruleLogCardExpiry('exp=13/26').length).toBe(0);
  });

  test('cardholder name fires on labelled multi-word value', () => {
    expect(ruleLogCardholderName('cardholder="Ali Ahmed" amount=100').length).toBe(1);
  });
});

describe('Balances', () => {
  test('balance fires on labelled numeric with currency', () => {
    expect(ruleLogAccountBalance('balance=12500.75 AED').length).toBe(1);
  });
  test('balance fires on decimal even without currency', () => {
    expect(ruleLogAccountBalance('availableBalance=987.50').length).toBe(1);
  });
  test('balance does NOT fire on zero or counter values', () => {
    expect(ruleLogAccountBalance('balance=0').length).toBe(0);
    expect(ruleLogAccountBalance('queue_size=12345').length).toBe(0);
  });
});

describe('IP addresses', () => {
  test('public IPv4 in customer-context field fires', () => {
    expect(ruleLogCustomerIPv4('client_ip=8.8.8.8 forwarded').length).toBe(1);
  });
  test('private IPv4 in customer-context field does NOT fire LOG-NET-001', () => {
    expect(ruleLogCustomerIPv4('client_ip=10.0.1.2 forwarded').length).toBe(0);
    expect(ruleLogCustomerIPv4('client_ip=192.168.1.1 forwarded').length).toBe(0);
  });

  test('IPv6 in customer-context field fires', () => {
    expect(ruleLogIPv6('client_ip="2001:db8::1428:57ab" forwarded').length).toBe(1);
  });
  test('IPv6 link-local / loopback does NOT fire', () => {
    expect(ruleLogIPv6('client_ip=::1 loopback').length).toBe(0);
  });

  test('internal IP rule fires on RFC-1918', () => {
    expect(ruleLogInternalIp('upstream 10.0.5.23 connected').length).toBe(1);
    expect(ruleLogInternalIp('host 172.16.0.5 reachable').length).toBe(1);
    expect(ruleLogInternalIp('peer 192.168.10.20').length).toBe(1);
  });
  test('internal IP rule does NOT fire on public IPs', () => {
    expect(ruleLogInternalIp('upstream 8.8.4.4 connected').length).toBe(0);
  });
});

describe('OAuth credentials', () => {
  test('client_secret fires CRITICAL', () => {
    const m = ruleLogOAuthCreds('client_secret=AbCdEf1234567890XyZ');
    expect(m.find((x) => x.ruleId === 'LOG-SEC-005')).toBeDefined();
  });
  test('client_id fires MEDIUM', () => {
    const m = ruleLogOAuthCreds('client_id=customer-portal-prod-2026');
    expect(m.find((x) => x.ruleId === 'LOG-SEC-006')).toBeDefined();
  });
  test('refresh_token fires CRITICAL', () => {
    const m = ruleLogOAuthCreds('refresh_token=def50200a8b4f3a1c2e9d8b7c6a5e4f3d2c1b0a9');
    expect(m.find((x) => x.ruleId === 'LOG-SEC-007')).toBeDefined();
  });
});

describe('Session / CSRF / SSH / cloud secrets', () => {
  test('session_token fires', () => {
    expect(ruleLogSessionToken('JSESSIONID=A1B2C3D4E5F6G7H8I9J0').length).toBe(1);
    expect(ruleLogSessionToken('"sessionId": "s.abc12345xyz98765"').length).toBe(1);
  });

  test('CSRF token fires', () => {
    expect(ruleLogCsrfToken('csrf_token=Ay93sZ8d2A0f8H7g6F5e4D3c2B1a').length).toBe(1);
  });

  test('SSH key fires', () => {
    expect(ruleLogSshKey('user@host ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDx5l8a/key+padding=').length).toBe(1);
  });

  test('Azure SAS fires', () => {
    const sas = '?sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2030-01-01T00:00:00Z&sig=abc123xyz/=%2BFwHQ';
    expect(ruleLogAzureSas(`download ${sas}`).length).toBe(1);
  });

  test('GCP service account fires', () => {
    const line = '{"type": "service_account", "project_id": "x", "private_key_id": "y", "private_key": "-----BEGIN PRIVATE KEY-----\\n..."}';
    expect(ruleLogGcpServiceAccount(line).length).toBe(1);
  });

  test('Public / API token fires', () => {
    expect(ruleLogPublicOrApiToken('access_token=ya29.a0AfH6SMC_abc123xyz98765').length).toBe(1);
  });
});

describe('Generic high-entropy secret', () => {
  test('fires when label ends in _secret/_key/_token AND value is high entropy', () => {
    expect(ruleLogGenericHighEntropySecret('webhook_signing_secret=eYxJh3KqL9mNpQrSt6vWx8yZbCdFgHjK').length).toBe(1);
  });
  test('does NOT fire on low-entropy values', () => {
    expect(ruleLogGenericHighEntropySecret('webhook_signing_secret=aaaaaaaaaaaaaaaaaaaaaaaaaa').length).toBe(0);
  });
  test('does NOT double-report tokens already covered by tighter rules', () => {
    expect(ruleLogGenericHighEntropySecret('jwt_secret=eYxJh3KqL9mNpQrSt6vWx8yZbCdFgHjK').length).toBe(0);
    expect(ruleLogGenericHighEntropySecret('access_token=eYxJh3KqL9mNpQrSt6vWx8yZbCdFgHjK').length).toBe(0);
  });
});
