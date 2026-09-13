import { Repository } from 'typeorm';
import { SecurityAuditEvent } from './security-audit-event.enum';
import { SecurityAuditLog } from './security-audit-log.entity';
import { SecurityAuditService } from './security-audit.service';

describe('SecurityAuditService', () => {
  it('drops secret-like metadata keys before persistence', async () => {
    const insertMock = jest.fn().mockResolvedValue({ identifiers: [] });
    const repository = {
      insert: insertMock,
    } as unknown as Repository<SecurityAuditLog>;
    const service = new SecurityAuditService(repository);

    await service.record({
      eventType: SecurityAuditEvent.LOGIN_FAILED,
      ipAddress: '127.0.0.1',
      metadata: {
        reason: 'invalid_credentials',
        password: 'must-not-be-stored',
        access_token: 'must-not-be-stored',
        verification_code: 'must-not-be-stored',
      },
    });

    expect(insertMock).toHaveBeenCalledWith(
      expect.objectContaining({
        event_type: SecurityAuditEvent.LOGIN_FAILED,
        ip_address: '127.0.0.1',
        metadata: { reason: 'invalid_credentials' },
      }),
    );
  });
});
