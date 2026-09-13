import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SecurityAuditEvent } from './security-audit-event.enum';
import { SecurityAuditLog } from './security-audit-log.entity';

export type SecurityAuditMetadata = Record<
  string,
  string | number | boolean | null
>;

export type SecurityAuditEntry = {
  eventType: SecurityAuditEvent;
  actorUserId?: number | null;
  targetUserId?: number | null;
  sessionId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: SecurityAuditMetadata | null;
};

const SENSITIVE_METADATA_KEY =
  /(password|token|secret|authorization|cookie|verification.?code|\bcode\b)/i;

@Injectable()
export class SecurityAuditService {
  private readonly logger = new Logger(SecurityAuditService.name);

  constructor(
    @InjectRepository(SecurityAuditLog)
    private readonly auditRepository: Repository<SecurityAuditLog>,
  ) {}

  private sanitizeMetadata(
    metadata?: SecurityAuditMetadata | null,
  ): SecurityAuditMetadata | null {
    if (!metadata) return null;

    const safeEntries = Object.entries(metadata)
      .filter(([key]) => !SENSITIVE_METADATA_KEY.test(key))
      .map(
        ([key, value]) =>
          [
            key,
            typeof value === 'string' ? value.slice(0, 512) : value,
          ] as const,
      );

    return safeEntries.length > 0 ? Object.fromEntries(safeEntries) : null;
  }

  async record(entry: SecurityAuditEntry): Promise<void> {
    try {
      await this.auditRepository.insert({
        event_type: entry.eventType,
        actor_user_id: entry.actorUserId ?? null,
        target_user_id: entry.targetUserId ?? null,
        session_id: entry.sessionId ?? null,
        ip_address: entry.ipAddress?.slice(0, 45) ?? null,
        user_agent: entry.userAgent?.slice(0, 512) ?? null,
        metadata: this.sanitizeMetadata(entry.metadata),
      });
    } catch {
      // Audit persistence must never expose secrets or replace the original
      // application outcome. Infrastructure monitoring should alert on this.
      this.logger.error(
        `Failed to persist security audit event: ${entry.eventType}`,
      );
    }
  }
}
