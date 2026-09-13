import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { SecurityAuditEvent } from './security-audit-event.enum';

@Entity({ name: 'security_audit_log' })
@Index('IDX_security_audit_event_created', ['event_type', 'created_at'])
@Index('IDX_security_audit_actor_created', ['actor_user_id', 'created_at'])
@Index('IDX_security_audit_target_created', ['target_user_id', 'created_at'])
export class SecurityAuditLog {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar', name: 'event_type', length: 64 })
  event_type!: SecurityAuditEvent;

  @Column({ type: 'int', name: 'actor_user_id', nullable: true })
  actor_user_id!: number | null;

  @Column({ type: 'int', name: 'target_user_id', nullable: true })
  target_user_id!: number | null;

  @Column({ type: 'uuid', name: 'session_id', nullable: true })
  session_id!: string | null;

  @Column({ type: 'varchar', name: 'ip_address', length: 45, nullable: true })
  ip_address!: string | null;

  @Column({ type: 'varchar', name: 'user_agent', length: 512, nullable: true })
  user_agent!: string | null;

  @Column({ type: 'jsonb', name: 'metadata', nullable: true })
  metadata!: Record<string, string | number | boolean | null> | null;

  @CreateDateColumn({
    type: 'timestamptz',
    name: 'created_at',
    default: () => 'CURRENT_TIMESTAMP',
  })
  created_at!: Date;
}
