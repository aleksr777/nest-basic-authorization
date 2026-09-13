import { Controller, Post, Body, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AuthService } from '../auth/auth.service';
import { Request } from 'express';
import { AdminTransferService } from './transfer-rights.service';
import { TransferConfirmDto } from './dto/transfer-rights-confirm.dto';
import { SecurityAuditService } from '../security-audit/security-audit.service';
import { SecurityAuditEvent } from '../security-audit/security-audit-event.enum';
import { User } from '../users/entities/user.entity';

@Controller('admin/transfer')
@UseGuards(JwtAuthGuard)
export class AdminTransferSecureController {
  constructor(
    private readonly transfer: AdminTransferService,
    private readonly authService: AuthService,
    private readonly securityAuditService: SecurityAuditService,
  ) {}

  @Post('confirm')
  async confirmTransfer(@Body() dto: TransferConfirmDto, @Req() req: Request) {
    const user = req.user as User;
    const result = await this.transfer.confirmTransfer(
      dto.code,
      +user.id,
      dto.password,
    );
    await this.securityAuditService.record({
      eventType: SecurityAuditEvent.ADMIN_RIGHTS_TRANSFERRED,
      actorUserId: +user.id,
      targetUserId: +user.id,
      sessionId: this.authService.getSessionIdFromToken(
        req.headers.authorization,
      ),
      ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
      userAgent: req.get('user-agent') ?? null,
    });
    return result;
  }
}
