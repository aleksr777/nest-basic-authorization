import {
  Get,
  Patch,
  Post,
  Delete,
  Body,
  Req,
  Query,
  Param,
  Controller,
  UseGuards,
  ParseIntPipe,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AuthService } from '../auth/auth.service';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { Role } from '../common/types/role.enum';
import { SecurityAuditService } from '../security-audit/security-audit.service';
import { SecurityAuditEvent } from '../security-audit/security-audit-event.enum';
import { GetUsersQueryDto } from './dto/get-users-query.dto';
import { BlockUserDto } from './dto/block-user.dto';
import { AdminPasswordDto } from './dto/admin-password.dto';
import { TransferInitiateDto } from './dto/transfer-rights-initiate.dto';
import { AdminService } from './admin.service';
import { AdminTransferService } from './transfer-rights.service';
import { Request } from 'express';
import { User } from '../users/entities/user.entity';

@Controller('admin')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
export class AdminController {
  constructor(
    private readonly adminService: AdminService,
    private readonly transfer: AdminTransferService,
    private readonly authService: AuthService,
    private readonly securityAuditService: SecurityAuditService,
  ) {}

  private getAuditContext(req: Request) {
    return {
      sessionId: this.authService.getSessionIdFromToken(
        req.headers.authorization,
      ),
      ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
      userAgent: req.get('user-agent') ?? null,
    };
  }

  @Get('transfer/status')
  getTransferStatus() {
    return this.transfer.getTransferStatus();
  }

  @Post('transfer/initiate')
  async initiateTransfer(
    @Body() dto: TransferInitiateDto,
    @Req() req: Request,
  ) {
    const admin = req.user as User;
    const adminId = +admin.id;
    const userId = +dto.id;
    return await this.transfer.initiateTransfer(adminId, userId, dto.password);
  }

  @Delete('transfer/cancel')
  async cancelTransfer(@Req() req: Request) {
    const admin = req.user as User;
    return await this.transfer.cancelTransfer(+admin.id);
  }

  @Get('users/find')
  getUsers(@Query() q: GetUsersQueryDto) {
    return this.adminService.getUsersByQuery(
      q.limit,
      q.offset,
      q.field,
      q.search,
    );
  }

  @Get('users/:id')
  getUser(@Param('id', ParseIntPipe) id: number) {
    return this.adminService.getUserById(id);
  }

  @Delete('users/delete/:id')
  async deleteUser(
    @Body() dto: AdminPasswordDto,
    @Req() req: Request,
    @Param('id', ParseIntPipe) id: number,
  ) {
    const admin = req.user as User;
    await this.adminService.deleteUserById(+admin.id, +id, dto.password);
  }

  @Patch('users/block/:id')
  async blockUser(
    @Body() dto: BlockUserDto,
    @Req() req: Request,
    @Param('id', ParseIntPipe) id: number,
  ) {
    const admin = req.user as User;
    const adminId = +admin.id;
    const userId = +id;
    const blocked_reason = dto.blocked_reason ? dto.blocked_reason : '';
    await this.adminService.blockUserById(
      adminId,
      userId,
      blocked_reason,
      dto.password,
    );
    const context = this.getAuditContext(req);
    await this.securityAuditService.record({
      eventType: SecurityAuditEvent.ACCOUNT_BLOCKED,
      actorUserId: adminId,
      targetUserId: userId,
      sessionId: context.sessionId,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });
  }

  @Patch('users/unblock/:id')
  async unblockUser(
    @Req() req: Request,
    @Param('id', ParseIntPipe) id: number,
  ) {
    const admin = req.user as User;
    const userId = +id;
    await this.adminService.unblockUserById(userId);
    const context = this.getAuditContext(req);
    await this.securityAuditService.record({
      eventType: SecurityAuditEvent.ACCOUNT_UNBLOCKED,
      actorUserId: +admin.id,
      targetUserId: userId,
      sessionId: context.sessionId,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });
  }
}
