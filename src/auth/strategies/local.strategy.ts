import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from '../../auth/auth.service';
import { LoginRateLimitService } from '../login-rate-limit.service';
import { SecurityAuditService } from '../../security-audit/security-audit.service';
import { SecurityAuditEvent } from '../../security-audit/security-audit-event.enum';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly authService: AuthService,
    private readonly loginRateLimitService: LoginRateLimitService,
    private readonly securityAuditService: SecurityAuditService,
  ) {
    super({
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true,
    });
  }

  async validate(req: Request, email: string, password: string) {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    await this.loginRateLimitService.assertAllowed(email, ip);

    try {
      const user = await this.authService.validateUserByEmailAndPassword(
        email,
        password,
      );
      await this.loginRateLimitService.clearEmailFailures(email);
      return user;
    } catch (err: unknown) {
      await this.loginRateLimitService.registerFailure(email, ip);
      await this.securityAuditService.record({
        eventType: SecurityAuditEvent.LOGIN_FAILED,
        ipAddress: ip,
        userAgent: req.get('user-agent') ?? null,
      });
      throw err;
    }
  }
}
