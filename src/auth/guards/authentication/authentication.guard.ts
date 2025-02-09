import { AccessTokenGuard } from './../access-token/access-token.guard';
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AUTH_TYPE_KEY } from 'src/auth/constants/auth.constants';
import { AuthType } from 'src/auth/enums/auth-type.enums';

@Injectable()
export class AuthenticationGuard implements CanActivate {
  private static readonly defaultAuthType = AuthType.None;
  private readonly authTypeGuardMap: Record<
    AuthType,
    CanActivate | CanActivate[]
  > = {
    [AuthType.Bearer]: this.accessTokenGuard,
    [AuthType.None]: { canActivate: () => true },
  };

  constructor(
    private readonly reflector: Reflector,
    private readonly accessTokenGuard: AccessTokenGuard,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const authTypes = this.reflector.getAllAndOverride<AuthType[]>(
      AUTH_TYPE_KEY,
      [context.getHandler(), context.getClass()],
    ) || [AuthenticationGuard.defaultAuthType];
    const guards = authTypes.flatMap((type) => this.authTypeGuardMap[type]);
    for (const guard of guards) {
      try {
        if (await guard.canActivate(context)) {
          return true;
        }
      } catch (error) {
        throw new UnauthorizedException(
          `Guard ${guard.constructor.name} failed`,
          error,
        );
      }
    }
    throw new UnauthorizedException('Unauthorized');
  }
}
